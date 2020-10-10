/** @file
 *****************************************************************************

 Implementation of functionality that runs the R1CS GG-ppzkSNARK for
 a given R1CS example.

 See run_r1cs_gg_ppzksnark.hpp .

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef RUN_R1CS_GG_PPZKSNARK_TCC_
#define RUN_R1CS_GG_PPZKSNARK_TCC_

#include <sstream>
#include <type_traits>

#include <libff/common/profiling.hpp>

//#include <libsnark/zk_proof_systems/ppzksnark/r1cs_HFAL_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/voting_snark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/voting_snark/SNARK_friendly.hpp>
 
namespace libsnark {

template<typename ppT>
typename std::enable_if<ppT::has_affine_pairing, void>::type
test_affine_verifier(const r1cs_gg_ppzksnark_verification_key<ppT> &vk,
                     const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input,
                     const r1cs_gg_ppzksnark_proof<ppT> &proof,
                     const bool expected_answer)
{
    libff::print_header("R1CS GG-ppzkSNARK Affine Verifier");
    const bool answer = r1cs_gg_ppzksnark_affine_verifier_weak_IC<ppT>(vk, primary_input, proof);
    assert(answer == expected_answer);
}

template<typename ppT>
typename std::enable_if<!ppT::has_affine_pairing, void>::type
test_affine_verifier(const r1cs_gg_ppzksnark_verification_key<ppT> &vk,
                     const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input,
                     const r1cs_gg_ppzksnark_proof<ppT> &proof,
                     const bool expected_answer)
{
    libff::print_header("R1CS GG-ppzkSNARK Affine Verifier");
    libff::UNUSED(vk, primary_input, proof, expected_answer);
    printf("Affine verifier is not supported; not testing anything.\n");
}

/**
 * The code below provides an example of all stages of running a R1CS GG-ppzkSNARK.
 *
 * Of course, in a real-life scenario, we would have three distinct entities,
 * mangled into one in the demonstration below. The three entities are as follows.
 * (1) The "generator", which runs the ppzkSNARK generator on input a given
 *     constraint system CS to create a proving and a verification key for CS.
 * (2) The "prover", which runs the ppzkSNARK prover on input the proving key,
 *     a primary input for CS, and an auxiliary input for CS.
 * (3) The "verifier", which runs the ppzkSNARK verifier on input the verification key,
 *     a primary input for CS, and a proof.
 */
template<typename ppT>
bool run_r1cs_gg_ppzksnark(const r1cs_example<libff::Fr<ppT> > &example,
                        const bool test_serialization)
{
    libff::enter_block("Call to run_r1cs_gg_ppzksnark");
    
    libff::print_header("R1CS GG-ppzkSNARK Generator");
    r1cs_gg_ppzksnark_keypair<ppT> keypair = r1cs_gg_ppzksnark_generator<ppT>(example.constraint_system);
    printf("\n"); libff::print_indent(); libff::print_mem("after generator");

    libff::print_header("Preprocess verification key");
    r1cs_gg_ppzksnark_processed_verification_key<ppT> pvk = r1cs_gg_ppzksnark_verifier_process_vk<ppT>(keypair.vk);

    if (test_serialization)
    {
        libff::enter_block("Test serialization of keys");
        keypair.pk = libff::reserialize<r1cs_gg_ppzksnark_proving_key<ppT> >(keypair.pk);
        keypair.vk = libff::reserialize<r1cs_gg_ppzksnark_verification_key<ppT> >(keypair.vk);
        pvk = libff::reserialize<r1cs_gg_ppzksnark_processed_verification_key<ppT> >(pvk);
        libff::leave_block("Test serialization of keys");
    }

    libff::print_header("SNARK Friendly Enc/Dec Key Generator");
    libff::enter_block("SF_key Generation");
    SF_keypair<ppT> SF_key = SF_key_generator(keypair);
    libff::leave_block("SF_key Generation");

    vector<SF_cypher_text<ppT>> SF_ct_array;
    libff::print_header("SNARK Friendly Encryption");
    libff::enter_block("SF Encrypt");
    std::string m1 = "00000000000000000000000000000001";
    SF_cypher_text<ppT> SF_ct1 = SF_encrypt(keypair, SF_key.pk, m1,example.primary_input,example.auxiliary_input); // Create Enc Proof
    std::string m2 = "00000000000000000000000000000002";
    SF_cypher_text<ppT> SF_ct2 = SF_encrypt(keypair, SF_key.pk, m2,example.primary_input,example.auxiliary_input); // Create Enc Proof
    libff::leave_block("SF Encrypt");

    SF_ct_array.emplace_back(SF_ct1);
    SF_ct_array.emplace_back(SF_ct2);
	// Flag , File Ouput , 
    libff::print_header("SNARK Friendly Encrypt Verifier");
    libff::enter_block("SF Enc Verifier");
    bool ans = SF_enc_verifier(keypair, SF_key.vk, SF_ct1.proof, example.primary_input, SF_ct1);//Encryption Proof
    printf("* The verification :result is: %s\n", (ans ? "PASS" : "FAIL"));
    ans = SF_enc_verifier(keypair, SF_key.vk, SF_ct2.proof, example.primary_input, SF_ct2);//Encryption Proof
    printf("* The verification :result is: %s\n", (ans ? "PASS" : "FAIL"));
    libff::leave_block("SF Enc Verifier");
    
    libff::print_header("SNARK Friendly Decryption");
    libff::enter_block("SF Decrypt");
    SF_plain_text<ppT> SF_pt = SF_decrypt(keypair,SF_key.sk,SF_ct_array/* ,example.primary_input.size(),example.auxiliary_input.size()*/); // Create Dec proof
    libff::leave_block("SF Decrypt");
    std::cout << "Decrypt:: " << SF_pt.msg << std::endl;

    libff::print_header("SNARK Friendly Decrypt Verifier");
    libff::enter_block("SF Dec Verifier");
    bool ans2 = SF_dec_verifier(SF_key.pk, SF_pt, SF_ct_array); // Decryption Proof
    printf("* The verification result is: %s\n", (ans2 ? "PASS" : "FAIL"));
    libff::leave_block("SF Dnc Verifier");
    
    libff::leave_block("Call to run_r1cs_gg_ppzksnark");

    libff::print_indent(); printf("* Size in bits pk: %zu\n", SF_key.pk.size_in_bits());
    libff::print_indent(); printf("* Size in bits sk: %zu\n", SF_key.sk.size_in_bits());
    libff::print_indent(); printf("* Size in bits vk: %zu\n", SF_key.vk.size_in_bits());
    libff::print_indent(); printf("* Size in bits ct: %zu\n", SF_ct1.size_in_bits());
    libff::print_indent(); printf("* Size in bits ct: %zu\n", SF_ct2.size_in_bits());
    libff::print_indent(); printf("* Size in bits pt: %zu\n", SF_pt.size_in_bits());

    return ans;
}

} // libsnark

#endif // RUN_R1CS_GG_PPZKSNARK_TCC_
