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
#include <fstream>
#include <cstring>

#include <libff/common/profiling.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/voting/r1cs_gg_ppzksnark.hpp>

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
void run_r1cs_gg_ppzksnark_setup(const r1cs_example<libff::Fr<ppT> > &example,
                        const bool test_serialization, string name)
{
    libff::enter_block("Call to run_r1cs_gg_ppzksnark setup");

    libff::print_header("R1CS GG-ppzkSNARK Generator");
    r1cs_gg_ppzksnark_keypair<ppT> keypair = r1cs_gg_ppzksnark_generator<ppT>(example.constraint_system);
    printf("\n"); libff::print_indent(); libff::print_mem("after generator");

    if (test_serialization)
    {
        libff::enter_block("Test serialization of keys");
        keypair.pk = libff::reserialize<r1cs_gg_ppzksnark_proving_key<ppT> >(keypair.pk);
        keypair.vk = libff::reserialize<r1cs_gg_ppzksnark_verification_key<ppT> >(keypair.vk);
        libff::leave_block("Test serialization of keys");
    }
    libff::print_header("GG-ppzkSNARK CRS Out file");
    string name1, name2;
    name1 = "./datafiles/" + name + "_CRS_pk.dat";
    name2 = "./datafiles/" + name + "_CRS_vk.dat";
    //name1 = strcat(name1, "_CRS_pk.dat");
    std::ofstream crs_pk_outfile(name1);
    
    //name2 = strcat(name2, "_CRS_vk.dat");
    std::ofstream crs_vk_outfile(name2);
    
    crs_pk_outfile << keypair.pk;
    crs_vk_outfile << keypair.vk; 
    crs_pk_outfile.close();
    crs_vk_outfile.close();
    libff::leave_block("Call to run_r1cs_gg_ppzksnark setup");
   // return keypair;
}

template<typename ppT>
void run_r1cs_gg_ppzksnark(const r1cs_example<libff::Fr<ppT> > &example,
                        const bool test_serialization, string name, string n)
{
    libff::enter_block("Call to run_r1cs_gg_ppzksnark");
    libff::print_header("GG-ppzkSNARK CRS In file");
    r1cs_gg_ppzksnark_keypair<ppT> keypair;
    string name1, name2, name3;
    name1 = "./datafiles/" + name + "_CRS_pk.dat";
    name2 = "./datafiles/" + name + "_CRS_vk.dat";
    
    std::ifstream crs_pk_infile(name1);
    
    std::ifstream crs_vk_infile(name2);
    // std::ifstream SF_PK_infile("SF_PK.dat");
    // std::ifstream SF_VK_infile("SF_VK.dat"); 
    // std::ifstream SF_CT_infile(file_name);
    
    crs_pk_infile >> keypair.pk; crs_pk_infile.close();
    crs_vk_infile >> keypair.vk; crs_vk_infile.close();
    // SF_PK_infile >> SF_key.pk; SF_PK_infile.close();
    // SF_CT_infile >> SF_ct; SF_CT_infile.close();

    libff::print_header("R1CS GG-ppzkSNARK Prover");
    r1cs_gg_ppzksnark_proof<ppT> proof = r1cs_gg_ppzksnark_prover<ppT>(keypair.pk, example.primary_input, example.auxiliary_input);
    printf("\n"); libff::print_indent(); libff::print_mem("after prover");

    if (test_serialization)
    {
        libff::enter_block("Test serialization of proof");
        proof = libff::reserialize<r1cs_gg_ppzksnark_proof<ppT> >(proof);
        libff::leave_block("Test serialization of proof");
    }

    libff::print_header("proof out");
    // name3 = name + "_Proof.dat";
    // name3 = name + "_proof_" + n + ".dat";
    name3 = "./datafiles/" + name + "_Proof_" + n + ".dat";
    std::ofstream proof_outfile(name3.c_str());
   
    proof_outfile << proof;
    proof_outfile.close();
    libff::leave_block("Call to run_r1cs_gg_ppzksnark");
}

template<typename ppT>
bool run_r1cs_gg_ppzksnark_verify(const r1cs_example<libff::Fr<ppT> > &example,
                        const bool test_serialization, string name, string n)
{
    libff::enter_block("Call to run_r1cs_gg_ppzksnark verify");
    libff::print_header("GG-ppzkSNARK CRS In file");
    r1cs_gg_ppzksnark_keypair<ppT> keypair;
    string name1, name2, name3;
    name1 = "./datafiles/" + name + "_CRS_pk.dat";
    name2 = "./datafiles/" + name + "_CRS_vk.dat";    
    // name3 = name + "_Proof.dat";
    // name3 = name + "_proof_" + n + ".dat";
    name3 = "./datafiles/" +  name + "_Proof_" + n + ".dat";
    std::ifstream crs_pk_infile(name1);
    //strcat(name2, "_CRS_vk.dat");
    std::ifstream crs_vk_infile(name2);
    //strcat(name3, "_Proof.dat");
    std::ifstream proof_infile(name3.c_str());
    // std::ifstream SF_PK_infile("SF_PK.dat");
    // std::ifstream SF_VK_infile("SF_VK.dat"); 
    // std::ifstream SF_CT_infile(file_name);
    crs_pk_infile >> keypair.pk; crs_pk_infile.close();
    crs_vk_infile >> keypair.vk; crs_vk_infile.close();
    // SF_PK_infile >> SF_key.pk; SF_PK_infile.close();
    // SF_CT_infile >> SF_ct; SF_CT_infile.close();
    r1cs_gg_ppzksnark_proof<ppT> proof;
    proof_infile >> proof;
    proof_infile.close();
    libff::print_header("Preprocess verification key");
    r1cs_gg_ppzksnark_processed_verification_key<ppT> pvk = r1cs_gg_ppzksnark_verifier_process_vk<ppT>(keypair.vk);

    pvk = libff::reserialize<r1cs_gg_ppzksnark_processed_verification_key<ppT> >(pvk);

    libff::print_header("R1CS GG-ppzkSNARK Verifier");
    const bool ans = r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(keypair.vk, example.primary_input, proof);
    printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

    libff::print_header("R1CS GG-ppzkSNARK Online Verifier");
    const bool ans2 = r1cs_gg_ppzksnark_online_verifier_strong_IC<ppT>(pvk, example.primary_input, proof);
    assert(ans == ans2);

    test_affine_verifier<ppT>(keypair.vk, example.primary_input, proof, ans);

    libff::leave_block("Call to run_r1cs_gg_ppzksnark verify");

    return ans;
}

} // libsnark

#endif // RUN_R1CS_GG_PPZKSNARK_TCC_
