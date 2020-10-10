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
#include<fstream>
#include<iostream>

#include <libff/common/profiling.hpp>

//#include <libsnark/zk_proof_systems/ppzksnark/r1cs_HFAL_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/voting_snark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/voting_snark/SNARK_friendly.hpp>
 
#define File
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
                        const bool test_serialization, int mode, int msg)
{

    libff::enter_block("Call to run_r1cs_gg_ppzksnark");
    
    r1cs_gg_ppzksnark_keypair<ppT> keypair;
    r1cs_gg_ppzksnark_processed_verification_key<ppT> pvk;
    SF_keypair<ppT> SF_key;
    vector<SF_cypher_text<ppT>> SF_ct_array;
    SF_plain_text<ppT> SF_pt;
    bool ans = false;
    bool ans_enc = false;

    switch(mode){
        case 0:{ // key Generation
            libff::print_header("KEY Generator");
            std::ofstream crs_outfile("CRS.dat");
            std::ofstream SF_PK_outfile("SF_PK.dat");
            std::ofstream SF_SK_outfile("SF_SK.dat"); 
            std::ofstream SF_VKenc_outfile("SF_VK_enc.dat"); 
            std::ofstream SF_VKdec_outfile("SF_VK_dec.dat"); 

            libff::print_header("R1CS GG-ppzkSNARK Generator");
            keypair = r1cs_gg_ppzksnark_generator<ppT>(example.constraint_system);
            crs_outfile << keypair;
            crs_outfile.close();

            libff::print_header("SNARK Friendly Enc/Dec Key Generator");
            libff::enter_block("SF_key Generation");
            SF_key = SF_key_generator(keypair);
            libff::leave_block("SF_key Generation");
            
            SF_PK_outfile << SF_key.pk;
            SF_SK_outfile << SF_key.sk;
            SF_VKenc_outfile << SF_key.vk_enc;
            SF_VKdec_outfile << SF_key.vk_dec;

            ans = true;
            break;
        }
        case 1:{ // MSG Encrypt

            libff::print_header("SNARK Friendly Encryption");
            std::ifstream crs_infile("CRS.dat");
            std::ifstream SF_PK_infile("SF_PK.dat");
            std::ifstream SF_VKenc_infile("SF_VK_enc.dat"); 
            
            crs_infile >> keypair; crs_infile.close();
            SF_PK_infile >> SF_key.pk; SF_PK_infile.close();
            SF_VKenc_infile >> SF_key.vk_enc; SF_VKenc_infile.close();

            std::string m = "";
            for(int i = 0; i < msg-1; i++)
                m += "00000000";
            m+= "00000001";
            for(int i = msg; i < 8; i++)
                m += "00000000";

            libff::enter_block("SF Encrypt");
            SF_cypher_text<ppT> SF_ct = SF_encrypt(keypair,
                                                    SF_key.pk,
                                                    m,
                                                    example.primary_input,
                                                    example.auxiliary_input); // Create Enc Proof
            libff::leave_block("SF Encrypt");

            libff::enter_block("SF Enc Verifier");
            ans_enc = SF_enc_verifier(keypair, SF_key.vk_enc, SF_ct, example.primary_input); //Encryption Proof
            printf("* The verification :result is: %s\n", (ans_enc ? "PASS" : "FAIL"));

            std::string file_name = "";
            std::ofstream SF_CT_outfile; 
            for(int i = 0;!SF_CT_outfile.fail();i++){
                SF_CT_outfile.close();
                file_name = "cipher"; file_name += std::to_string(i); file_name += ".dat";
                SF_CT_outfile.open(file_name,std::ios::in);
            }
            SF_CT_outfile.open(file_name,ios::out);
            SF_CT_outfile << SF_ct;
            SF_CT_outfile.close();

            ans = ans_enc;

            break;
        }
        case 2:{ // Decrypt
            libff::print_header("SNARK Friendly Decryption");
            std::ifstream crs_infile("CRS.dat");
            std::ifstream SF_SK_infile("SF_SK.dat");
            std::ifstream SF_VKenc_infile("SF_VK_enc.dat"); 
            std::ifstream SF_VKdec_infile("SF_VK_dec.dat"); 
            
            crs_infile >> keypair; crs_infile.close();
            SF_SK_infile >> SF_key.sk; SF_SK_infile.close();
            SF_VKenc_infile >> SF_key.vk_enc; SF_VKenc_infile.close();
            SF_VKdec_infile >> SF_key.vk_dec; SF_VKdec_infile.close();

            std::string file_name = "cipher0.dat";
            std::ifstream SF_CT_infile;
            SF_CT_infile.open(file_name,std::ios::in);
            for(int i = 1;!SF_CT_infile.fail();i++){
                SF_cypher_text<ppT> SF_ct;
                SF_CT_infile >> SF_ct;
                SF_CT_infile.close();

                libff::enter_block("SF Enc Verifier");
                ans_enc = SF_enc_verifier(keypair, SF_key.vk_enc, SF_ct, example.primary_input); //Encryption Proof
                printf("* The enc %s verification :result is: %s\n",file_name, (ans_enc ? "PASS" : "FAIL"));
                if(ans_enc)
                    SF_ct_array.emplace_back(SF_ct);

                file_name = "cipher"; file_name += std::to_string(i); file_name += ".dat";
                SF_CT_infile.open(file_name,std::ios::in);
            }

            libff::enter_block("SF Decrypt");
            SF_pt = SF_decrypt(keypair, SF_key.sk, SF_ct_array); // Create Dec proof
            libff::leave_block("SF Decrypt");

            libff::bigint<4> bg_msg = SF_pt.msg.as_bigint();
            char char_arr[65] = "";
            gmp_sprintf(char_arr, "%064NX", bg_msg.data, bg_msg.N);
            printf("Decrypt::%s\n", char_arr);

            libff::print_header("SNARK Friendly Decrypt Verifier");
            libff::enter_block("SF Dec Verifier");
            bool ans_dec = SF_dec_verifier(keypair, SF_pt, SF_ct_array, SF_key.vk_dec); // Decryption Proof
            printf("* The dec verification result is: %s\n", (ans_dec ? "PASS" : "FAIL"));
            libff::leave_block("SF Dec Verifier");
            
            std::ofstream SF_PT_outfile("SF_PT.dat");
            SF_PT_outfile << SF_pt; SF_PT_outfile.close();

            ans = ans_dec;
            break;
        }
        case 3:{ // verify Dec
            libff::print_header("SNARK Friendly Decrypt Verifier");
            
            std::ifstream crs_infile("CRS.dat");
            std::ifstream SF_PT_infile("SF_PT.dat"); 
            std::ifstream SF_VKenc_infile("SF_VK_enc.dat"); 
            std::ifstream SF_VKdec_infile("SF_VK_dec.dat"); 
            
            crs_infile >> keypair; crs_infile.close();
            SF_PT_infile >> SF_pt; SF_PT_infile.close();
            SF_VKenc_infile >> SF_key.vk_enc; SF_VKenc_infile.close();
            SF_VKdec_infile >> SF_key.vk_dec; SF_VKdec_infile.close();

            std::string file_name = "cipher0.dat";
            std::ifstream SF_CT_infile;
            SF_CT_infile.open(file_name,std::ios::in);
            for(int i = 1;!SF_CT_infile.fail();i++){
                SF_cypher_text<ppT> SF_ct;
                SF_CT_infile >> SF_ct;
                SF_CT_infile.close();

                libff::enter_block("SF Enc Verifier");
                ans_enc = SF_enc_verifier(keypair, SF_key.vk_enc, SF_ct, example.primary_input); //Encryption Proof
                printf("* The enc %s verification :result is: %s\n",file_name.c_str(), (ans_enc ? "PASS" : "FAIL"));
                if(ans_enc)
                    SF_ct_array.emplace_back(SF_ct);

                file_name = "cipher"; file_name += std::to_string(i); file_name += ".dat";
                SF_CT_infile.open(file_name,std::ios::in);
            }


            libff::bigint<4> bg_msg = SF_pt.msg.as_bigint();
            char char_arr[65] = "";
            gmp_sprintf(char_arr, "%064NX", bg_msg.data, bg_msg.N);
            printf("Decrypt::%s\n", char_arr);

            libff::enter_block("SF Dec Verifier");
            bool ans_dec = SF_dec_verifier(keypair, SF_pt, SF_ct_array, SF_key.vk_dec); // Decryption Proof
            printf("* The verification result is: %s\n", (ans_dec ? "PASS" : "FAIL"));
            libff::leave_block("SF Dec Verifier");

            ans = ans_dec;
            break;
        }
        default:{
            printf("\n");
            printf("input: [*.arith] [*.in] [mode] [vote(1~8)]\n");
            libff::print_indent(); printf("mode 0: Key Generation\n");
            libff::print_indent(); printf("mode 1: Enc Message [vote] data require\n");
            libff::print_indent(); printf("mode 2: Dec Message\n");
            libff::print_indent(); printf("mode 3: Dec Verify\n");
            printf("\n");
        }
    }
    
    libff::leave_block("Call to run_r1cs_gg_ppzksnark");
/*
    libff::print_indent(); printf("* Size in bits pk: %zu\n", SF_key.pk.size_in_bits());
    libff::print_indent(); printf("* Size in bits sk: %zu\n", SF_key.sk.size_in_bits());
    libff::print_indent(); printf("* Size in bits vk: %zu\n", SF_key.vk.size_in_bits());
    libff::print_indent(); printf("* Size in bits ct: %zu\n", SF_ct1.size_in_bits());
    libff::print_indent(); printf("* Size in bits ct: %zu\n", SF_ct2.size_in_bits());
    libff::print_indent(); printf("* Size in bits pt: %zu\n", SF_pt.size_in_bits());
*/
    return (ans);
}

} // libsnark

#endif // RUN_R1CS_GG_PPZKSNARK_TCC_
