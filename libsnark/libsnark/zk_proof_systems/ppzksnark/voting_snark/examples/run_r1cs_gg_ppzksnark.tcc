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
                        const bool test_serialization, int mode, int msg, int MSG_BLOCK, std::string public_e)
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
        case -1:{ // test
        std::string crsgen = "./crsgen"; crsgen += std::to_string(MSG_BLOCK); crsgen += ".txt";
        std::string savergen = "./savergen"; savergen += std::to_string(MSG_BLOCK); savergen += ".txt";
        std::string encpath = "./enc"; encpath += std::to_string(MSG_BLOCK); encpath += ".txt";
        std::string rerandom = "./rerandom"; rerandom += std::to_string(MSG_BLOCK); rerandom += ".txt";
        std::string enf_vf = "./enf_vf"; enf_vf += std::to_string(MSG_BLOCK); enf_vf += ".txt";
        std::string decpath = "./dec"; decpath += std::to_string(MSG_BLOCK); decpath += ".txt";
        std::string dec_vf = "./dec_vf"; dec_vf += std::to_string(MSG_BLOCK); dec_vf += ".txt";

        printf("SIZE:::%d\n",example.auxiliary_input.size());
        libff::print_header("R1CS GG-ppzkSNARK Generator");

        libff::enter_block("R1CS GG-ppzkSNARK Generator");
            keypair = r1cs_gg_ppzksnark_generator<ppT>(example.constraint_system);
        libff::leave_block("R1CS GG-ppzkSNARK Generator",crsgen,true);

        libff::print_header("SNARK Friendly Enc/Dec Key Generator");
        
        libff::enter_block("SF_key Generation");
            SF_key = SF_key_generator(keypair,MSG_BLOCK);
        libff::leave_block("SF_key Generation",savergen,true);

        libff::print_header("SNARK Friendly Encryption 1");

            std::string m = "";
            m += "0000000F";
            for(int i = 1; i < MSG_BLOCK; i++)
                m += "0000000F";

        libff::enter_block("SF Encrypt");
            SF_cypher_text<ppT> SF_ct1 = SF_encrypt(keypair,
                                                    SF_key.pk,
                                                    m,MSG_BLOCK,
                                                    example.primary_input,
                                                    example.auxiliary_input); // Create Enc Proof
        libff::leave_block("SF Encrypt",encpath,true);

        libff::enter_block("SF Rerandomize");
            SF_cypher_text<ppT> SF_ct2 = SF_rerandomize(keypair, SF_key.pk, SF_ct1);
        libff::leave_block("SF Rerandomize",rerandom,true);

            ans_enc = SF_enc_verifier(keypair, SF_key.pk, SF_ct1); //Encryption Proof
            printf("* The verification :result is: %s\n", (ans_enc ? "PASS" : "FAIL"));
            
        libff::enter_block("SF Enc Verifier");
            ans_enc = SF_enc_verifier(keypair, SF_key.pk, SF_ct2); //Encryption Proof
            printf("* The verification :result is: %s\n", (ans_enc ? "PASS" : "FAIL"));
        libff::leave_block("SF Enc Verifier",enf_vf,true);
            printf("\n\n%d\n\n",SF_ct2.ct_g1.size());

        libff::print_header("SNARK Friendly Encryption 2");
            SF_ct_array.emplace_back(SF_ct2);

        libff::enter_block("SF Encrypt");
        for(int i = 1; i < msg; i++){
            SF_cypher_text<ppT> SF_ct = SF_encrypt(keypair,
                                                    SF_key.pk,
                                                    m,MSG_BLOCK,
                                                    example.primary_input,
                                                    example.auxiliary_input); // Create Enc Proof
            SF_ct_array.emplace_back(SF_ct);
        }
        libff::leave_block("SF Encrypt");


        libff::print_header("SNARK Friendly Decryption");

        libff::enter_block("SF Decrypt");
            SF_pt = SF_decrypt(keypair, SF_key.sk, SF_key.vk, SF_ct_array); // Create Dec proof
        libff::leave_block("SF Decrypt",decpath,true);

        std::cout << "\n\t* Decrypt message *" << std::endl;
        for (size_t i = 0; i < SF_pt.msg.size(); i++)
        {
            std::cout << "\t    [" << i << "] ";
            SF_pt.msg[i].print();
        }

        libff::print_header("SNARK Friendly Decrypt Verifier");
        libff::enter_block("SF Dec Verifier");
            bool ans_dec = SF_dec_verifier(keypair, SF_key.pk, SF_key.vk, SF_pt, SF_ct_array); // Decryption Proof
            printf("* The dec verification result is: %s\n", (ans_dec ? "PASS" : "FAIL"));
        libff::leave_block("SF Dec Verifier",dec_vf,true);

            ans = ans_dec;

            std::string crsdat = "CRS"; crsdat += std::to_string(msg); crsdat += ".dat";
            std::string pkdat = "SF_pk"; pkdat += std::to_string(msg); pkdat += ".dat";
            std::string skdat = "SF_sk"; skdat += std::to_string(msg); skdat += ".dat";
            std::string vkdat = "SF_vk"; vkdat += std::to_string(msg); vkdat += ".dat";
            std::string encdat = "SF_ct"; encdat += std::to_string(msg); encdat += ".dat";

            std::ofstream crs_outfile(crsdat);
            std::ofstream SF_PK_outfile(pkdat);
            std::ofstream SF_SK_outfile(skdat); 
            std::ofstream SF_VK_outfile(vkdat); 
            std::ofstream SF_CT_outfile(encdat); 

            crs_outfile << keypair; crs_outfile.close();
            SF_PK_outfile << SF_key.pk; SF_PK_outfile.close();
            SF_SK_outfile << SF_key.sk; SF_SK_outfile.close();
            SF_VK_outfile << SF_key.vk; SF_VK_outfile.close();
            SF_CT_outfile << SF_ct1; SF_CT_outfile.close();

            break;
        }
        case 0:{ // key Generation
            libff::print_header("KEY Generator");

            libff::print_header("R1CS GG-ppzkSNARK Generator");
            libff::enter_block("R1CS GG-ppzkSNARK Generator");
            keypair = r1cs_gg_ppzksnark_generator<ppT>(example.constraint_system);
            libff::leave_block("R1CS GG-ppzkSNARK Generator");

            libff::print_header("SNARK Friendly Enc/Dec Key Generator");
            libff::enter_block("SF_key Generation");
            SF_key = SF_key_generator(keypair,MSG_BLOCK);
            libff::leave_block("SF_key Generation");
            
            std::ofstream crs_outfile("CRS.dat");
            std::ofstream SF_PK_outfile("SF_PK.dat");
            std::ofstream SF_SK_outfile("SF_SK.dat"); 
            std::ofstream SF_VK_outfile("SF_VK.dat"); 

            crs_outfile << keypair; crs_outfile.close();
            SF_PK_outfile << SF_key.pk; SF_PK_outfile.close();
            SF_SK_outfile << SF_key.sk; SF_SK_outfile.close();
            SF_VK_outfile << SF_key.vk; SF_VK_outfile.close();

            ans = true;
            break;
        }
        case 1:{ // MSG Encrypt

            libff::print_header("SNARK Friendly Encryption");
            std::ifstream crs_infile("CRS.dat");
            std::ifstream SF_PK_infile("SF_PK.dat");
            std::ifstream SF_VK_infile("SF_VK.dat"); 
            printf("msg :: %d\n",msg);
            
            crs_infile >> keypair; crs_infile.close();
            SF_PK_infile >> SF_key.pk; SF_PK_infile.close();
            SF_VK_infile >> SF_key.vk; SF_VK_infile.close();


            std::string m = "";
            for(int i = 0; i < msg-1; i++)
                m += "00000000";
            m+= "00000001";
            for(int i = msg; i < MSG_BLOCK; i++)
                m += "00000000";
            printf("msg :: %s\n",m);
            libff::enter_block("SF Encrypt");
            SF_cypher_text<ppT> SF_ct = SF_encrypt(keypair,
                                                    SF_key.pk,
                                                    m,MSG_BLOCK,
                                                    example.primary_input,
                                                    example.auxiliary_input); // Create Enc Proof
            libff::leave_block("SF Encrypt");

            libff::enter_block("SF Enc Verifier");
            ans_enc = SF_enc_verifier(keypair, SF_key.pk, SF_ct); //Encryption Proof
            printf("* The verification :result is: %s\n", (ans_enc ? "PASS" : "FAIL"));
            libff::leave_block("SF Enc Verifier");

            std::string file_name = "";
            std::ofstream SF_CT_outfile, SF_IO_outfile;
            int filenum = 0;
            for(filenum = 0;!SF_CT_outfile.fail();filenum++){
                SF_CT_outfile.close();
                file_name = "./" + public_e + "/cipher"; file_name += std::to_string(filenum); file_name += ".dat";
                SF_CT_outfile.open(file_name,std::ios::in);
            }
            SF_CT_outfile.open(file_name,ios::out);
            SF_CT_outfile << SF_ct;
            SF_CT_outfile.close();
            
            SF_IO_outfile.open("./" + public_e + "/IO" + std::to_string(--filenum) + ".dat",ios::out);

            for(int i = 0; i < SF_ct.primary_input.size(); i++){
                //printf("input[%d] :: ",i);
                //SF_ct.primary_input[i].print();
                //printf("input[%d] :: ",i);
                libff::bigint<4> bg_r = SF_ct.primary_input[i].as_bigint();
                char char_arr[1024] = "";
                if(i < 8)
                    gmp_sprintf(char_arr,"e: %NX", bg_r.data, bg_r.N);
                else if(i < 11)
                    gmp_sprintf(char_arr,"sn: %NX", bg_r.data, bg_r.N);
                else if(i < 14)
                    gmp_sprintf(char_arr,"rt: %NX", bg_r.data, bg_r.N);
                else
                    gmp_sprintf(char_arr,"%NX", bg_r.data, bg_r.N);
                //printf("%s\n\n",char_arr);
                SF_IO_outfile << char_arr << std::endl;
            }
            SF_IO_outfile.close();

            ans = ans_enc;
            
            break;
        }
        case 2:{ // Decrypt
            libff::print_header("SNARK Friendly Decryption");
            std::ifstream crs_infile("CRS.dat");
            std::ifstream SF_SK_infile("SF_SK.dat");
            std::ifstream SF_VK_infile("SF_VK.dat");
            
            crs_infile >> keypair; crs_infile.close();
            SF_SK_infile >> SF_key.sk; SF_SK_infile.close();
            SF_VK_infile >> SF_key.vk; SF_VK_infile.close();

            std::string file_name = "./" + public_e + "/cipher0.dat";
            std::ifstream SF_CT_infile;
            SF_CT_infile.open(file_name,std::ios::in);
            for(int i = 1;!SF_CT_infile.fail();i++){
                SF_cypher_text<ppT> SF_ct;
                SF_CT_infile >> SF_ct;
                SF_CT_infile.close();

                SF_ct_array.emplace_back(SF_ct);

                file_name = "./" + public_e +"/cipher"; file_name += std::to_string(i); file_name += ".dat";
                SF_CT_infile.open(file_name,std::ios::in);
            }

            libff::enter_block("SF Decrypt");
            SF_pt = SF_decrypt(keypair, SF_key.sk, SF_key.vk, SF_ct_array); // Create Dec proof
            libff::leave_block("SF Decrypt");

            std::cout << "\n\t* Decrypt message *" << std::endl;
            for (size_t i = 0; i < SF_pt.msg.size(); i++){
                std::cout << "\t    [" << i << "] ";
                SF_pt.msg[i].print();
            }

            libff::print_header("SNARK Friendly Decrypt Verifier");
            libff::enter_block("SF Dec Verifier");
            bool ans_dec = SF_dec_verifier(keypair, SF_key.pk, SF_key.vk, SF_pt, SF_ct_array); // Decryption Proof
            printf("* The dec verification result is: %s\n", (ans_dec ? "PASS" : "FAIL"));
            libff::leave_block("SF Dec Verifier");
            
            std::ofstream SF_PT_outfile("./" + public_e + "/SF_PT.dat");
            SF_PT_outfile << SF_pt; SF_PT_outfile.close();

            ans = ans_dec;
            break;
        }
        case 3:{ // verify Dec
            libff::print_header("SNARK Friendly Decrypt Verifier");
            
            std::ifstream crs_infile("CRS.dat");
            std::ifstream SF_PT_infile("./" + public_e + "/SF_PT.dat"); 
            std::ifstream SF_VK_infile("SF_VK.dat"); 
            
            crs_infile >> keypair; crs_infile.close();
            SF_PT_infile >> SF_pt; SF_PT_infile.close();
            SF_VK_infile >> SF_key.vk; SF_VK_infile.close();

            std::string file_name = "./" + public_e + "/cipher0.dat";
            std::ifstream SF_CT_infile;
            SF_CT_infile.open(file_name,std::ios::in);
            for(int i = 1;!SF_CT_infile.fail();i++){
                SF_cypher_text<ppT> SF_ct;
                SF_CT_infile >> SF_ct;
                SF_CT_infile.close();

                SF_ct_array.emplace_back(SF_ct);

                file_name = "./" + public_e + "/cipher"; file_name += std::to_string(i); file_name += ".dat";
                SF_CT_infile.open(file_name,std::ios::in);
            }

            std::cout << "\n\t* Decrypt message *" << std::endl;
            for (size_t i = 0; i < SF_pt.msg.size(); i++){
                std::cout << "\t    [" << i << "] ";
                SF_pt.msg[i].print();
            }

            libff::enter_block("SF Dec Verifier");
            bool ans_dec = SF_dec_verifier(keypair, SF_key.pk, SF_key.vk, SF_pt, SF_ct_array); // Decryption Proof
            printf("* The verification result is: %s\n", (ans_dec ? "PASS" : "FAIL"));
            libff::leave_block("SF Dec Verifier");

            ans = ans_dec;
            break;
        }
        case 4: // rerandomize
        {
            SF_cypher_text<ppT> SF_ct;
            std::string file_name = public_e;

            std::ifstream crs_infile("CRS.dat");
            std::ifstream SF_PK_infile("SF_PK.dat");
            std::ifstream SF_VK_infile("SF_VK.dat"); 
            std::ifstream SF_CT_infile(file_name);
            
            crs_infile >> keypair; crs_infile.close();
            SF_PK_infile >> SF_key.pk; SF_PK_infile.close();
            SF_CT_infile >> SF_ct; SF_CT_infile.close();

        libff::enter_block("SF Rerandomize");
            SF_cypher_text<ppT> SF_ct_new = SF_rerandomize(keypair, SF_key.pk, SF_ct);
        libff::leave_block("SF Rerandomize");
            
            std::ofstream SF_CT_outfile(file_name); 
            SF_CT_outfile << SF_ct_new; SF_CT_outfile.close();

            break;
        }
        case 5: // enc_vf
        {
            libff::print_header("SNARK Friendly Encryption Verifier");
            
            SF_cypher_text<ppT> SF_ct;
            std::string file_name = public_e;

            std::ifstream crs_infile("CRS.dat");
            std::ifstream SF_PK_infile("SF_PK.dat");
            std::ifstream SF_CT_infile(file_name);

            crs_infile >> keypair; crs_infile.close();
            SF_PK_infile >> SF_key.pk; SF_PK_infile.close();
            SF_CT_infile >> SF_ct; SF_CT_infile.close();
            
            libff::enter_block("SF Enc Verifier");
            ans_enc = SF_enc_verifier(keypair, SF_key.pk, SF_ct); //Encryption Proof
            printf("* The verification :result is: %s\n", (ans_enc ? "PASS" : "FAIL"));
            libff::leave_block("SF Enc Verifier");

            ans = ans_enc;
            break;
        }
        
        default:{
            printf("\n");
            printf("input: <.arith file> <.in file> mode vote(1~8) <Vote_e>\n");
            libff::print_indent(); printf("mode 0: Key Generation\n");
            libff::print_indent(); printf("mode 1: Enc Message\n");
            libff::print_indent(); printf("mode 2: Dec Message\n");
            libff::print_indent(); printf("mode 3: Dec Verify\n");
            printf("\n");
        }
    }
    
    libff::leave_block("Call to run_r1cs_gg_ppzksnark");
    
    return (ans);
}

} // libsnark

#endif // RUN_R1CS_GG_PPZKSNARK_TCC_
