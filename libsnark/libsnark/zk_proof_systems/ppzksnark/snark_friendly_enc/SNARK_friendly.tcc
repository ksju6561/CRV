
#ifndef SNARK_FRIENDLY_TCC_
#define SNARK_FRIENDLY_TCC_

#include <algorithm>
#include <cassert>
#include <functional>
#include <iostream>
#include <sstream>

#include <gmp.h>

#include <libff/algebra/scalar_multiplication/multiexp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

#include <libsnark/knowledge_commitment/kc_multiexp.hpp>
#include <libsnark/reductions/r1cs_to_qap/r1cs_to_qap.hpp>

namespace libsnark {

template<typename ppT>
bool SF_public_key<ppT>::operator==(const SF_public_key<ppT> &other) const
{
    return (this->G_pub == other.G_pub);
}
template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_public_key<ppT> &pk)
{
    out << pk.G_pub;

    return out;
}
template<typename ppT>
std::istream& operator>>(std::istream &in, SF_public_key<ppT> &pk)
{
    in >> pk.G_pub;

    return in;
}

template<typename ppT>
bool SF_secret_key<ppT>::operator==(const SF_secret_key<ppT> &other) const
{
    return (this->H_pub == other.H_pub &&
            this->GT_pub == other.GT_pub);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_secret_key<ppT> &sk)
{
    out << sk.H_pub;
    out << sk.GT_pub;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, SF_secret_key<ppT> &sk)
{
    in >> sk.H_pub;
    in >> sk.GT_pub;

    return in;
}

template<typename ppT>
bool SF_verify_key<ppT>::operator==(const SF_verify_key<ppT> &other) const
{
    return (this->H_pub == other.H_pub &&
            this->GT_pub == other.GT_pub);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_verify_key<ppT> &vk)
{
    out << vk.g_ak << OUTPUT_NEWLINE;
    out << vk.g_k_2n2 << OUTPUT_NEWLINE;
    out << vk.h_ramda_p << OUTPUT_NEWLINE;
    out << vk.h_ramda_q << OUTPUT_NEWLINE;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, SF_verify_key<ppT> &vk)
{
    in >> vk.g_ak;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.g_k_2n2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.g_h_ramda_p;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.g_h_rapda_q;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}

template<typename ppT>
bool SF_cypher_text<ppT>::operator==(const SF_cypher_text<ppT> &other) const
{
    return (this->proof == other.proof &&
            this->G1_ct == other.G1_ct);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_cypher_text<ppT> &ct)
{
    out << ct.proof;
    out << ct.G1_ct;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, SF_cypher_text<ppT> &ct)
{
    in >> ct.proof;
    in >> ct.G1_ct;

    return in;
}

template <typename ppT>
SF_keypair<ppT> SF_key_generator(const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair){
    const int input_size = gg_keypair.vk.gamma_ABC_g1.rest.values.size();

    libff::Fr<ppT> p = libff::Fr<ppT>::random_element();
    libff::Fr<ppT> q = libff::Fr<ppT>::random_element();
    libff::Fr<ppT> pq = p*q;

    libff::Fr<ppT> p_inverse = p.inverse();
    libff::Fr<ppT> q_inverse = q.inverse();

    libff::G1_vector<ppT> G_pub;
    libff::G2_vector<ppT> H_pub;
    std::vector<libff::GT<ppT>> GT_pub;

    G_pub.reserve(input_size);
    H_pub.reserve(input_size/2);
    GT_pub.reserve(input_size/2);

    G_pub.emplace_back( p * gg_keypair.vk.gamma_ABC_g1.rest.values[1] );
    H_pub.emplace_back( p * gg_keypair.vk.gamma_ABC_g2.rest.values[1] );

    for(int i = 2; i < input_size; i++){
        G_pub.emplace_back( q * gg_keypair.vk.gamma_ABC_g1.rest.values[i] );
        if(i%2 == 0){
            H_pub.emplace_back( q * gg_keypair.vk.gamma_ABC_g2.rest.values[i] );
        }
        else{
            libff::GT<ppT> temp_pairing = ppT::reduced_pairing(
                gg_keypair.vk.gamma_ABC_g1.rest.values[1],
                gg_keypair.vk.gamma_ABC_g2.rest.values[i]);
            GT_pub.emplace_back(temp_pairing^pq);
        }
    }
    libff::G1<ppT> g_ak = gg_keypair.pk.alpha_g1;
    libff::G2<ppT> h_gamma_p = p_inverse * gg_keypair.vk.gamma_g2;
    libff::G2<ppT> h_gamma_q = q_inverse * gg_keypair.vk.gamma_g2;

    SF_public_key<ppT> pk( G_pub );
    SF_secret_key<ppT> sk = SF_secret_key<ppT>( H_pub, GT_pub );
    SF_verify_key<ppT> vk = SF_verify_key<ppT>( gg_keypair.pk.alpha_g1,
                                                gg_keypair.vk.gamma_ABC_g1.rest.values[input_size - 2],
                                                h_gamma_p,
                                                h_gamma_q );
    SF_keypair<ppT> sf_keyset = SF_keypair<ppT>( pk, sk, vk );

    return sf_keyset;
}

template <typename ppT>
SF_cypher_text<ppT> SF_encrypt( const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair, 
                                const SF_public_key<ppT> &pk,
                                std::string msg,
                                const r1cs_gg_ppzksnark_auxiliary_input<ppT> &auxiliary_input){
    msg.insert(0,32 - msg.length(),'0');
    std::string m_r(msg); 
    libff::Fr<ppT> r = libff::Fr<ppT>::random_element();
    libff::bigint<4> bg_r = r.as_bigint();
    char char_arr[65] = "";
    gmp_sprintf(char_arr,"%064NX", bg_r.data, bg_r.N);
    m_r = m_r + std::string(char_arr);

    printf("Encrypt test::\n");
    std::cout << "m||r  :: " << m_r << std::endl;

    r1cs_gg_ppzksnark_primary_input<ppT> primary_input;
    primary_input.emplace_back(libff::Fr<ppT>::one());
    primary_input.emplace_back(r);
    for(size_t i = 0; i < m_r.length(); i++){
        primary_input.emplace_back(r);
        int m_r_hex =  (m_r.at(i) >= 'A') ? (m_r.at(i) - 'A' + 10) : (m_r.at(i) - '0');
        primary_input.emplace_back(libff::Fr<ppT>(m_r_hex));
    }
    primary_input.emplace_back(r);
    libff::bigint<4> bg_msg = libff::bigint<4>(msg.c_str(),16);
    primary_input.emplace_back(bg_msg);

    r1cs_gg_ppzksnark_proof<ppT> proof = r1cs_gg_ppzksnark_prover<ppT>(gg_keypair.pk, primary_input, auxiliary_input);
    // const bool ans = r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(gg_keypair.vk, primary_input, proof);
    // std::cout << "gg_verify result:: " << (ans ? "PASS" : "FAIL") << std::endl;
    
    libff::G1_vector<ppT> G1_ct;
    G1_ct.reserve(primary_input.size());

    G1_ct.emplace_back( primary_input[1] * pk.G_pub[0]);
    for(size_t i = 2; i < primary_input.size()-1; i += 2){
        libff::G1<ppT> tmp_ct = primary_input[i] * pk.G_pub[i-1] + primary_input[i+1] * pk.G_pub[i];
        G1_ct.emplace_back( tmp_ct );
    }
    SF_cypher_text<ppT> CT(proof,G1_ct);

    return CT;
}

template <typename ppT>
SF_plain_text<ppT> SF_decrypt( const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair, 
                        const SF_secret_key<ppT> &sk,
                        const SF_cypher_text<ppT> &ct,
                        const r1cs_gg_ppzksnark_auxiliary_input<ppT> &auxiliary_input){
    std::string m_r;
    std::string r_strhex;
    std::string msg;

    for(size_t i = 1; i < ct.G1_ct.size() -1 ; i++){ 
        libff::GT<ppT> ci_sk_0 = ppT::reduced_pairing( ct.G1_ct[i], sk.H_pub[0] );
        libff::GT<ppT> c0_sk_i = ppT::reduced_pairing( ct.G1_ct[0], sk.H_pub[i] );

        libff::GT<ppT> dec_tmp = ci_sk_0 * c0_sk_i.unitary_inverse();
        libff::GT<ppT> sk_tmp =libff::GT<ppT>::one();

        for(size_t j = 0; j < 16; j++){
            if(dec_tmp == sk_tmp){
                m_r += std::string(1,(j >= 10) ? (j - 10 + 'A') : (j + '0') );
                break;
            }
            sk_tmp = sk_tmp * sk.GT_pub[i - 1];
        }
    }

    printf("\n\nDecrypt Test::\n");
    std::cout << "m||r  :: " << m_r << std::endl;

    msg.assign(m_r,0,32);
    std::cout << "m     :: " << msg << std::endl;

    r_strhex.assign(m_r,32,m_r.size());
    libff::bigint<4> r_bndec = libff::bigint<4>(r_strhex.c_str(),16);

    r1cs_gg_ppzksnark_primary_input<ppT> primary_input;

    primary_input.emplace_back(libff::Fr<ppT>::one());
    primary_input.emplace_back(r_bndec);

    for(size_t i = 0; i < m_r.length(); i++){
        primary_input.emplace_back(r_bndec);
        int m_r_hex =  (m_r.at(i) >= 'A') ? (m_r.at(i) - 'A' + 10) : (m_r.at(i) - '0');
        primary_input.emplace_back(libff::Fr<ppT>(m_r_hex));
    }

    primary_input.emplace_back(r_bndec);
    libff::bigint<4> bg_msg = libff::bigint<4>(msg.c_str(),16);
    primary_input.emplace_back(bg_msg);

    r1cs_gg_ppzksnark_proof<ppT> proof = r1cs_gg_ppzksnark_prover<ppT>(gg_keypair.pk, primary_input, auxiliary_input);
    // const bool ans = r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(gg_keypair.vk, primary_input, proof);
    // std::cout << "gg_verify result:: " << (ans ? "PASS" : "FAIL") << std::endl;

    libff::G1<ppT> G1_r = r_bndec * gg_keypair.vk.gamma_ABC_g1.rest.values[gg_keypair.vk.gamma_ABC_g1.rest.size()-2];

    SF_plain_text<ppT> pt = SF_plain_text<ppT>(proof,G1_r,msg);

    return pt;
}

template <typename ppT>
bool SF_enc_verifier(const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair,
                            const SF_verify_key<ppT> &vk,
                            const r1cs_gg_ppzksnark_proof<ppT> &proof,
                            const SF_cypher_text<ppT> &ct){
    libff::G1<ppT> g_acc_c = libff::G1<ppT>::zero();
    libff::G1<ppT> g1_gamma_ABC_g1_01 = gg_keypair.vk.gamma_ABC_g1.first + gg_keypair.vk.gamma_ABC_g1.rest.values[0];
    for(size_t i = 1; i < ct.G1_ct.size(); i++){
        g_acc_c = g_acc_c + ct.G1_ct[i];
    }

    const libff::G1_precomp<ppT> proof_g1_A_precomp = ppT::precompute_G1(proof.g_A);
    const libff::G2_precomp<ppT> proof_g2_B_precomp = ppT::precompute_G2(proof.g_B);

    const libff::G1_precomp<ppT> pk_g1_alpha_precomp = ppT::precompute_G1(gg_keypair.pk.alpha_g1);
    const libff::G2_precomp<ppT> pk_g2_beta_precomp = ppT::precompute_G2(gg_keypair.pk.beta_g2);

    const libff::G1_precomp<ppT> proof_g1_C_precomp = ppT::precompute_G1(proof.g_C);
    const libff::G2_precomp<ppT> vk_g2_delta_precomp = ppT::precompute_G2(gg_keypair.vk.delta_g2);

    const libff::G1_precomp<ppT> proof_g1_c0_precomp = ppT::precompute_G1(ct.G1_ct[0]);
    const libff::G2_precomp<ppT> vk_g2_gamma_p_precomp = ppT::precompute_G2(vk.h_gamma_p);

    const libff::G1_precomp<ppT> proof_g1_cn_precomp = ppT::precompute_G1(g_acc_c);
    const libff::G2_precomp<ppT> vk_g2_gamma_q_precomp = ppT::precompute_G2(vk.h_gamma_q);

    const libff::G1_precomp<ppT> g1_gamma_ABC_g1_01_precomp = ppT::precompute_G1(g1_gamma_ABC_g1_01);
    const libff::G2_precomp<ppT> vk_g2_gamma_precomp = ppT::precompute_G2(gg_keypair.vk.gamma_g2);
    
    libff::Fqk<ppT> QAPl_1 = ppT::miller_loop(proof_g1_A_precomp, proof_g2_B_precomp);
    libff::Fqk<ppT> QAPl_2 = ppT::double_miller_loop(
        proof_g1_C_precomp, vk_g2_delta_precomp,
        pk_g1_alpha_precomp, pk_g2_beta_precomp
        );

    libff::Fqk<ppT> QAPr_1 = ppT::miller_loop(proof_g1_c0_precomp, vk_g2_gamma_p_precomp);
    libff::Fqk<ppT> QAPr_2 = ppT::double_miller_loop(
        proof_g1_cn_precomp, vk_g2_gamma_q_precomp,
        g1_gamma_ABC_g1_01_precomp, vk_g2_gamma_precomp
    ); 

    libff::GT<ppT> QAPl = ppT::final_exponentiation(QAPl_1 * QAPl_2.unitary_inverse());
    libff::GT<ppT> QAPr = ppT::final_exponentiation(QAPr_1 * QAPr_2);

    return (QAPl == QAPr);
}

template <typename ppT>
bool SF_dec_verifier(const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair,
                            const SF_verify_key<ppT> &vk,
                            const r1cs_gg_ppzksnark_proof<ppT> &proof,
                            const SF_plain_text<ppT> &pt,
                            const SF_cypher_text<ppT> &ct){
    libff::G1<ppT> g_acc_c = libff::G1<ppT>::zero();
    libff::bigint<4> bg_msg = libff::bigint<4>(pt.msg.c_str(),16);
    libff::G1<ppT> g1_gamma_ABC_g1_01 = gg_keypair.vk.gamma_ABC_g1.first 
                                        + gg_keypair.vk.gamma_ABC_g1.rest.values[0]
                                        + pt.G1_r 
                                        + bg_msg * gg_keypair.vk.gamma_ABC_g1.rest.values[gg_keypair.vk.gamma_ABC_g1.rest.size()-1];
    for(size_t i = 1; i < ct.G1_ct.size() - 1; i++){
        g_acc_c = g_acc_c + ct.G1_ct[i];
    }

    const libff::G1_precomp<ppT> proof_g1_A_precomp = ppT::precompute_G1(proof.g_A);
    const libff::G2_precomp<ppT> proof_g2_B_precomp = ppT::precompute_G2(proof.g_B);

    const libff::G1_precomp<ppT> pk_g1_alpha_precomp = ppT::precompute_G1(gg_keypair.pk.alpha_g1);
    const libff::G2_precomp<ppT> pk_g2_beta_precomp = ppT::precompute_G2(gg_keypair.pk.beta_g2);

    const libff::G1_precomp<ppT> proof_g1_C_precomp = ppT::precompute_G1(proof.g_C);
    const libff::G2_precomp<ppT> vk_g2_delta_precomp = ppT::precompute_G2(gg_keypair.vk.delta_g2);

    const libff::G1_precomp<ppT> proof_g1_c0_precomp = ppT::precompute_G1(ct.G1_ct[0]);
    const libff::G2_precomp<ppT> vk_g2_gamma_p_precomp = ppT::precompute_G2(vk.h_gamma_p);

    const libff::G1_precomp<ppT> proof_g1_cn_precomp = ppT::precompute_G1(g_acc_c);
    const libff::G2_precomp<ppT> vk_g2_gamma_q_precomp = ppT::precompute_G2(vk.h_gamma_q);

    const libff::G1_precomp<ppT> g1_gamma_ABC_g1_01_precomp = ppT::precompute_G1(g1_gamma_ABC_g1_01);
    const libff::G2_precomp<ppT> vk_g2_gamma_precomp = ppT::precompute_G2(gg_keypair.vk.gamma_g2);
    
    libff::Fqk<ppT> QAPl_1 = ppT::miller_loop(proof_g1_A_precomp, proof_g2_B_precomp);
    libff::Fqk<ppT> QAPl_2 = ppT::double_miller_loop(
        proof_g1_C_precomp, vk_g2_delta_precomp,
        pk_g1_alpha_precomp, pk_g2_beta_precomp
        );

    libff::Fqk<ppT> QAPr_1 = ppT::miller_loop(proof_g1_c0_precomp, vk_g2_gamma_p_precomp);
    libff::Fqk<ppT> QAPr_2 = ppT::double_miller_loop(
        proof_g1_cn_precomp, vk_g2_gamma_q_precomp,
        g1_gamma_ABC_g1_01_precomp, vk_g2_gamma_precomp
    ); 

    libff::GT<ppT> QAPl = ppT::final_exponentiation(QAPl_1 * QAPl_2.unitary_inverse());
    libff::GT<ppT> QAPr = ppT::final_exponentiation(QAPr_1 * QAPr_2);

    //QAPl.print();
    return (QAPl == QAPr);
}

}

#endif
