
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
//SF_public_key
template<typename ppT>
bool SF_public_key<ppT>::operator==(const SF_public_key<ppT> &other) const
{
    return (this->g_1_p == other.g_1_p);
}
template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_public_key<ppT> &pk)
{
    out << pk.g_1_p << OUTPUT_NEWLINE;
    return out;
}
template<typename ppT>
std::istream& operator>>(std::istream &in, SF_public_key<ppT> &pk)
{
    in >> pk.g_1_p;
    libff::consume_OUTPUT_NEWLINE(in);
    return in;
}
//SF_secret_key
template<typename ppT>
bool SF_secret_key<ppT>::operator==(const SF_secret_key<ppT> &other) const
{
    return (this->p == other.p &&
            this->v == other.v);
}
template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_secret_key<ppT> &sk)
{
    out << sk.p << OUTPUT_NEWLINE;
    out << sk.v << OUTPUT_NEWLINE;

    return out;
}
template<typename ppT>
std::istream& operator>>(std::istream &in, SF_secret_key<ppT> &sk)
{
    in >> sk.p;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> sk.v;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}
//SF_verify_enc_key
template<typename ppT>
bool SF_verify_enc_key<ppT>::operator==(const SF_verify_enc_key<ppT> &other) const
{
    return (this->h_lambda_p == other.h_lambda_p);
}
template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_verify_enc_key<ppT> &vk)
{
    out << vk.h_lambda_p << OUTPUT_NEWLINE;
    return out;
}
template<typename ppT>
std::istream& operator>>(std::istream &in, SF_verify_enc_key<ppT> &vk)
{
    in >> vk.h_lambda_p;
    libff::consume_OUTPUT_NEWLINE(in);
    return in;
}
//SF_verify_dec_key
template<typename ppT>
bool SF_verify_dec_key<ppT>::operator==(const SF_verify_dec_key<ppT> &other) const
{
    return (this->h_1_v == other.h_1_v &&
            this->h_1_pv == other.h_1_pv &&
            this->g_2n_2_h_1_pv == other.g_2n_2_h_1_pv);
}
template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_verify_dec_key<ppT> &vk)
{
    out << vk.h_1_v << OUTPUT_NEWLINE;
    out << vk.h_1_pv << OUTPUT_NEWLINE;
    out << vk.g_2n_2_h_1_pv << OUTPUT_NEWLINE;
    return out;
}
template<typename ppT>
std::istream& operator>>(std::istream &in, SF_verify_dec_key<ppT> &vk)
{
    in >> vk.h_1_v;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.h_1_pv;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.g_2n_2_h_1_pv;
    libff::consume_OUTPUT_NEWLINE(in);
    return in;
}
//SF_keypair
template<typename ppT>
bool SF_keypair<ppT>::operator==(const SF_keypair<ppT> &other) const
{
    return (this->pk == other.pk &&
            this->sk == other.sk &&
            this->vk_enc == other.vk_enc &&
            this->vk_dec == other.vk_dec );
}
template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_keypair<ppT> &keypair)
{
    out << keypair.pk;
    out << keypair.sk;
    out << keypair.vk_enc;
    out << keypair.vk_dec;
    return out;
}
template<typename ppT>
std::istream& operator>>(std::istream &in, SF_keypair<ppT> &keypair)
{
    in >> keypair.pk;
    in >> keypair.sk;
    in >> keypair.vk_enc;
    in >> keypair.vk_dec;
    return in;
}
//SF_cypher_text
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
//SF_plain_text
template<typename ppT>
bool SF_plain_text<ppT>::operator==(const SF_plain_text<ppT> &other) const
{
    return (this->msg == other.msg &&
            this->vm == other.vm);
}
template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_plain_text<ppT> &pt)
{
    out << pt.msg << OUTPUT_NEWLINE;
    out << pt.vm << OUTPUT_NEWLINE;
    return out;
}
template<typename ppT>
std::istream& operator>>(std::istream &in, SF_plain_text<ppT> &pt)
{
    in >> pt.msg;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pt.vm;
    libff::consume_OUTPUT_NEWLINE(in);
    return in;
}
// end stream

template <typename ppT>
SF_keypair<ppT> SF_key_generator(const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair){
    const int input_size = gg_keypair.vk.gamma_ABC_g1.rest.values.size();

    libff::Fr<ppT> p = libff::Fr<ppT>::random_element();
    libff::Fr<ppT> v = libff::Fr<ppT>::random_element();
    libff::Fr<ppT> pv = p*v;

    libff::Fr<ppT> p_inverse = p.inverse();

    libff::G1<ppT> g_1_p = p * gg_keypair.vk.gamma_ABC_g1.rest.values[1];
    
    libff::G2<ppT> h_lambda_p =  p_inverse * gg_keypair.vk.gamma_g2;

    libff::G2<ppT> h_1_v =  v * gg_keypair.vk.gamma_ABC_g2.rest.values[1];
    libff::G2<ppT> h_1_pv =  p * h_1_v;
    libff::GT<ppT> g_2n_2_h_1_pv = ppT::reduced_pairing(
        gg_keypair.vk.gamma_ABC_g1.rest.values[gg_keypair.vk.gamma_ABC_g1.rest.values.size()-8],
        h_1_pv);
    
    SF_public_key<ppT> pk( g_1_p );
    SF_secret_key<ppT> sk = SF_secret_key<ppT>( p, v );
    SF_verify_enc_key<ppT> vk_enc = SF_verify_enc_key<ppT> (h_lambda_p);
    SF_verify_dec_key<ppT> vk_dec = SF_verify_dec_key<ppT> (h_1_v, h_1_pv, g_2n_2_h_1_pv);
    SF_keypair<ppT> sf_keyset = SF_keypair<ppT>( pk, sk, vk_enc, vk_dec);

    return sf_keyset;
}

template <typename ppT>
SF_cypher_text<ppT> SF_encrypt( const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair, 
                                const SF_public_key<ppT> &pk,
                                std::string msg,
                                const r1cs_gg_ppzksnark_primary_input<ppT> &r1cs_primary_input,
                                const r1cs_gg_ppzksnark_auxiliary_input<ppT> &auxiliary_input){
    libff::Fr<ppT> r = libff::Fr<ppT>::random_element();

    printf("Encrypt test::\n");
    std::cout << "msg  :: " << msg << std::endl;

    r1cs_gg_ppzksnark_primary_input<ppT> primary_input;
    primary_input.emplace_back(libff::Fr<ppT>::one());
    primary_input.emplace_back(r);
    for(size_t i = 0; i < msg.length(); i = i+8){
        primary_input.emplace_back(r);
        unsigned int msg_hex = 0;
        for(size_t j = 0; j < 8; j++){
            msg_hex *= 16;
            msg_hex += (msg.at(i+j) >= 'A') ? (msg.at(i+j) - 'A' + 10) : (msg.at(i+j) - '0');
        }
        primary_input.emplace_back(libff::Fr<ppT>(msg_hex));
    }
    primary_input.emplace_back(r);
    libff::bigint<4> bg_msg = libff::bigint<4>(msg.c_str(),16);
    primary_input.emplace_back(bg_msg);

    libff::G1_vector<ppT> G1_ct;
    G1_ct.reserve(primary_input.size());

    G1_ct.emplace_back( primary_input[1] * pk.g_1_p);
    //std::cout<< "input Size:: " << r1cs_primary_input.size()<<std::endl;
    int msg_size = primary_input.size();
    for(size_t i = 2; i < msg_size; i += 2){
        libff::G1<ppT> tmp_ct = primary_input[i] * gg_keypair.vk.gamma_ABC_g1.rest.values[i] 
                            + primary_input[i+1] * gg_keypair.vk.gamma_ABC_g1.rest.values[i+1];
        G1_ct.emplace_back( tmp_ct );
        //printf("::: %d :: ",i);
        //tmp_ct.print();
        //primary_input[i].print();
        //primary_input[i+1].print();
    }

    for(size_t i = msg_size; i < r1cs_primary_input.size();i++){
        primary_input.emplace_back(r1cs_primary_input[i]);
    }
    // for(size_t i = 0; i < primary_input.size(); i++){
    //     printf("::: %d :: ",i);
    //     primary_input[i].print();
    // }

    r1cs_gg_ppzksnark_proof<ppT> proof = r1cs_gg_ppzksnark_prover<ppT>(gg_keypair.pk, primary_input, auxiliary_input);
    // const bool ans = r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(gg_keypair.vk, primary_input, proof);
    // std::cout << "gg_verify result:: " << (ans ? "PASS" : "FAIL") << std::endl;

    SF_cypher_text<ppT> CT(proof,G1_ct);

    return CT;
}

template <typename ppT>
SF_plain_text<ppT> SF_decrypt( const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair, 
                        const SF_secret_key<ppT> &sk,
                        const vector<SF_cypher_text<ppT>> &ct){
                         
    libff::G1<ppT> C0_new = libff::G1<ppT>::zero();
    libff::Fr<ppT> m_new = libff::Fr<ppT>::zero();

    for (size_t ct_i = 0; ct_i < ct.size(); ct_i++){
        std::string msg;

        for (size_t i = 1; i < ct[ct_i].G1_ct.size() - 1; i++){
            libff::GT<ppT> ci_sk_0 = ppT::reduced_pairing(
                ct[ct_i].G1_ct[i], 
                sk.p * gg_keypair.vk.gamma_ABC_g2.rest.values[1]);
            libff::GT<ppT> c0_sk_i = ppT::reduced_pairing(
                ct[ct_i].G1_ct[0], 
                gg_keypair.vk.gamma_ABC_g2.rest.values[2*i]);

            libff::GT<ppT> dec_tmp = ci_sk_0 * c0_sk_i.unitary_inverse();
            libff::GT<ppT> sk_tmp = libff::GT<ppT>::one();

            if (dec_tmp == sk_tmp)
                msg += "00000000";
            else
                msg += "00000001";
        }

        printf("\n\nDecrypt Test::\n");
        std::cout << "msg  :: " << msg << std::endl;
        libff::bigint<4> bg_msg = libff::bigint<4>(msg.c_str(),16);

        C0_new = C0_new + ct[ct_i].G1_ct[0];
        m_new = m_new + libff::Fr<ppT>(bg_msg);
    }

    std::cout << "m_new ::: "; m_new.print();
    std::cout << "C_new ::: "; C0_new.print();

    libff::G1<ppT> verify_c0 = sk.v * C0_new;

    SF_plain_text<ppT> pt = SF_plain_text<ppT>(m_new,verify_c0);

    return pt;
}

template <typename ppT>
bool SF_enc_verifier(const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair,
                            const SF_verify_enc_key<ppT> &vk,
                            const SF_cypher_text<ppT> &ct,
                            const r1cs_gg_ppzksnark_primary_input<ppT> &r1cs_primary_input){
    size_t i = 0;
    // for(i = 0; i < r1cs_primary_input.size(); i++){
    //     printf("::: %d :: ",i); r1cs_primary_input[i].print();
    // }
    libff::G1<ppT> g_acc_c = libff::G1<ppT>::zero();
    libff::G1<ppT> test = libff::G1<ppT>::zero();
    libff::G1<ppT> g1_gamma_ABC_g1_01 = gg_keypair.vk.gamma_ABC_g1.first + gg_keypair.vk.gamma_ABC_g1.rest.values[0];
    for(i = 1; i < ct.G1_ct.size(); i++){
        g_acc_c = g_acc_c + ct.G1_ct[i];
    }
    
    for(i = ct.G1_ct.size()*2; i < r1cs_primary_input.size(); i++){
        g1_gamma_ABC_g1_01 = g1_gamma_ABC_g1_01 + r1cs_primary_input[i] * gg_keypair.vk.gamma_ABC_g1.rest.values[i];
    }

    const libff::G1_precomp<ppT> proof_g1_A_precomp = ppT::precompute_G1(ct.proof.g_A);
    const libff::G2_precomp<ppT> proof_g2_B_precomp = ppT::precompute_G2(ct.proof.g_B);

    const libff::G1_precomp<ppT> pk_g1_alpha_precomp = ppT::precompute_G1(gg_keypair.pk.alpha_g1);
    const libff::G2_precomp<ppT> pk_g2_beta_precomp = ppT::precompute_G2(gg_keypair.pk.beta_g2);

    const libff::G1_precomp<ppT> proof_g1_C_precomp = ppT::precompute_G1(ct.proof.g_C);
    const libff::G2_precomp<ppT> vk_g2_delta_precomp = ppT::precompute_G2(gg_keypair.vk.delta_g2);

    const libff::G1_precomp<ppT> proof_g1_c0_precomp = ppT::precompute_G1(ct.G1_ct[0]);
    const libff::G2_precomp<ppT> vk_g2_gamma_p_precomp = ppT::precompute_G2(vk.h_lambda_p);

    const libff::G1_precomp<ppT> proof_g1_cn_precomp = ppT::precompute_G1(g_acc_c);
    const libff::G2_precomp<ppT> vk_g2_gamma_q_precomp = ppT::precompute_G2(gg_keypair.vk.gamma_g2);

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
                     const SF_plain_text<ppT> &pt,
                     const vector<SF_cypher_text<ppT>> &ct_vect,
                     const SF_verify_dec_key<ppT> &vk){
    libff::G1<ppT> acc_c0 = libff::G1<ppT>::zero();
    libff::G1<ppT> acc_cn = libff::G1<ppT>::zero();
    for(size_t i = 0; i < ct_vect.size(); i++){
        acc_c0 = acc_c0 + ct_vect[i].G1_ct[0];
        acc_cn = acc_cn + ct_vect[i].G1_ct[ct_vect[i].G1_ct.size()-1];
    }
    libff::GT<ppT> vm_h1 = ppT::reduced_pairing(
        pt.vm,
        gg_keypair.vk.gamma_ABC_g2.rest.values[1]);
    libff::GT<ppT> c0_vk0 = ppT::reduced_pairing(
        acc_c0,
        vk.h_1_v);

    const libff::G1_precomp<ppT> acc_cn_precomp = ppT::precompute_G1( acc_cn );
    const libff::G2_precomp<ppT> vk1_precomp = ppT::precompute_G2( vk.h_1_pv );

    const libff::G1_precomp<ppT> vm_precomp = ppT::precompute_G1( pt.vm );
    const libff::G2_precomp<ppT> hcx_precomp = ppT::precompute_G2( 
        gg_keypair.vk.gamma_ABC_g2.rest.values[gg_keypair.vk.gamma_ABC_g2.rest.values.size()-9] );

    libff::Fqk<ppT> QAP1 = ppT::miller_loop(acc_cn_precomp, vk1_precomp);
    libff::Fqk<ppT> QAP2 = ppT::miller_loop(vm_precomp, hcx_precomp);
    
    libff::GT<ppT> QAPl = ppT::final_exponentiation(QAP1 * QAP2.unitary_inverse());
    libff::GT<ppT> QAPr = vk.g_2n_2_h_1_pv ^ pt.msg;

    // printf(":::: vm,H1 :::: \n"); vm_h1.print();
    // printf(":::: c0,vk0 :::: \n"); c0_vk0.print();
    // printf("\n:::: QAPl :::: \n"); QAPl.print();
    // printf(":::: pt.msg*vk.g_2n_2_h_1_pv :::: \n"); QAPr.print();

    return ( vm_h1 == c0_vk0 && QAPl == QAPr);
}

}

#endif
