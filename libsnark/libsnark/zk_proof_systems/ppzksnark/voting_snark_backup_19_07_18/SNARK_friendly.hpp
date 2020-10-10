
#ifndef SNARK_FRIENDLY_HPP_
#define SNARK_FRIENDLY_HPP_

#include <memory>

#include <libff/algebra/curves/public_params.hpp>

#include <libsnark/common/data_structures/accumulation_vector.hpp>
#include <libsnark/knowledge_commitment/knowledge_commitment.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/voting_snark/r1cs_gg_ppzksnark_params.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/voting_snark/r1cs_gg_ppzksnark.hpp>

namespace libsnark {

template<typename ppT>
class SF_public_key;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_public_key<ppT> &pk);

template<typename ppT>
std::istream& operator>>(std::istream &in, SF_public_key<ppT> &pk);

template<typename ppT>
class SF_public_key{
public:
    libff::G1_vector<ppT> G_pub;

    SF_public_key() {};
    SF_public_key<ppT>& operator=(const SF_public_key<ppT> &other) = default;
    SF_public_key(const SF_public_key<ppT> &other) = default;
    SF_public_key(SF_public_key<ppT> &&other) = default;
    SF_public_key(libff::G1_vector<ppT> &G_pub) :
        G_pub(G_pub)
    {};

    size_t size_in_bits() const
    {
        return (libff::size_in_bits(G_pub));
    }

    void print_size() const
    {
        libff::print_indent(); printf("* SF_PK size in bits: %zu\n",this->size_in_bits);
    }
    bool operator==(const SF_public_key<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const SF_public_key<ppT> &pk);
    friend std::istream& operator>> <ppT>(std::istream &in, SF_public_key<ppT> &pk);
};

template<typename ppT>
class SF_secret_key;
template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_secret_key<ppT> &sk);
template<typename ppT>
std::istream& operator>>(std::istream &in, SF_secret_key<ppT> &sk);

template<typename ppT>
class SF_secret_key{
public:
    libff::G2_vector<ppT> H_pub;
    std::vector<libff::GT<ppT>> GT_pub;

    SF_secret_key() {};
    SF_secret_key<ppT>& operator=(const SF_secret_key<ppT> &other) = default;
    SF_secret_key(const SF_secret_key<ppT> &other) = default;
    SF_secret_key(SF_secret_key<ppT> &&other) = default;
    SF_secret_key(libff::G2_vector<ppT> &H_pub,
                  std::vector<libff::GT<ppT>> &GT_pub) :
        H_pub(H_pub),
        GT_pub(GT_pub)
    {};

    size_t size_in_bits() const
    {
        return (libff::size_in_bits(H_pub)) + (libff::size_in_bits(GT_pub));
    }

    void print_size() const
    {
        libff::print_indent(); printf("* SF_SK size in bits: %zu\n",this->size_in_bits);
    }
    bool operator==(const SF_secret_key<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const SF_secret_key<ppT> &sk);
    friend std::istream& operator>> <ppT>(std::istream &in, SF_secret_key<ppT> &sk);
};

template<typename ppT>
class SF_verify_key;
template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_verify_key<ppT> &vk);
template<typename ppT>
std::istream& operator>>(std::istream &in, SF_verify_key<ppT> &vk);

template<typename ppT>
class SF_verify_key{
public:
    libff::G1<ppT> g_ak;
    libff::G1<ppT> g_k_2n2;
    libff::G2<ppT> h_gamma_p; //  lambda
    libff::G2<ppT> h_gamma_q;

    SF_verify_key() {};
    SF_verify_key<ppT>& operator=(const SF_verify_key<ppT> &other) = default;
    SF_verify_key(const SF_verify_key<ppT> &other) = default;
    SF_verify_key(SF_verify_key<ppT> &&other) = default;
    SF_verify_key(  libff::G1<ppT> g_ak,
                    libff::G1<ppT> g_k_2n2,
                    libff::G2<ppT> h_gamma_p,
                    libff::G2<ppT> h_gamma_q) :
        g_ak(g_ak),
        g_k_2n2(g_k_2n2),
        h_gamma_p(h_gamma_p),
        h_gamma_q(h_gamma_q)
    {};

    size_t size_in_bits() const
    {
        return (2 * libff::G2<ppT>::size_in_bits() + 2 * libff::G1<ppT>::size_in_bits());
    }

    void print_size() const
    {
        libff::print_indent(); printf("* SF_VK size in bits: %zu\n",this->size_in_bits);
    }
    bool operator==(const SF_verify_key<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const SF_verify_key<ppT> &vk);
    friend std::istream& operator>> <ppT>(std::istream &in, SF_verify_key<ppT> &vk);
};
template<typename ppT>
class SF_keypair{
public:
    SF_public_key<ppT> pk;
    SF_secret_key<ppT> sk;
    SF_verify_key<ppT> vk;

    //SK_keypair() = default;
    SF_keypair(const SF_keypair<ppT> &other) = default;
    SF_keypair( SF_public_key<ppT> &pk,
                SF_secret_key<ppT> &sk,
                SF_verify_key<ppT> &vk) :
        pk(std::move(pk)),
        sk(std::move(sk)),
        vk(std::move(vk))
    {}

    SF_keypair(SF_keypair<ppT> &&other) = default;
};

template<typename ppT>
class SF_cypher_text;
template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_cypher_text<ppT> &ct);
template<typename ppT>
std::istream& operator>>(std::istream &in, SF_cypher_text<ppT> &ct);

template<typename ppT>
class SF_cypher_text{
public:
    r1cs_gg_ppzksnark_proof<ppT> proof;
    libff::G1_vector<ppT> G1_ct;
    r1cs_gg_ppzksnark_primary_input<ppT> primary_input;

    SF_cypher_text() {};
    SF_cypher_text<ppT>& operator=(const SF_cypher_text<ppT> &other) = default;
    SF_cypher_text(const SF_cypher_text<ppT> &other) = default;
    SF_cypher_text(SF_cypher_text<ppT> &&other) = default;
    SF_cypher_text(
                    r1cs_gg_ppzksnark_proof<ppT> &proof,
                    libff::G1_vector<ppT> &G1_ct ) :
        proof(std::move(proof)),
        G1_ct(std::move(G1_ct))
    {};

    size_t size_in_bits() const
    {
        return (proof.size_in_bits()) + (libff::size_in_bits(G1_ct));
    }

    void print_size() const
    {
        libff::print_indent(); printf("* SF_CT size in bits: %zu\n",this->size_in_bits);
    }
    bool operator==(const SF_cypher_text<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const SF_cypher_text<ppT> &ct);
    friend std::istream& operator>> <ppT>(std::istream &in, SF_cypher_text<ppT> &ct);
};

template<typename ppT>
class SF_plain_text;
template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_plain_text<ppT> &pt);
template<typename ppT>
std::istream& operator>>(std::istream &in, SF_plain_text<ppT> &pt);

template<typename ppT>
class SF_plain_text{
public:
    libff::Fr<ppT> r_new;
    std::string msg;

    SF_plain_text() {};
    SF_plain_text<ppT>& operator=(const SF_plain_text<ppT> &other) = default;
    SF_plain_text(const SF_plain_text<ppT> &other) = default;
    SF_plain_text(SF_plain_text<ppT> &&other) = default;
    SF_plain_text(
                    libff::Fr<ppT> r_new,
                    std::string &msg ) :
        r_new(std::move(r_new)),
        msg(std::move(msg))
    {};

    size_t size_in_bits() const
    {
        return (r_new.size_in_bits()) + msg.size() * 8;
    }

    void print_size() const
    {
        libff::print_indent(); printf("* SF_CT size in bits: %zu\n",this->size_in_bits);
    }
    bool operator==(const SF_plain_text<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const SF_plain_text<ppT> &pt);
    friend std::istream& operator>> <ppT>(std::istream &in, SF_plain_text<ppT> &pt);
};

template <typename ppT>
SF_keypair<ppT> SF_key_generator(const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair);

template <typename ppT>
SF_cypher_text<ppT> SF_encrypt( const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair, 
                                const SF_public_key<ppT> &pk,
                                const std::string msg,
                                const r1cs_gg_ppzksnark_primary_input<ppT> &r1cs_primary_input,
                                const r1cs_gg_ppzksnark_auxiliary_input<ppT> &auxiliary_input);

template <typename ppT>
SF_plain_text<ppT> SF_decrypt(  const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair, 
                                const SF_secret_key<ppT> &sk,
                                const vector<SF_cypher_text<ppT>> &ct);

template <typename ppT>
bool SF_enc_verifier(const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair,
                     const SF_verify_key<ppT> &vk,
                     const r1cs_gg_ppzksnark_proof<ppT> &proof,
                     const r1cs_gg_ppzksnark_primary_input<ppT> &r1cs_primary_input,
                     const SF_cypher_text<ppT> &ct);     
                                           
template <typename ppT>
bool SF_dec_verifier(const SF_public_key<ppT> &pk,
                     const SF_plain_text<ppT> &pt,
                     const vector<SF_cypher_text<ppT>> &ct_vect);
}
#include <libsnark/zk_proof_systems/ppzksnark/voting_snark/SNARK_friendly.tcc>
#endif