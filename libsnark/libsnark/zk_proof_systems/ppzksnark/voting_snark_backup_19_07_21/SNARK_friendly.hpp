
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
    libff::G1<ppT> g_1_p;

    SF_public_key() {};
    SF_public_key<ppT>& operator=(const SF_public_key<ppT> &other) = default;
    SF_public_key(const SF_public_key<ppT> &other) = default;
    SF_public_key(SF_public_key<ppT> &&other) = default;
    SF_public_key(libff::G1<ppT> &g_1_p) :
        g_1_p(g_1_p)
    {};

    size_t size_in_bits() const
    {
        return (libff::G1<ppT>::size_in_bits());
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
    libff::Fr<ppT> p;
    libff::Fr<ppT> v;

    SF_secret_key() {};
    SF_secret_key<ppT>& operator=(const SF_secret_key<ppT> &other) = default;
    SF_secret_key(const SF_secret_key<ppT> &other) = default;
    SF_secret_key(SF_secret_key<ppT> &&other) = default;
    SF_secret_key(
                    libff::Fr<ppT> &p,
                    libff::Fr<ppT> &v) :
        p(p),
        v(v)
    {};

    size_t size_in_bits() const
    {
        return (libff::Fr<ppT>::size_in_bits()) + (libff::Fr<ppT>::size_in_bits());
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
class SF_verify_enc_key;
template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_verify_enc_key<ppT> &vk);
template<typename ppT>
std::istream& operator>>(std::istream &in, SF_verify_enc_key<ppT> &vk);

template<typename ppT>
class SF_verify_enc_key{
public:
    libff::G2<ppT> h_lambda_p;

    SF_verify_enc_key() {};
    SF_verify_enc_key<ppT>& operator=(const SF_verify_enc_key<ppT> &other) = default;
    SF_verify_enc_key(const SF_verify_enc_key<ppT> &other) = default;
    SF_verify_enc_key(SF_verify_enc_key<ppT> &&other) = default;
    SF_verify_enc_key(libff::G2<ppT> &h_lambda_p) :
        h_lambda_p(h_lambda_p)
    {};

    size_t size_in_bits() const
    {
        return (1 * libff::G2<ppT>::size_in_bits());
    }

    void print_size() const
    {
        libff::print_indent(); printf("* SF_VK_enc size in bits: %zu\n",this->size_in_bits);
    }
    bool operator==(const SF_verify_enc_key<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const SF_verify_enc_key<ppT> &vk);
    friend std::istream& operator>> <ppT>(std::istream &in, SF_verify_enc_key<ppT> &vk);
};

template<typename ppT>
class SF_verify_dec_key;
template<typename ppT>
std::ostream& operator<<(std::ostream &out, const SF_verify_dec_key<ppT> &vk);
template<typename ppT>
std::istream& operator>>(std::istream &in, SF_verify_dec_key<ppT> &vk);

template<typename ppT>
class SF_verify_dec_key{
public:
    libff::G2<ppT> h_1_v;
    libff::G2<ppT> h_1_pv;
    libff::GT<ppT> g_2n_2_h_1_pv;

    SF_verify_dec_key() {};
    SF_verify_dec_key<ppT>& operator=(const SF_verify_dec_key<ppT> &other) = default;
    SF_verify_dec_key(const SF_verify_dec_key<ppT> &other) = default;
    SF_verify_dec_key(SF_verify_dec_key<ppT> &&other) = default;
    SF_verify_dec_key(
                        libff::G2<ppT> &h_1_v,
                        libff::G2<ppT> &h_1_pv,
                        libff::GT<ppT> &g_2n_2_h_1_pv) :
        h_1_v(h_1_v),
        h_1_pv(h_1_pv),
        g_2n_2_h_1_pv(g_2n_2_h_1_pv)
    {};

    size_t size_in_bits() const
    {
        return (2 * libff::G2<ppT>::size_in_bits() + libff::G2<ppT>::size_in_bits() * libff::G1<ppT>::size_in_bits());
    }

    void print_size() const
    {
        libff::print_indent(); printf("* SF_VK_enc size in bits: %zu\n",this->size_in_bits);
    }
    bool operator==(const SF_verify_dec_key<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const SF_verify_dec_key<ppT> &vk);
    friend std::istream& operator>> <ppT>(std::istream &in, SF_verify_dec_key<ppT> &vk);
};

template<typename ppT>
class SF_keypair{
public:
    SF_public_key<ppT> pk;
    SF_secret_key<ppT> sk;
    SF_verify_enc_key<ppT> vk_enc;
    SF_verify_dec_key<ppT> vk_dec;

    //SK_keypair() = default;
    SF_keypair(const SF_keypair<ppT> &other) = default;
    SF_keypair( SF_public_key<ppT> &pk,
                SF_secret_key<ppT> &sk,
                SF_verify_enc_key<ppT> &vk_enc,
                SF_verify_dec_key<ppT> &vk_dec) :
        pk(std::move(pk)),
        sk(std::move(sk)),
        vk_enc(std::move(vk_enc)),
        vk_dec(std::move(vk_dec))
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
    libff::Fr<ppT> msg;
    libff::G1<ppT> vm;

    SF_plain_text() {};
    SF_plain_text<ppT>& operator=(const SF_plain_text<ppT> &other) = default;
    SF_plain_text(const SF_plain_text<ppT> &other) = default;
    SF_plain_text(SF_plain_text<ppT> &&other) = default;
    SF_plain_text(
                        libff::Fr<ppT> &msg,
                        libff::G1<ppT> &vm ) :
        msg(std::move(msg)),
        vm(std::move(vm))
    {};

    size_t size_in_bits() const
    {
        return (msg.size_in_bits()) + libff::G1<ppT>::size_in_bits();
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
                                std::string msg,
                                const r1cs_gg_ppzksnark_primary_input<ppT> &r1cs_primary_input,
                                const r1cs_gg_ppzksnark_auxiliary_input<ppT> &auxiliary_input);

template <typename ppT>
SF_plain_text<ppT> SF_decrypt(  const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair, 
                                const SF_secret_key<ppT> &sk,
                                const vector<SF_cypher_text<ppT>> &ct);

template <typename ppT>
bool SF_enc_verifier(const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair,
                            const SF_verify_enc_key<ppT> &vk,
                            const SF_cypher_text<ppT> &ct,
                            const r1cs_gg_ppzksnark_primary_input<ppT> &r1cs_primary_input);     
                                           
template <typename ppT>
bool SF_dec_verifier(const r1cs_gg_ppzksnark_keypair<ppT> &gg_keypair,
                     const SF_plain_text<ppT> &pt,
                     const vector<SF_cypher_text<ppT>> &ct_vect,
                     const SF_verify_dec_key<ppT> &vk);
}
#include <libsnark/zk_proof_systems/ppzksnark/voting_snark/SNARK_friendly.tcc>
#endif