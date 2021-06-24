#include <iostream>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <flint/fmpz.h>
#include <vector> 
#include <map>
#include <math.h>
#include <time.h>
#include <string.h>
#include <string>
#include <cstdlib>
#include <ctime>


#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>   
#include <libsnark/zk_proof_systems/ppzksnark/membership/membership_snark.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>




using namespace std;


namespace membership{
    typedef struct {
        int security_level;
        fmpz_t N;
        fmpz_t p;
        fmpz_t q;
        fmpz_t V; 
        vector<BIGNUM*> prime_e; 
    }_struct_pp_;

    typedef struct {
        BIGNUM* W;
        BIGNUM* C_x;
        BIGNUM* C_y;
        BIGNUM* k;
        BIGNUM* opt_k;
        BIGNUM* h;
        BIGNUM* Q;
        BIGNUM* l;
    }_struct_proof_;

    typedef struct {
        vector<pair<BIGNUM*, int>> user_key; 
    }_struct_user_;


    void print_point(const char* msg) {
        cout << endl << "================================================================================" << endl;
        cout << msg << endl;
        cout  << "================================================================================" << endl << endl;
    }
    
    int groupGen(_struct_pp_* pp, const int lambda, const int logD) {
        BIGNUM* bn_N = BN_new();
        BIGNUM* bn_p = BN_new();
        BIGNUM* bn_q = BN_new();
        BN_CTX* ctx = BN_CTX_new();

        pp->security_level = lambda;
        do{
            BN_generate_prime_ex(bn_p, lambda>>1, 1, NULL, NULL, NULL);
            BN_generate_prime_ex(bn_q, lambda>>1, 1, NULL, NULL, NULL);
            BN_mul(bn_N, bn_p, bn_q, ctx);
            fmpz_set_str(pp->N, BN_bn2hex(bn_N), 16);
        }while(BN_num_bits(bn_N) != lambda);
        
        // BN_copy(pp->p, bn_p);
        // BN_copy(pp->q, bn_q);
        do{
            BN_generate_prime_ex(bn_p, lambda/2, 0, NULL, NULL, NULL);
            fmpz_set_str(pp->V, BN_bn2hex(bn_p), 16);
        }while(0);

        BN_generate_prime_ex(bn_p, 128, 0, NULL, NULL, NULL);
        fmpz_set_str(pp->p, BN_bn2hex(bn_p), 16);

        fmpz_init_set_ui(pp->q, 0);
        fmpz_setbit(pp->q, 128*(2*logD+1));


        BN_free(bn_N);
        BN_free(bn_p);
        BN_free(bn_q);
        BN_CTX_free(ctx);

        return 1;
    }

    int pp_init(_struct_pp_* pp) {
        fmpz_init(pp->N);
        fmpz_init(pp->p);
        fmpz_init(pp->q);
        fmpz_init(pp->V);

        return 1;
    }

    int pp_clear(_struct_pp_* pp) {
        fmpz_clear(pp->N);
        fmpz_clear(pp->p);
        fmpz_clear(pp->q);
        fmpz_clear(pp->V);

        return 1;
    }

    int write_pp(const char* path, _struct_pp_* pp) {
        FILE* fp;

        fp = fopen(path, "w");

        fprintf(fp, "%x\n", pp->security_level);
        fprintf(fp, "%s\n", fmpz_get_str(NULL, 16, pp->N));
        fprintf(fp, "%s\n", fmpz_get_str(NULL, 16, pp->N));
        fprintf(fp, "%x\n", (int)fmpz_bits(pp->q)-1);
        fprintf(fp, "%s\n", fmpz_get_str(NULL, 16, pp->p));
        fprintf(fp, "%s\n", fmpz_get_str(NULL, 16, pp->V));
        fclose(fp);

        return 1;
    }

    void print_BN(BIGNUM* p, string s) {
        cout << s << endl;
        char *a;
        a = BN_bn2dec(p);
        cout << a << endl << endl;
    }

    // pk = H(sk)
    void Hash1(BIGNUM* res, int sk) {
        unsigned char hash_digest[SHA256_DIGEST_LENGTH];
        char temp[2048];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);

        sprintf(temp, "%d", sk);
        SHA256_Update(&sha256, temp, strlen(temp));

        SHA256_Final(hash_digest, &sha256);   

        BN_bin2bn(hash_digest, 32, res);
    }

    // ret = H(W||C||R) = H(W||C_x||C_y||R)
    void Hash2(BIGNUM* ret, BIGNUM* W, BIGNUM* C_x, BIGNUM* C_y, BIGNUM* R) {
        unsigned char hash_digest[SHA256_DIGEST_LENGTH];
        unsigned char temp[2048];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);

        BN_bn2bin(W, temp);
        SHA256_Update(&sha256, temp, BN_num_bytes(W));
        BN_bn2bin(C_x, temp);
        SHA256_Update(&sha256, temp, BN_num_bytes(C_x));
        BN_bn2bin(C_y, temp);
        SHA256_Update(&sha256, temp, BN_num_bytes(C_y));        
        BN_bn2bin(R, temp);
        SHA256_Update(&sha256, temp, BN_num_bytes(R));

        SHA256_Final(hash_digest, &sha256);

        BN_bin2bn(hash_digest, 32, ret);
    }

    // l <-Hash3(V||W), which is prime number. 
    void Hash3(BIGNUM* ret, BIGNUM* V, BIGNUM* W) {
        unsigned char hash_digest[SHA256_DIGEST_LENGTH];
        unsigned char temp[2048];
        SHA256_CTX sha256_ctx;
        SHA256_Init(&sha256_ctx);
        BN_CTX* bn_ctx = BN_CTX_new();

        do{
            BN_bn2bin(V, temp);
            SHA256_Update(&sha256_ctx, temp, BN_num_bytes(V));

            BN_bn2bin(W, temp);
            SHA256_Update(&sha256_ctx, temp, BN_num_bytes(W));

            SHA256_Final(hash_digest, &sha256_ctx);

            BN_bin2bn(hash_digest, 32, ret);        
        }while(!BN_is_prime(ret, 5, NULL, bn_ctx, NULL));
    }

    void setup(_struct_pp_* pp, int n, int lambda, int logD) {
        libff::start_profiling();
        libff::enter_block("Call to setup for membership test");
        BN_CTX* ctx = BN_CTX_new();
        
        // Choose an unknown order group and generator of it. 
        pp_init(pp);
        groupGen(pp, lambda, logD);
    
        int cnt = 0;
        int num = 3;

        // Choose the smallest odd primes of e_1 ~ e_n        
        while(cnt != n){
            BIGNUM* temp = BN_new();
            string str_num = to_string(num);
            BN_dec2bn(&temp, str_num.c_str());

            if(!BN_is_prime(temp, 5, NULL, ctx, NULL))
            {
                num++;
                continue;
            }
            pp->prime_e.push_back(temp);
            cnt++; num++;
        }        

        BN_CTX_free(ctx);
        libff::leave_block("Call to setup for membership test");
    }

    void add(vector<BIGNUM*> &U, vector<BIGNUM*> u) {
        libff::start_profiling();
        libff::enter_block("Call to Add; add new user to existing set");
        for(auto x : u) {
            U.push_back(x);
        }
        // U.push_back(u);
        libff::leave_block("Call to Add; add new user to existing set");
    }

    void accumulate(_struct_pp_* pp, vector<BIGNUM*> U, BIGNUM* &ACC) {
        libff::start_profiling();
        libff::enter_block("Call to Accumulate");

        BN_CTX* bn_ctx = BN_CTX_new();
        BIGNUM* bn_V = BN_new();    
        BN_hex2bn(&bn_V, fmpz_get_str(NULL, 16, pp->V));
    
        BIGNUM* bn_N = BN_new();
        BN_hex2bn(&bn_N, fmpz_get_str(NULL, 16, pp->N)); 
      
        // exponentiation part, which is to be raised on ACC       
        BIGNUM* bn_acc_exp = BN_new(); 
        BN_copy(bn_acc_exp, BN_value_one());

        // multiplication all of the e_i which is prime_e
        for(auto x : pp->prime_e) {
            BN_mul(bn_acc_exp, bn_acc_exp, x, bn_ctx);
        }
        
        // multiplication e_i (bn_acc_exp) and u_j
        for(auto x : U) {
            BN_mul(bn_acc_exp, bn_acc_exp, x, bn_ctx);
            // BN_mod_mul(bn_acc_exp, bn_acc_exp, x, bn_phiN, bn_ctx);            
        }

        // ACC <- V^{e_i * u_j}
        BN_mod_exp(ACC, bn_V, bn_acc_exp, bn_N, bn_ctx);
        
        BN_CTX_free(bn_ctx);      
        libff::leave_block("Call to accumulate");
    }

    void compute(_struct_pp_* pp, 
    const libsnark::r1cs_gg_ppzksnark_keypair<libsnark::default_r1cs_gg_ppzksnark_pp> snark_key,
    libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> snark_ex, 
    libff::G1_vector<libff::alt_bn128_pp> &commit_base, vector<BIGNUM*> U, vector<BIGNUM*> u, _struct_proof_* proof,
     libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> &snark_proof) {
        libff::start_profiling();
        libff::enter_block("Call to compute (generate membership proof)");
        
        vector<int> rand_b; // b_i <- {0, 1}
        BIGNUM* bn_w_exp = BN_new();
        proof->W = BN_new();
        proof->k = BN_new();
        proof->C_x = BN_new();
        proof->C_y = BN_new();
        proof->h = BN_new();
        BIGNUM* bn_s = BN_new();
        BIGNUM* bn_r = BN_new();    
        BN_CTX* bn_ctx = BN_CTX_new();

        BN_copy(bn_w_exp, BN_value_one());

        BN_copy(bn_s, BN_value_one());
        // BN_copy(bn_r, BN_value_one());

        BIGNUM* bn_V = BN_new(); 
        BN_hex2bn(&bn_V, fmpz_get_str(NULL, 16, pp->V));

        // bn_u is for storing the multiplication of all u_i ~ u_j
        BIGNUM* bn_u = BN_new();
        BN_copy(bn_u, BN_value_one());

        for(int i = 0; i < u.size(); i++) {
            BN_mul(bn_u, bn_u, u[i], bn_ctx);
        }
        

        BN_copy(bn_w_exp, BN_value_one());
        srand(time(NULL));

        BIGNUM* bn_N = BN_new();
        BN_hex2bn(&bn_N, fmpz_get_str(NULL, 16, pp->N));

        // snark proof generation
        // libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> snark_proof = libsnark::r1cs_gg_ppzksnark_prover(snark_pk.pk, snark_ex.primary_input, snark_ex.auxiliary_input);
        snark_proof = libsnark::r1cs_gg_ppzksnark_prover(snark_key.pk, snark_ex.primary_input, snark_ex.auxiliary_input);
       
        // prod_{i=1}^n{{e_i}^{1-b_i}}
        for(int i = 0; i < U.size(); i++) {
            rand_b.push_back(rand()%2); // generate random bit vector
            if(rand_b.back() == 0) {
                BN_mul(bn_w_exp, bn_w_exp, pp->prime_e[i], bn_ctx);
            }
        }

        // \prod_{i = 1}^n {e_i} \prod_{u_j \in U-{u}} u_j
        for(auto x : U) {
            if (*find(u.begin(), u.end(), x) != x) {
                BN_mul(bn_w_exp, bn_w_exp, x, bn_ctx); 
            }        
        }
        
       // W <- V^bn_w_exp 
        BN_mod_exp(proof->W, bn_V, bn_w_exp, bn_N, bn_ctx);

        // s <- prod_{i=1}^n {e_i}^{b_i}
        int cnt = 0;
        for(int i = 0; i < pp->prime_e.size(); i++) {
            if(rand_b[i] == 1) {
                BN_mul(bn_s, bn_s, pp->prime_e[i], bn_ctx);
            }
        }    

        // len = BN_num_bits(u) + BN_num_bits(bn_s) + BN_num_bits(proof->h)
        int len = BN_num_bits(bn_u) + BN_num_bits(bn_s) + 256;
        BN_rand(bn_r, len , 1,  NULL); // r <- {0, 1}^len
        
        vector<string> bn_str_s, bn_str_r, bn_str_u;
        string str_tmp_s, str_tmp_r, str_tmp_u;
        str_tmp_s = BN_bn2hex(bn_s);
        str_tmp_r = BN_bn2hex(bn_r);
        str_tmp_u = BN_bn2hex(bn_u);
        size_t split_unit = 256;

        // split phase for s
        if(str_tmp_s.size() > split_unit) {
            int q_s = ceil(double(str_tmp_s.size()) / double(split_unit));
            int rem = str_tmp_s.size() % split_unit;

            for(int i = 0; i < q_s; i++) {  
                if((rem != 0) && (i == q_s-1)) {
                    bn_str_s.push_back(str_tmp_s.substr(i*split_unit, rem));
                }            
                bn_str_s.push_back(str_tmp_s.substr(i*split_unit, split_unit));
            }
        }
        else {
            bn_str_s.push_back(BN_bn2hex(bn_s));
        }

        // split phase for r 
        if(str_tmp_r.size() > split_unit) {
            int q_r = ceil(double(str_tmp_r.size()) / double(split_unit));
            int rem = str_tmp_r.size() % split_unit;

            for(int i = 0; i < q_r; i++) {                  
                if((rem != 0) && (i == (q_r - 1))) {
                    bn_str_r.push_back(str_tmp_r.substr(i*split_unit, rem));
                }
                else {
                    bn_str_r.push_back(str_tmp_r.substr(i*split_unit, split_unit));
                }
            }
        }
        else {
            bn_str_r.push_back(BN_bn2hex(bn_r));
        }

        // split phase for u
        if(str_tmp_u.size() > split_unit) {
            int q_u = ceil(double(str_tmp_u.size() / double(split_unit)));
            int rem = str_tmp_u.size() % split_unit;

            for(int i = 0; i < q_u; i++) {  
                if((rem != 0) && (i == q_u-1)) {
                    bn_str_u.push_back(str_tmp_u.substr(i*split_unit, rem));
                }
                bn_str_u.push_back(str_tmp_u.substr(i*split_unit, split_unit));
            }
        }
        else {
            bn_str_u.push_back(BN_bn2hex(bn_u));
        }
    
        // R <- W^r
        BIGNUM* bn_R = BN_new();
        BN_mod_exp(bn_R, proof->W, bn_r, bn_N, bn_ctx); 

        // com_val <- commitIO_crs(s, r, u) 
        libff::G1<libff::alt_bn128_pp> com_val; 

        membership_snark::membership_statement<libsnark::default_r1cs_gg_ppzksnark_pp> test(std::move(commit_base));
        test.commitIO_crs(bn_str_s, bn_str_r, bn_str_u, com_val);
        
        

        libff::bigint<4> bg_com_x = com_val.X.as_bigint();
        libff::bigint<4> bg_com_y = com_val.Y.as_bigint();
        char char_arr_x[1024] = "";
        char char_arr_y[1024] = "";

        gmp_sprintf(char_arr_x, "%Nd", bg_com_x.data, bg_com_x.N);
        gmp_sprintf(char_arr_y, "%Nd", bg_com_y.data, bg_com_y.N);

        

        BN_dec2bn(&proof->C_x, char_arr_x);
        BN_dec2bn(&proof->C_y, char_arr_y);

        // h <- H(W||C||R)
        Hash2(proof->h, proof->W, proof->C_x, proof->C_y, bn_R);
        
        // k <- r + u*s*h
        BIGNUM* bn_ush = BN_new();
        BN_copy(bn_ush, BN_value_one());
        BN_mul(bn_s, bn_s, proof->h, bn_ctx);   
        BN_mul(bn_ush, bn_u, bn_s, bn_ctx);
        BN_add(proof->k, bn_r, bn_ush);

        BN_CTX_free(bn_ctx);
        libff::leave_block("Call to compute (generate membership proof)");
    }

    void optCompute(_struct_pp_* pp, 
    const libsnark::r1cs_gg_ppzksnark_keypair<libsnark::default_r1cs_gg_ppzksnark_pp> snark_key,
    libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> snark_ex, 
    libff::G1_vector<libff::alt_bn128_pp> &commit_base, vector<BIGNUM*> U, vector<BIGNUM*> u, _struct_proof_* proof,
     libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> &snark_proof) {
        libff::start_profiling();
        libff::enter_block("Call to Optimized Compute (generate membership proof)");
        
        vector<int> rand_b; // b_i <- {0, 1}
        BIGNUM* bn_w_exp = BN_new();
        proof->W = BN_new();
        proof->k = BN_new();
        proof->C_x = BN_new();
        proof->C_y = BN_new();
        proof->h = BN_new();
        BIGNUM* bn_s = BN_new();
        BIGNUM* bn_r = BN_new();    
        BN_CTX* bn_ctx = BN_CTX_new();

        BN_copy(bn_w_exp, BN_value_one());

        BN_copy(bn_s, BN_value_one());
        // BN_copy(bn_r, BN_value_one());

        BIGNUM* bn_V = BN_new(); 
        BN_hex2bn(&bn_V, fmpz_get_str(NULL, 16, pp->V));

        // bn_u is for storing the multiplication of all u_i ~ u_j
        BIGNUM* bn_u = BN_new();
        BN_copy(bn_u, BN_value_one());

        for(int i = 0; i < u.size(); i++) {
            BN_mul(bn_u, bn_u, u[i], bn_ctx);
        }

        BN_copy(bn_w_exp, BN_value_one());
        srand(time(NULL));

        BIGNUM* bn_N = BN_new();
        BN_hex2bn(&bn_N, fmpz_get_str(NULL, 16, pp->N));

        // snark proof generation
        // libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> snark_proof = libsnark::r1cs_gg_ppzksnark_prover(snark_pk.pk, snark_ex.primary_input, snark_ex.auxiliary_input);
        snark_proof = libsnark::r1cs_gg_ppzksnark_prover(snark_key.pk, snark_ex.primary_input, snark_ex.auxiliary_input);
       
        

        // prod_{i=1}^n{{e_i}^{1-b_i}}
        for(int i = 0; i < U.size(); i++) {
            rand_b.push_back(rand()%2); // generate random bit vector
            if(rand_b.back() == 0) {
                BN_mul(bn_w_exp, bn_w_exp, pp->prime_e[i], bn_ctx);
            }
        }

        // \prod_{i = 1}^n {e_i} \prod_{u_j \in U-{u}} u_j
        for(auto x : U) {
            if (*find(u.begin(), u.end(), x) != x) {
                BN_mul(bn_w_exp, bn_w_exp, x, bn_ctx); 
            }        
        }

        // W <- V^bn_w_exp 
        BN_mod_exp(proof->W, bn_V, bn_w_exp, bn_N, bn_ctx);

        // l <- H_1(V||W), l is the prime
        proof->l = BN_new();
        Hash3(proof->l, bn_V, proof->W);

        // s <- prod_{i=1}^n {e_i}^{b_i}
        int cnt = 0;
        for(int i = 0; i < pp->prime_e.size(); i++) {
            if(rand_b[i] == 1) {
                BN_mul(bn_s, bn_s, pp->prime_e[i], bn_ctx);
            }
        }    

        // len = BN_num_bits(u) + BN_num_bits(bn_s) + BN_num_bits(proof->h)
        int len = BN_num_bits(bn_u) + BN_num_bits(bn_s) + 256;
        BN_rand(bn_r, len , 1,  NULL); // r <- {0, 1}^len
        
        vector<string> bn_str_s, bn_str_r, bn_str_u;
        string str_tmp_s, str_tmp_r, str_tmp_u;
        str_tmp_s = BN_bn2hex(bn_s);
        str_tmp_r = BN_bn2hex(bn_r);
        str_tmp_u = BN_bn2hex(bn_u);
        size_t split_unit = 256;

        // split phase for s
        if(str_tmp_s.size() > split_unit) {
            int q_s = ceil(double(str_tmp_s.size()) / double(split_unit));
            int rem = str_tmp_s.size() % split_unit;

            for(int i = 0; i < q_s; i++) {  
                if((rem != 0) && (i == q_s-1)) {
                    bn_str_s.push_back(str_tmp_s.substr(i*split_unit, rem));
                }            
                bn_str_s.push_back(str_tmp_s.substr(i*split_unit, split_unit));
            }
        }
        else {
            bn_str_s.push_back(BN_bn2hex(bn_s));
        }

        // split phase for r 
        if(str_tmp_r.size() > split_unit) {
            int q_r = ceil(double(str_tmp_r.size()) / double(split_unit));
            int rem = str_tmp_r.size() % split_unit;

            for(int i = 0; i < q_r; i++) {                  
                if((rem != 0) && (i == (q_r - 1))) {
                    bn_str_r.push_back(str_tmp_r.substr(i*split_unit, rem));
                }
                else {
                    bn_str_r.push_back(str_tmp_r.substr(i*split_unit, split_unit));
                }
            }
        }
        else {
            bn_str_r.push_back(BN_bn2hex(bn_r));
        }

        // split phase for u
        if(str_tmp_u.size() > split_unit) {
            int q_u = ceil(double(str_tmp_u.size() / double(split_unit)));
            int rem = str_tmp_u.size() % split_unit;

            for(int i = 0; i < q_u; i++) {  
                if((rem != 0) && (i == q_u-1)) {
                    bn_str_u.push_back(str_tmp_u.substr(i*split_unit, rem));
                }
                bn_str_u.push_back(str_tmp_u.substr(i*split_unit, split_unit));
            }
        }
        else {
            bn_str_u.push_back(BN_bn2hex(bn_u));
        }

        // R <- W^r
        BIGNUM* bn_R = BN_new();
        BN_mod_exp(bn_R, proof->W, bn_r, bn_N, bn_ctx); 

        // com_val <- commitIO_crs(s, r, u) 
        libff::G1<libff::alt_bn128_pp> com_val; 

        membership_snark::membership_statement<libsnark::default_r1cs_gg_ppzksnark_pp> test(std::move(commit_base));
        test.commitIO_crs(bn_str_s, bn_str_r, bn_str_u, com_val);
        
        libff::bigint<4> bg_com_x = com_val.X.as_bigint();
        libff::bigint<4> bg_com_y = com_val.Y.as_bigint();
        char char_arr_x[1024] = "";
        char char_arr_y[1024] = "";

        gmp_sprintf(char_arr_x, "%Nd", bg_com_x.data, bg_com_x.N);
        gmp_sprintf(char_arr_y, "%Nd", bg_com_y.data, bg_com_y.N);

        

        BN_dec2bn(&proof->C_x, char_arr_x);
        BN_dec2bn(&proof->C_y, char_arr_y);

        // h <- H(W||C||R)
        Hash2(proof->h, proof->W, proof->C_x, proof->C_y, bn_R);
        
        // k <- r + u*s*h
        BIGNUM* bn_ush = BN_new();
        BN_copy(bn_ush, BN_value_one());
        BN_mul(bn_s, bn_s, proof->h, bn_ctx);   
        BN_mul(bn_ush, bn_u, bn_s, bn_ctx);
        BN_add(proof->k, bn_r, bn_ush);


        
        // k' <- k mod l 
        proof->opt_k = BN_new();
        BN_nnmod(proof->opt_k, proof->k, proof->l, bn_ctx);


        BIGNUM* bn_test = BN_new();
        // Q <- W^(k/l)
        proof->Q = BN_new();
        BIGNUM* bn_n_one = BN_new();
        BIGNUM* bn_tmp_exp = BN_new();
        BIGNUM* bn_exp_ret = BN_new();

        // BN_exp(bn_tmp_exp, bn_l, bn_n_one, bn_ctx); // l^{-1}
        // BN_mul(bn_test, bn_tmp_exp, bn_l, bn_ctx);
        BN_div(bn_exp_ret, NULL, proof->k, proof->l, bn_ctx);

        // BN_mul(bn_exp_ret, proof->k, bn_tmp_exp, bn_ctx); // k* {l^{-1}}, which is k/l
        
        
        
        BN_mod_exp(proof->Q, proof->W, bn_exp_ret, bn_N, bn_ctx);

        BN_CTX_free(bn_ctx);
        libff::leave_block("Call to Optimized compute (generate membership proof)");
    }

    void verify(_struct_pp_* pp, libsnark::r1cs_gg_ppzksnark_verification_key<libsnark::default_r1cs_gg_ppzksnark_pp> snark_vk, 
    libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> snark_ex, BIGNUM* &ACC, vector<BIGNUM*> U,
     _struct_proof_* proof, libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> snark_proof) {
        libff::start_profiling();
        libff::enter_block("Call to verification");
        BIGNUM* tmp = BN_new();
        BN_CTX* bn_ctx = BN_CTX_new();
        BIGNUM* bn_denom = BN_new(); //for storing ACC^h 
        BIGNUM* bn_num = BN_new(); // for storing W^k
        BIGNUM* bn_ret = BN_new();

        BN_copy(bn_denom, BN_value_one());
        BN_copy(bn_num, BN_value_one());
        BN_copy(bn_ret, BN_value_one());
        
        // SNARK Verification
        bool snark_verify = libsnark::r1cs_gg_ppzksnark_verifier_weak_IC(snark_vk, snark_ex.primary_input, snark_proof);
      /*
        print_point("Snark verification test");
        if(snark_verify) {
            cout << "Snark Verification Pass" << endl << endl; 
        }
        else {
            cout << "Snark Verification Fail" << endl << endl;
        }
    */
        BIGNUM* bn_N = BN_new();
        BN_hex2bn(&bn_N, fmpz_get_str(NULL, 16, pp->N));
        
        BN_mod_exp(bn_denom, ACC, proof->h, bn_N, bn_ctx); // bn_denom <- ACC^h
        BN_mod_exp(bn_num, proof->W, proof->k, bn_N, bn_ctx); // bn_num <- W^k
        
        BN_mod_inverse(bn_denom, bn_denom, bn_N, bn_ctx); // bn_denom <- ACC^{-h}
        BN_mod_mul(bn_ret, bn_num, bn_denom, bn_N, bn_ctx); // bn_ret <- W^k * ACC^{-h}

        // print_BN(bn_ret, "Check W^k / ACC^h");

        // H(W || C || ACC^h/W^k)
        Hash2(tmp, proof->W, proof->C_x, proof->C_y, bn_ret); 

        // print_BN(proof->h, "Check the hash value in compute phase");
        // print_BN(tmp, "Check the hash value in verification phase");

        if((!BN_cmp(proof->h, tmp)) && snark_verify) {
            cout << "Verification Pass" << endl;
        }
        else {
            cout << "Verification Fail" << endl;
        }

        BN_CTX_free(bn_ctx);
        libff::leave_block("Call to verification");
    }

    void optVerify(_struct_pp_* pp, libsnark::r1cs_gg_ppzksnark_verification_key<libsnark::default_r1cs_gg_ppzksnark_pp> snark_vk, 
    libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> snark_ex, BIGNUM* &ACC, vector<BIGNUM*> U,
     _struct_proof_* proof, libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> snark_proof) {
        libff::start_profiling();
        libff::enter_block("Call to Optimized verification");
        BIGNUM* tmp = BN_new();
        BN_CTX* bn_ctx = BN_CTX_new();
        BIGNUM* bn_denom = BN_new(); //for storing ACC^h 
        BIGNUM* bn_num_1 = BN_new(); // for storing Q^l
        BIGNUM* bn_num_2 = BN_new(); // for storing W^k' 
        BIGNUM* bn_num = BN_new(); // for storing Q^l * W^k'
        BIGNUM* bn_ret = BN_new();

        BN_copy(bn_denom, BN_value_one());
        BN_copy(bn_num_1, BN_value_one());
        BN_copy(bn_num_2, BN_value_one());
        BN_copy(bn_ret, BN_value_one());
        
        // SNARK Verification
        bool snark_verify = libsnark::r1cs_gg_ppzksnark_verifier_weak_IC(snark_vk, snark_ex.primary_input, snark_proof);
      /*
        print_point("Snark verification test");
        if(snark_verify) {
            cout << "Snark Verification Pass" << endl << endl; 
        }
        else {
            cout << "Snark Verification Fail" << endl << endl;
        }
    */
        BIGNUM* bn_N = BN_new();
        BN_hex2bn(&bn_N, fmpz_get_str(NULL, 16, pp->N));
        
        BN_mod_exp(bn_denom, ACC, proof->h, bn_N, bn_ctx); // bn_denom <- ACC^h
        BN_mod_exp(bn_num_1, proof->Q, proof->l, bn_N, bn_ctx); // bn_num_1 <- Q^l
        BN_mod_exp(bn_num_2, proof->W, proof->opt_k, bn_N, bn_ctx); // bn_num_2 <- W^k'
        BN_mod_mul(bn_num, bn_num_1, bn_num_2, bn_N, bn_ctx); // bn_num <- Q^l * W^k'

        
        BN_mod_inverse(bn_denom, bn_denom, bn_N, bn_ctx); // bn_denom <- ACC^{-h}
        BN_mod_mul(bn_ret, bn_num, bn_denom, bn_N, bn_ctx); // bn_ret <- Q^l * W^k' * ACC^{-h}

        // print_BN(bn_ret, "Check W^k / ACC^h");

        // H(W || C || Q^l * W^k' * ACC^{-h})
        Hash2(tmp, proof->W, proof->C_x, proof->C_y, bn_ret); 

        // print_BN(proof->h, "Check the hash value in compute phase");
        // print_BN(tmp, "Check the hash value in verification phase");

        if((!BN_cmp(proof->h, tmp)) && snark_verify) {
            cout << "Verification Pass" << endl;
        }
        else {
            cout << "Verification Fail" << endl;
        }

        BN_CTX_free(bn_ctx);
        libff::leave_block("Call to Optimized verification");
    }
}

   