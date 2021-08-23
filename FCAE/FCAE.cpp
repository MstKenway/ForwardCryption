//
// Created by GaoYun on 2021/5/22.
//

#include "FCAE.h"
#include <chrono>
#include <iostream>
#include <cstring>
#include <Utils.h>

using namespace std;
using namespace chrono;


/// \brief generate public key for user
/// \param kgc_g g from kgc
/// \param kgc_Ppub Ppub from kgc
/// \param kgc_pk pk from kgc
/// \param kgc_sk sk from kgc
void FCAE::user_key_gen(element_t kgc_g, element_t kgc_Ppub, element_t &kgc_h, element_t &kgc_pk, element_t &kgc_sk) {
    ///copy g and Ppub
    element_set(g, kgc_g);
    element_set(Ppub, kgc_Ppub);
    element_set(h, kgc_h);
    element_set(pid->pk, kgc_pk);
    element_set(pri_key->sk, kgc_sk);

    steady_clock::time_point begintime, endtime;
    std::cout << "UE get key from KGC...";
    ///init temp element

    begintime = steady_clock::now();


    element_random(pri_key->x);
    element_pow_zn(pid->X, g, pri_key->x);

    /// compute some const member to accelerate
    element_add(sk_x, pri_key->sk, pri_key->x);

    element_pow_zn(X_pri_acc, Ppub, h);
    element_mul(X_pri_acc, X_pri_acc, pid->pk);


    endtime = steady_clock::now();
    key_gen_time = duration<double, milli>(endtime - begintime).count();
}

element_ptr FCAE::get_id() const {
    return pid->id;
}

FCAE::FCAE() {
    pbc_pairing_init_file(pairing, (char *)PARAM_FILE_NAME);
    pid = new PID(pairing);
    pri_key = new PRIVATE(pairing);
    element_random(pid->id);
    element_init_G1(g, pairing);
    element_init_G1(Ppub, pairing);
    element_init_G1(X_pri_acc, pairing);
    element_init_Zr(h, pairing);
    element_init_Zr(sk_x, pairing);

}

FCAE::~FCAE() {
    element_clear(g);
    element_clear(Ppub);
    element_clear(X_pri_acc);
    element_clear(h);
    element_clear(sk_x);
    delete pid;
    delete pri_key;
    pairing_clear(pairing);
}

P FCAE::proof_gen(PID &pid_k) {
    P ret(pairing);
    element_t r, r_bar;
    element_t d;
    element_t hk;
    element_t temp_var;

    element_init_Zr(r, pairing);
    element_init_Zr(r_bar, pairing);
    element_init_Zr(d, pairing);
    element_init_Zr(hk, pairing);
    element_init_G1(temp_var, pairing);

    element_random(r);
    /// compute d
    unsigned int hash_len;
    unsigned char *d_hash = H2(*pid, pid_k, hash_len);
    element_from_hash(d, (void *) d_hash, (int) hash_len);
    /// compute r_bar
    element_mul(r_bar, d, pri_key->x);
    element_add(r_bar, r_bar, pri_key->sk);
    element_sub(r_bar, r_bar, r);

    /// compute R
    unsigned char *hk_hash_raw = H1(pid_k.pk, pid_k.id, hash_len);
    element_from_hash(hk, (void *) hk_hash_raw, (int) hash_len);
    element_pow_zn(ret.R, Ppub, hk);
    element_mul(ret.R, ret.R, pid_k.pk);
    /// raw formula without X^d
    element_mul(ret.R, ret.R, pid_k.X);
    /// revised into X^d
//    element_pow_zn(temp_var, pid_k.X, d);
//    element_mul(ret.R, ret.R, temp_var);
    element_pow_zn(ret.R, ret.R, r);

    /// compute R_bar
    element_pow_zn(ret.R_bar, g, r_bar);

    /// compute X_pri
    element_pow_zn(temp_var, pid->X, d);
    element_mul(ret.X_pri, X_pri_acc, temp_var);

    end:
    element_clear(temp_var);
    element_clear(hk);
    element_clear(d);
    element_clear(r_bar);
    element_clear(r);
    /// free hash result
    delete[] d_hash;
    delete[] hk_hash_raw;
    return ret;
}

/// \brief verify P
bool FCAE::verify(const P &p, const PID &pid_i) {
    /// cast away "const", in the following code, substitute p_ for p
    P &p_ = const_cast<P &> (p);
    PID &pid_i_ = const_cast<PID &>(pid_i);

    element_t verf_i, verf_i_pri;
    element_t d, order;
    bool ret = false;

    element_init_G1(verf_i, pairing);
    element_init_G1(verf_i_pri, pairing);
    element_init_Zr(d, pairing);
//    element_init_Zr(order, pairing);

    /// compute d
    unsigned int hash_len;
    unsigned char *d_raw = H2(pid_i, *pid, hash_len);
    //reinterpret_cast<void *>(const_cast<char *>())=void *
    element_from_hash(d, d_raw, (int) hash_len);

    /// compute order
//    element_mul(order, d, pri_key->x);
//    element_add(order, order, pri_key->sk);
//    element_add(order, pri_key->sk, pri_key->x);
    /// compute verf_i
    element_pow_zn(verf_i, p_.R_bar, sk_x);
    element_mul(verf_i, p_.R, verf_i);


    /// todo:save order sk_x as constant, improve the performance
    /// compute verf_i_bar
    element_pow_zn(verf_i_pri, p_.X_pri, sk_x);

    /// get return value
    ret = element_cmp(verf_i, verf_i_pri) == 0 ? true : false;

//    element_printf("verf_i:%B\n", verf_i);
//    element_printf("verf_i_pri:%B\n", verf_i_pri);
    end:
    element_clear(verf_i);
    element_clear(verf_i_pri);
    element_clear(d);
//    element_clear(order);
    /// free hash result
    delete[] d_raw;
    return ret;
}

void FCAE::cipher_gen(const PID &pid_j, element_t &X_bar, std::string &k1k2) const {
    /// cast away
    FCAE *this_ = const_cast<FCAE *>(this);

    element_t e, x_e, ps_ij, ps_order, h_j;// todo:pre-compute h_j

    element_init_Zr(e, this_->pairing);
    element_init_Zr(ps_order, this_->pairing);
    element_init_Zr(h_j, this_->pairing);
    element_init_G1(ps_ij, this_->pairing);
    element_init_G1(x_e, this_->pairing);

    /// compute e
    unsigned int hash_len;
    unsigned char *e_raw = H2(*pid, pid_j, hash_len);
    element_from_hash(e, (void *) e_raw, (int) hash_len);

    /// compute X_bar
    element_pow_zn(x_e, pid->X, e);
    element_pow_zn(X_bar, this_->Ppub, this_->h);
    element_mul(X_bar, X_bar, pid->pk);
    element_mul(X_bar, X_bar, x_e);

    /// compute h_j
    unsigned char *h_j_raw = H1(pid_j.pk, pid_j.id, hash_len);
    element_from_hash(h_j, (void *) h_j_raw, (int) hash_len);

    /// compute ps_order
    element_mul(ps_order, pri_key->x, e);
    element_add(ps_order, ps_order, pri_key->sk);

    /// compute ps_ij
    element_pow_zn(ps_ij, this_->Ppub, h_j);
    element_mul(ps_ij, ps_ij, const_cast<element_t &>(pid_j.pk));
    element_pow_zn(ps_ij, ps_ij, ps_order);

    unsigned char *key = KDF(ps_ij, X_bar, pid_j, hash_len);
    k1k2 = string((char *) key, hash_len);

    end:
    element_clear(e);
    element_clear(ps_ij);
    element_clear(ps_order);
    element_clear(x_e);
    element_clear(h_j);
    /// free hash result
    delete[] e_raw;
    delete[] h_j_raw;
    delete[] key;
}

bool FCAE::decode(const PID &pid_i, const element_t &X_bar, const string &cipher_text, string &k1k2, string &M) const {
    FCAE *this_ = const_cast<FCAE *>(this);

    /// temporary variable
    element_t ps_ij;
    bool ret = false;

    element_init_G1(ps_ij, this_->pairing);

    /// compute ps_ij
    unsigned int hash_len;
    element_pow_zn(ps_ij, const_cast<element_t &>(X_bar), pri_key->sk);

    unsigned char *key = KDF((ps_ij), X_bar, *(this_->pid), hash_len);
    k1k2 = string((char *) key, hash_len);

    /// decrypt and verify
    const char *iv = cipher_text.c_str(), *p = iv + IV_LEN;
    const char *k1 = k1k2.c_str();
    int c_len = cipher_text.length() - IV_LEN, k1_len = k1k2.length() / 2;
    string plain_text;
    bool r = DecryptString(string(p, c_len), string(k1, k1_len), string(iv, IV_LEN), plain_text);
    if (!r) {
        ret = false;
    } else {
        PID pid_i_temp(this_->pairing, plain_text.substr(0, pid_i.length()));
        if (pid_i != pid_i_temp) {
            ret = false;
        } else {
            ret = true;
            M = plain_text.substr(pid_i.length());
        }
    }
    end:
    element_clear(ps_ij);
    /// free hash result
    delete[] key;
    return ret;
}

void FCAE::encode(const string &k1, const string &M, string &cipher_text) const {
    FCAE *p = const_cast<FCAE *>(this);

    string iv = get_rand_num(IV_LEN);
    string temp = EncryptString(p->pid->to_String() + M, k1, iv);
    cipher_text = iv + temp;
}

void pbc_pairing_init_file(pairing_t pairing, char *filename) {
    char s[16384];
    FILE *fp;
    unsigned int count;
    fp = fopen(filename, "r");
    if (!fp) {
        printf("error opening %s", filename);
        exit(1);
    }
    count = fread(s, 1, 16384, fp);
    if (!count) {
        printf("input error");
    }
    fclose(fp);
    pairing_init_set_buf(pairing, s, count);
}