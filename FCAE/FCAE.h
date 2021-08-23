//
// Created by GaoYun on 2021/5/22.
//

#ifndef AUTH_ALL_FCAE_H
#define AUTH_ALL_FCAE_H

#include <string>
#include "FCAE_BASE.h"

#define PARAM_FILE_NAME "ec.param"

void pbc_pairing_init_file(pairing_t pairing, char *filename);

class FCAE {
private:
    pairing_t pairing;
    element_t g, Ppub;
    element_t h;
    element_t sk_x, X_pri_acc;
    PRIVATE *pri_key;
public:
    PID *pid;

    FCAE();

    ~FCAE();

    void user_key_gen(element_t kgc_g, element_t kgc_Ppub, element_t &kgc_h, element_t &kgc_pk, element_t &kgc_sk);

    P proof_gen(PID &pid_k);

    bool verify(const P &p, const PID &pid_i);

    void cipher_gen(const PID &pid_j, element_t &X_bar, std::string &k1k2) const;

    void encode(const std::string &k1, const std::string &M, std::string &cipher_text) const;

    bool decode(const PID &pid_i, const element_t &X_bar, const std::string &cipher_text, std::string &k1k2,
                std::string &M) const;

    element_ptr get_id() const;

private:
    /// statistic member
    double key_gen_time;
};

#endif //AUTH_ALL_FCAE_H
