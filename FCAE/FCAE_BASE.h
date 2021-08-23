//
// Created by GaoYun on 2021/5/26.
//

#ifndef AUTH_ALL_FCAE_BASE_H
#define AUTH_ALL_FCAE_BASE_H

#include "pbc.h"
#include <string>

unsigned char * H1(const element_t a, const element_t b, unsigned int &ret_len);

struct PID {
    element_t pk, X, id;

    explicit PID(pairing_t pairing);

    PID(pairing_t pairing, const std::string &raw);


    PID(const PID &other);

    PID &operator=(const PID &other);

    ~PID();

    std::string to_String() const;

    int length() const;

    bool operator==(const PID &other) const;

    bool operator!=(const PID &other) const;


};

unsigned char * H2(const PID &a, const PID &b, unsigned int &ret_len);

struct PRIVATE {
    element_t sk, x;

    explicit PRIVATE(pairing_t pairing);

    PRIVATE(const PRIVATE &other);

    PRIVATE &operator=(const PRIVATE &other);

    ~PRIVATE();

    std::string to_String() const;

    int length() const;

};

struct P {
    element_t X_pri, R, R_bar;

    explicit P(pairing_t pairing);

    P(pairing_t pairing, const std::string &raw);


    P(const P &other);

    P &operator=(const P &other);

    ~P();

    std::string to_String() const;

    int length() const;

};

unsigned char * KDF(const element_t &ps_ij, const element_t &X_bar, const PID &pid, unsigned int &ret_len);

#endif //AUTH_ALL_FCAE_BASE_H
