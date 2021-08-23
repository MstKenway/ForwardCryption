//
// Created by GaoYun on 2021/5/26.
//

#include "FCAE_BASE.h"
#include "Utils.h"

using namespace std;

PID::PID(pairing_t pairing) {
    element_init_Zr(id, pairing);
    element_init_G1(pk, pairing);
    element_init_G1(X, pairing);
}

/// \brief Construct a PID though string/bytes, and the order is pk|X|id
PID::PID(pairing_s *pairing, const string &raw) {
    element_init_Zr(id, pairing);
    element_init_G1(pk, pairing);
    element_init_G1(X, pairing);
    int pk_len = element_length_in_bytes(pk), X_len = element_length_in_bytes(X);
    const char *p = raw.c_str();
    element_from_bytes(pk, (unsigned char *) p);
    element_from_bytes(X, (unsigned char *) p + pk_len);
    element_from_bytes(id, (unsigned char *) p + pk_len + X_len);
}


PID::~PID() {
    element_clear(id);
    element_clear(pk);
    element_clear(X);
}

PID::PID(const PID &other) {
    element_init_same_as(pk, const_cast<element_ptr>( other.pk));
    element_init_same_as(X, const_cast<element_ptr>(other.X));
    element_init_same_as(id, const_cast<element_ptr>(other.id));
    *this = other;
}

PID &PID::operator=(const PID &other) {
    if (&other != this) {
        element_set(pk, const_cast<element_ptr>( other.pk));
        element_set(X, const_cast<element_ptr>(other.X));
        element_set(id, const_cast<element_ptr>(other.id));
    }
    return *this;
}


string PID::to_String() const {
    int pk_len = element_length_in_bytes(const_cast<element_t &>(pk)),
            X_len = element_length_in_bytes(const_cast<element_t &>(X)),
            id_len = element_length_in_bytes(const_cast<element_t &>(id));
    int len = pk_len + X_len + id_len;

    unsigned char temp[len];
    element_to_bytes(temp, const_cast<element_t &>(pk));
    element_to_bytes(temp + pk_len, const_cast<element_t &>(X));
    element_to_bytes(temp + pk_len + X_len, const_cast<element_t &>(id));
    return string((char *) temp, len);
}

int PID::length() const {
    int pk_len = element_length_in_bytes(const_cast<element_t &>(pk)),
            X_len = element_length_in_bytes(const_cast<element_t &>(X)),
            id_len = element_length_in_bytes(const_cast<element_t &>(id));
    return pk_len + X_len + id_len;
}

bool PID::operator==(const PID &other) const {
    PID *p = const_cast<PID *>(this);
    PID *o = const_cast<PID *>(&other);
    if (element_cmp(p->pk, o->pk) != 0)return false;
    if (element_cmp(p->X, o->X) != 0)return false;
    if (element_cmp(p->id, o->id) != 0)return false;
    return true;
}

bool PID::operator!=(const PID &other) const {
    return !(*this == other);
}


unsigned char *H1(const element_t a, const element_t b, unsigned int &ret_len) {
    int a_len = element_length_in_bytes(const_cast<element_ptr>(a)),
            b_len = element_length_in_bytes(const_cast<element_ptr>(b));
    unsigned char h_temp[a_len + b_len];
    element_to_bytes(h_temp, const_cast<element_ptr>(a));
    element_to_bytes(h_temp + a_len, const_cast<element_ptr>(b));
    return get_hash(h_temp, a_len + b_len, ret_len);
}


unsigned char *H2(const PID &a, const PID &b, unsigned int &ret_len) {
    string d_temp = a.to_String() + b.to_String();
    return get_hash(reinterpret_cast<const unsigned char *>(d_temp.c_str()), d_temp.length(), ret_len);
}

unsigned char * KDF(const element_t &ps_ij, const element_t &X_bar, const PID &pid, unsigned int &ret_len) {
    element_t &ps = const_cast<element_t &>(ps_ij), &X = const_cast<element_t &>(X_bar);
    int ps_len = element_length_in_bytes(ps), X_len = element_length_in_bytes(X);
    unsigned char buf[ps_len + X_len];
    element_to_bytes(buf, ps);
    element_to_bytes(buf + ps_len, X);
    string temp((char *) buf, ps_len + X_len);
    temp += pid.to_String();
    return get_hash((unsigned char *) temp.c_str(), temp.length(), ret_len);
}

PRIVATE::PRIVATE(pairing_t pairing) {
    element_init_Zr(x, pairing);
    element_init_Zr(sk, pairing);
}

PRIVATE::~PRIVATE() {
    element_clear(x);
    element_clear(sk);
}

PRIVATE::PRIVATE(const PRIVATE &other) {
    element_init_same_as(sk, const_cast<element_ptr>( other.sk));
    element_init_same_as(x, const_cast<element_ptr>(other.x));
    *this = other;
}

PRIVATE &PRIVATE::operator=(const PRIVATE &other) {
    if (&other != this) {
        element_set(sk, const_cast<element_ptr>( other.sk));
        element_set(x, const_cast<element_ptr>(other.x));
    }
    return *this;
}

std::string PRIVATE::to_String() const {
    PRIVATE *p = const_cast<PRIVATE *>(this);
    int sk_len = element_length_in_bytes(p->sk), x_len = element_length_in_bytes(p->x);
    int len = sk_len + x_len;
    unsigned char temp[len];
    element_to_bytes(temp, p->sk);
    element_to_bytes(temp + sk_len, p->x);
    return string((char *) temp, len);
}

int PRIVATE::length() const {
    auto *p = const_cast<PRIVATE *>(this);
    int sk_len = element_length_in_bytes(p->sk), x_len = element_length_in_bytes(p->x);
    return sk_len + x_len;
}

P::P(pairing_s *pairing) {
    element_init_G1(X_pri, pairing);
    element_init_G1(R, pairing);
    element_init_G1(R_bar, pairing);
}


/// \brief Construct a P though string/bytes, and the order is X_pri|R|R_bar
P::P(pairing_s *pairing, const string &raw) {
    element_init_G1(X_pri, pairing);
    element_init_G1(R, pairing);
    element_init_G1(R_bar, pairing);
    int pk_len = element_length_in_bytes(X_pri), X_len = element_length_in_bytes(R);
    const char *p = raw.c_str();
    element_from_bytes(X_pri, (unsigned char *) p);
    element_from_bytes(R, (unsigned char *) p + pk_len);
    element_from_bytes(R_bar, (unsigned char *) p + pk_len + X_len);
}

P::~P() {
    element_clear(X_pri);
    element_clear(R);
    element_clear(R_bar);
}

P::P(const P &other) {
    element_init_same_as(X_pri, const_cast<element_ptr>( other.X_pri));
    element_init_same_as(R, const_cast<element_ptr>(other.R));
    element_init_same_as(R_bar, const_cast<element_ptr>(other.R_bar));
    *this = other;
}

P &P::operator=(const P &other) {
    if (&other != this) {
        element_set(X_pri, const_cast<element_ptr>( other.X_pri));
        element_set(R, const_cast<element_ptr>(other.R));
        element_set(R_bar, const_cast<element_ptr>(other.R_bar));
    }
    return *this;
}

std::string P::to_String() const {
    P *p = const_cast<P *>(this);
    int X_bar_len = element_length_in_bytes(const_cast<element_t &>(X_pri)),
            R_len = element_length_in_bytes(const_cast<element_t &>(R)),
            R_bar_len = element_length_in_bytes(const_cast<element_t &>(R_bar));
    int len = X_bar_len + R_len + R_bar_len;
    unsigned char temp[len];
    element_to_bytes(temp, p->X_pri);
    element_to_bytes(temp + X_bar_len, p->R);
    element_to_bytes(temp + X_bar_len + R_len, p->R_bar);
    return string((char *) temp, len);
}

int P::length() const {
    int X_bar_len = element_length_in_bytes(const_cast<element_t &>(X_pri)),
            R_len = element_length_in_bytes(const_cast<element_t &>(R)),
            R_bar_len = element_length_in_bytes(const_cast<element_t &>(R_bar));
    return X_bar_len + R_len + R_bar_len;
}


