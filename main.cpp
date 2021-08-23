
#include <ctime>
#include <cstring>
#include <iostream>
#include <string>
#include <chrono>

#include "Utils/Utils.h"

#include "KGC/KGC.h"
#include "FCAE/FCAE.h"

#define TEST_TIMES 1000


using namespace std;
using namespace chrono;


void test_rand_num() {
    string test = get_rand_num(128);
    cout << test << endl;
    cout << test.length() << endl;
    const char *p = test.c_str();
    for (int i = 0; i < test.length(); ++i) {
        printf("%02x", (unsigned char) p[i]);
        if ((i + 1) % 8 == 0)
            printf("\n");
    }
}

void test_en_de_crypt() {
    const char *input = "This is a test";
    string key = get_rand_num(128);
    string iv = get_rand_num(IV_LEN);
    string enstr = EncryptString(string(input), key, iv);
    cout << "cipher text :\t" << enstr << endl;
    string destr;
    bool res = DecryptString(enstr, key, iv, destr);
    if (res)
        cout << "plain text :\t" << destr << endl;
    else
        cout << "fail in decryption" << endl;

    enstr[0] = 1;
    res = DecryptString(enstr, key, iv, destr);
    if (res)
        cout << "plain text :\t" << destr << endl;
    else
        cout << "fail in decryption" << endl;
}

int main() {
    system_clock::time_point begin_time, end_time, t1, t2, t3;
    double auth_total_time = 0, proofgen_total_time = 0, verify_total_time = 0;

    pairing_t pairing;
    pbc_pairing_init_file(pairing, PARAM_FILE_NAME);


    KGC kgc;
    element_ptr g, Ppub;
    g = kgc.get_g();
    Ppub = kgc.get_Ppub();

    string plain_text, cipher_text, message = "Hello world!\n", key;

    FCAE i, j, k;
    element_t pk, sk, h, X_bar;
    element_init_G1(pk, pairing);
    element_init_G1(X_bar, pairing);
    element_init_Zr(sk, pairing);
    element_init_Zr(h, pairing);

    /// register
    kgc.user_key_gen(i.get_id(), pk, sk, h);
    i.user_key_gen(g, Ppub, h, pk, sk);

    kgc.user_key_gen(k.get_id(), pk, sk, h);
    k.user_key_gen(g, Ppub, h, pk, sk);

    kgc.user_key_gen(j.get_id(), pk, sk, h);
    j.user_key_gen(g, Ppub, h, pk, sk);

    /// i generate
    P p_ik = i.proof_gen(*k.pid);
    i.cipher_gen(*j.pid, X_bar, key);
    i.encode(key.substr(0, key.length() / 2), message, cipher_text);

    /// k receive and verify
    bool r = k.verify(p_ik, *i.pid);
    P p_kj = k.proof_gen(*j.pid);
    if (r) {
        cout << "k verify i success." << endl;
    } else {
        cout << "k verify i FAIL!!!!" << endl;
        exit(0);
    }

    /// j receive ,verify and decode
    r = j.verify(p_kj, *k.pid);
    if (r) {
        cout << "j verify k success." << endl;
    } else {
        cout << "j verify k FAIL!!!!" << endl;
        exit(0);
    }
    /// decode and print message
    r = j.decode(*i.pid, X_bar, cipher_text, key, plain_text);
    if (r) {
        cout << "j decode message success." << endl;
        cout << "Message is :\t" << plain_text << endl;
    } else {
        cout << "j decode message FAIL!!!!" << endl;
        exit(0);
    }

    begin_time = system_clock::now();
    for (int count = 0; count < TEST_TIMES; ++count) {
        t1 = system_clock::now();
        /// i generate
        p_ik = i.proof_gen(*k.pid);
        t2 = system_clock::now();

        /// k receive and verify
        r = k.verify(p_ik, *i.pid);
        t3 = system_clock::now();

        if (r) {
//            p_kj = k.proof_gen(*j.pid);
        } else {
            cout << "Count : " << count << "\tk verify i FAIL!!!!" << endl;
        }
        proofgen_total_time += duration<double, milli>(t2 - t1).count();
        verify_total_time += duration<double, milli>(t3 - t2).count();
    }
    end_time = system_clock::now();
    auth_total_time = duration<double, milli>(end_time - begin_time).count();
    cout << "Proof_Gen total time for " << TEST_TIMES << " costs " << proofgen_total_time << "ms" << endl;
    cout << "Auth avg time costs " << proofgen_total_time / TEST_TIMES << "ms" << endl;
    cout << "Verify total time for " << TEST_TIMES << " costs " << verify_total_time << "ms" << endl;
    cout << "Verify avg time costs " << verify_total_time / TEST_TIMES << "ms" << endl;

    cout << "Auth total time for " << TEST_TIMES << " costs " << auth_total_time << "ms" << endl;
    cout << "Auth avg time costs " << auth_total_time / TEST_TIMES << "ms" << endl;


    end:
    element_clear(h);
    element_clear(sk);
    element_clear(pk);
    element_clear(X_bar);

    return 0;
}


