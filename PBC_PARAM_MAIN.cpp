//
// Created by GaoYun on 2021/6/17.
//

#include "pbc.h"

#define PARAM_FILE_NAME "ec.param"
#define TEST_TIME 1000

#include "Utils/Utils.h"
#include <chrono>
#include <iostream>

using namespace std;
using namespace chrono;

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

void pbc_param_init_file(pbc_param_t param, char *filename) {
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
    pbc_param_init_set_buf(param, s, count);
}

void test_single_time() {
    system_clock::time_point begin_time, end_time;
    double total_time;
    int len;
    pairing_t pairing;
    pbc_pairing_init_file(pairing, PARAM_FILE_NAME);

    string plain_text = "hello world.\n", key = get_rand_num(128), cipher_text, iv = get_rand_num(IV_LEN);

    element_t zr0, zr1, zr2, G0, G1, G2, GT;
    element_init_Zr(zr0, pairing);
    element_init_Zr(zr1, pairing);
    element_init_Zr(zr2, pairing);
    element_init_G1(G0, pairing);
    element_init_G1(G1, pairing);
    element_init_G2(G2, pairing);
    element_init_GT(GT, pairing);


    element_random(zr1);
    element_random(zr2);
    element_random(G1);
    element_random(G2);
    element_random(GT);


    ///output length
    len = element_length_in_bytes(zr1);
    cout << "Lr=Lid is : " << len << "byte(s)" << endl;
    len = element_length_in_bytes(G1);
    cout << "L+=L* is : " << len << "byte(s)" << endl;
    cout << "Lh is : " << "32 byte(s)" << endl;
    cout << "Ls consists of iv + ciphter text + tag; the len of iv is  " << IV_LEN
         << " byte(s)\t cipher text =plain text \t"
         << "tag len is " << TAG_LEN << " byte(s)" << endl;
    cout << "Lt is : " << sizeof(time_t) << " byte(s)" << endl;

    /// zr*zr
    begin_time = system_clock::now();
    for (int i = 0; i < TEST_TIME; ++i) {
        element_mul(zr0, zr1, zr2);
    }
    end_time = system_clock::now();
    total_time = duration<double, milli>(end_time - begin_time).count();
    cout << "Zr*Zr total time for " << TEST_TIME << " costs " << total_time << "ms" << endl;
    cout << "Zr*Zr avg time costs " << total_time / TEST_TIME << "ms" << endl;


    /// zr*G1
    begin_time = system_clock::now();
    for (int i = 0; i < TEST_TIME; ++i) {
        element_mul(G0, G1, zr1);
    }
    end_time = system_clock::now();
    total_time = duration<double, milli>(end_time - begin_time).count();
    cout << "Zr*G1 total time for " << TEST_TIME << " costs " << total_time << "ms" << endl;
    cout << "Zr*G1 avg time costs " << total_time / TEST_TIME << "ms" << endl;


    /// G1*G1
    begin_time = system_clock::now();
    for (int i = 0; i < TEST_TIME; ++i) {
        element_mul(G0, G1, G1);
    }
    end_time = system_clock::now();
    total_time = duration<double, milli>(end_time - begin_time).count();
    cout << "G1*G1 total time for " << TEST_TIME << " costs " << total_time << "ms" << endl;
    cout << "G1*G1 avg time costs " << total_time / TEST_TIME << "ms" << endl;

    /// G1^Zr
    begin_time = system_clock::now();
    for (int i = 0; i < TEST_TIME; ++i) {
        element_pow_zn(G0, G1, zr1);
    }
    end_time = system_clock::now();
    total_time = duration<double, milli>(end_time - begin_time).count();
    cout << "G1^Zr total time for " << TEST_TIME << " costs " << total_time << "ms" << endl;
    cout << "G1^Zr avg time costs " << total_time / TEST_TIME << "ms" << endl;

    /// G1&G2->GT
    begin_time = system_clock::now();
    for (int i = 0; i < TEST_TIME; ++i) {
        pairing_apply(GT, G1, G2, pairing);
    }
    end_time = system_clock::now();
    total_time = duration<double, milli>(end_time - begin_time).count();
    cout << "G1&G2->GT total time for " << TEST_TIME << " costs " << total_time << "ms" << endl;
    cout << "G1&G2->GT avg time costs " << total_time / TEST_TIME << "ms" << endl;

    /// sha-256
    begin_time = system_clock::now();
    for (int i = 0; i < TEST_TIME; ++i) {
        get_hash((unsigned char *) plain_text.c_str(), plain_text.length(), <#initializer#>);
    }
    end_time = system_clock::now();
    total_time = duration<double, milli>(end_time - begin_time).count();
    cout << "sha-256 total time for " << TEST_TIME << " costs " << total_time << "ms" << endl;
    cout << "sha-256 avg time costs " << total_time / TEST_TIME << "ms" << endl;


    /// aes-128-gcm
    begin_time = system_clock::now();
    for (int i = 0; i < TEST_TIME; ++i) {
        EncryptString(plain_text, key, iv);
    }
    end_time = system_clock::now();
    total_time = duration<double, milli>(end_time - begin_time).count();
    cout << "aes-128-gcm total time for " << TEST_TIME << " costs " << total_time << "ms" << endl;
    cout << "aes-128-gcm avg time costs " << total_time / TEST_TIME << "ms" << endl;

    end:
    element_clear(zr0);
    element_clear(zr1);
    element_clear(zr2);
    element_clear(G0);
    element_clear(G1);
    element_clear(G2);
    element_clear(GT);
}


void test_diff_key_len() {
    system_clock::time_point begin_time, end_time, t1, t2, t3;
    string plain_text = "hello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\nhello world.\n",
            key = get_rand_num(128), cipher_text, iv = get_rand_num(IV_LEN), temp_text;
    double total_time, en_total_time = 0, de_total_time = 0;

    /// aes-128-gcm
    begin_time = system_clock::now();
    for (int i = 0; i < TEST_TIME; ++i) {
        t1 = system_clock::now();
        cipher_text = EncryptString(plain_text, key, iv);
        t2 = system_clock::now();
        DecryptString(cipher_text, key, iv, temp_text);
        t3 = system_clock::now();
        en_total_time += duration<double, milli>(t2 - t1).count();
        de_total_time += duration<double, milli>(t3 - t2).count();
    }
    end_time = system_clock::now();
    total_time = duration<double, milli>(end_time - begin_time).count();
    cout << "aes-128-gcm total encrypt time for " << TEST_TIME << " costs " << en_total_time << "ms" << endl;
    cout << "aes-128-gcm avg encrypt time costs " << en_total_time / TEST_TIME << "ms" << endl;

    cout << "aes-128-gcm total decrypt time for " << TEST_TIME << " costs " << de_total_time << "ms" << endl;
    cout << "aes-128-gcm avg decrypt time costs " << de_total_time / TEST_TIME << "ms" << endl;
    cout << "aes-128-gcm total encrypt & decrypt time for " << TEST_TIME << " costs " << total_time << "ms" << endl;
    cout << "aes-128-gcm avg encrypt & decrypt time costs " << total_time / TEST_TIME << "ms" << endl;

}

int main() {
    test_single_time();
    return 0;

    pbc_param_t param;
    pbc_param_init_file(param, PARAM_FILE_NAME);
    pairing_t pairing;
    pairing_init_pbc_param(pairing, param);

    element_t a, b, c;
    element_init_Zr(a, pairing);
    element_init_G1(b, pairing);
    element_init_G2(c, pairing);


    element_random(a);
    element_random(b);
    element_random(c);

    element_printf("%B\n", a);
    element_printf("%B\n", b);
    element_printf("%B\n", c);


    element_clear(a);
    element_clear(b);
    element_clear(c);
    return 0;
}