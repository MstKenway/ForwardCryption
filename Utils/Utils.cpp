//
// Created by GaoYun on 2021/5/21.
//

#include "Utils.h"
#include "openssl/evp.h"
#include "openssl/rand.h"
#include "openssl/err.h"
#include <cstring>
#include <iostream>

#define byte unsigned char


using namespace std;

void utils_init() {
    OpenSSL_add_all_digests();
}

static void print_errors() {
    int flags, line;
    char *data, *file;
    unsigned long code;

    code = ERR_get_error_line_data((const char **) &file, &line, (const char **) &data, &flags);
    while (code) {
        printf("error code: %lu in %s line %d.\n", code, file, line);
        if (data && (flags & ERR_TXT_STRING))
            printf("error data: %s\n", data);
        code = ERR_get_error_line_data((const char **) &file, &line, (const char **) &data, &flags);
    }
}


static void handle_errors() {
    print_errors();
}

unsigned char * get_hash(const unsigned char *message, int len, unsigned int &ret_len) {
    const EVP_MD *md;
    EVP_MD_CTX *mdctx;
    unsigned char *md_value = new unsigned char[EVP_MAX_MD_SIZE];
    ret_len = 0;

    md = EVP_get_digestbyname(HASH_NAME);
    if (!md) {
        printf("Unknown message digest %s\n", HASH_NAME);
        exit(1);
    }
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, message, len);
    EVP_DigestFinal_ex(mdctx, md_value, &ret_len);
    EVP_MD_CTX_destroy(mdctx);
    return md_value;
}

static int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                       unsigned char *aad, int aad_len,
                       unsigned char *key,
                       unsigned char *iv, int iv_len,
                       unsigned char *ciphertext,
                       unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;


    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handle_errors();

    /* Initialise the encryption operation. */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        handle_errors();

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handle_errors();

    /* Initialise key and IV */
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handle_errors();

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handle_errors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handle_errors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handle_errors();
    ciphertext_len += len;

    /* Get the tag */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handle_errors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

static int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                       unsigned char *aad, int aad_len,
                       unsigned char *tag,
                       unsigned char *key,
                       unsigned char *iv, int iv_len,
                       unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handle_errors();

    /* Initialise the decryption operation. */
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        handle_errors();

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handle_errors();

    /* Initialise key and IV */
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handle_errors();

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handle_errors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handle_errors();
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handle_errors();

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}

std::string EncryptString(const string &instr, const string &passPhrase, const string &iv) {
    int r;
    char tag[TAG_LEN], cipher_text[instr.length()];
    r = gcm_encrypt((unsigned char *) instr.c_str(), instr.length(), (unsigned char *) nullptr, 0,
                    (unsigned char *) passPhrase.c_str(),
                    (unsigned char *) iv.c_str(), IV_LEN,
                    (unsigned char *) cipher_text, (unsigned char *) tag);
    if (r != instr.length()) {
        return "";
    }
    string outstr = string(cipher_text, r);
    outstr += string(tag, TAG_LEN);
    return outstr;
}

bool DecryptString(const string &instr, const string &passPhrase, const string &iv, string &plain_text) {
    int r;
    char pt[instr.length() - TAG_LEN];
    r = gcm_decrypt((unsigned char *) instr.c_str(), instr.length() - TAG_LEN, (unsigned char *) nullptr, 0,
                    (unsigned char *) instr.c_str() + instr.length() - TAG_LEN,
                    (unsigned char *) passPhrase.c_str(),
                    (unsigned char *) iv.c_str(), IV_LEN,
                    (unsigned char *) pt);
    if (r != instr.length() - TAG_LEN) {
        return false;
    }
    plain_text = string(pt, r);
    return true;
}

std::string get_rand_num(int num) {
    int r;
    string ret = "";
    while (num > 0) {
        unsigned char buf[4096];
        int chunk;

        chunk = num;
        if (chunk > (int) sizeof(buf))
            chunk = sizeof(buf);
        r = RAND_bytes(buf, chunk);
        if (r <= 0)
            return "";
        string temp((char *) buf, chunk);
        ret += temp;
        num -= chunk;
    }
    return ret;
}

