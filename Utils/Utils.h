//
// Created by GaoYun on 2021/5/21.
//

#ifndef AUTH_ALL_UTILS_H
#define AUTH_ALL_UTILS_H

#include <string>

#define HASH_NAME "sha256"
#define IV_LEN 12
#define TAG_LEN 16

unsigned char * get_hash(const unsigned char *message, int len, unsigned int &ret_len);

std::string EncryptString(const std::string &instr, const std::string &passPhrase, const std::string &iv);


bool
DecryptString(const std::string &instr, const std::string &passPhrase, const std::string &iv, std::string &plain_text);

std::string get_rand_num(int num);

#endif //AUTH_ALL_UTILS_H
