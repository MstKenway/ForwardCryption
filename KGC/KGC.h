//
// Created by alicia on 10/8/20.
//

#ifndef BATHCH_AUTH_UP_KGC_H
#define BATHCH_AUTH_UP_KGC_H

#include <cstring>
#include <string>
#include <vector>
#include <iostream>

#include "pbc.h"
#include "plog.h"

class KGC {
    pairing_t pairing;
    element_t s;

/// init & free
    void init_pairing();

    void init_elements();

    void free_elements();

    void free_pairing();

    /// key generation
    void kgc_key_gen();


public:
    element_t g, Ppub;

    KGC();

    ~KGC();

    [[noreturn]] void run();

    /// key generation
    void user_key_gen(element_ptr id, element_t &pk, element_t &sk, element_t &h);

    /// return value
    element_ptr get_g();

    element_ptr get_Ppub();

private:
    ///Variable for performance test
    ///fragment time
    double init_time = 0, key_gen_time = 0, worst_keygen_time = 0;
    double comm_keygen_time = 0, worst_comm_keygen_time = 0;
    unsigned int keygen_count = 0;
    ///total time
    double total_compute_time = 0, total_comm_time = 0;
    ///data for draw table
    std::vector<VOIDDATA> cur_data, avg_data, wst_data;

    void output_result();
};


#endif //BATHCH_AUTH_UP_KGC_H
