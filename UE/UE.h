//
// Created by alicia on 10/8/20.
//

#ifndef BATHCH_AUTH_UP_UE_H
#define BATHCH_AUTH_UP_UE_H

#include "FCAE.h"


#define UEN_VRF_UE_PORT 16667


#include "pbc.h"
#include <string>
#include <vector>
#include <iostream>
#include <thread>
#include "plog.h"

struct SUBUE {
    element_t id, m, U, pk, T, s, h, Tn_gamma, pkn_gamma, Un_gamma, hn_gamma;
};


class UE {
private:
    int no;
    FCAE ae;
    element_t k, pk, sk, t, T, SK, m, U, s, SK_help, gamma, h, g, Ppub;
    element_t Tn_gamma, pkn_gamma, hn_gamma, Un_gamma;
    element_t omega;
    element_t Q1, Q2;// cert in the E2E.

    PID pid;
    PRIVATE pri_key;

    /// init & free
    void init_pairing();

    void init_elements();

    void free_elements();

    void free_pairing();


public:

//    element_t Q1p,Q2p;// cert in the E2E in pair.
    element_t E2E_Sign;//cert sign for E2E.
//    element_t E2E_Pair_CertSign;
    pairing_t pairing;
    bool isverify = false;

    ///members for batch authorisation
    std::vector<SUBUE> ue_list;

    ///thread and its function
    std::thread new_ue_accept;
    bool isReady = false;

    void start_new_ue_accept_thread();

    void stop_new_ue_accept_thread();

    [[noreturn]]void accept_new_ue(unsigned short port);

    void uen_luanch(const std::string &addr, unsigned short port);


    UE(int i = 1);

    ~UE();

    ///function for register

    int Keygen(element_t &g, element_t &Ppub);

    int Register(const std::string &addr);



    ///following is the function for e2e authorisation

    void Cergen_E2E(element_t h_others, element_t pk_others, element_t T_others);

    int CertVerify_E2E(element_t Q1_ver, element_t Q2_ver, element_t h_others, element_t pk_others, element_t T_others);

    int verify_e2e_launch(const std::string &addr, unsigned short port);

    [[noreturn]]void verify_e2e_respond();


private:
    ///Variable for performance test
    ///fragment time
    double init_time = 0, keygen_time = 0, batch_poly_time = 0, batch_verify_time = 0, e2e_cer_gen_time = 0,
            e2e_verify_time = 0, batch_cer_gen_time = 0, uei_ver_time = 0;
    double comm_keygen_time = 0, comm_batch_response_time = 0, comm_e2e_response_time = 0, comm_uei_time = 0;
    double wst_uei_ver_time = 0, wst_uei_comm_time = 0;
    unsigned int batch_uei_ver_count = 0, e2e_cer_gen_count = 0;
    ///worst time
    double wst_e2e_comm_time = 0, wst_e2e_cer_gen_time = 0, wst_e2e_cer_ver_time = 0;
    ///total time
    double total_uei_ver_time = 0, total_uei_comm_time = 0, total_e2e_comm_time = 0, total_e2e_cer_gen_time = 0,
            total_e2e_cer_ver_time = 0;
    ///data for draw table
    std::vector<VOIDDATA> init_data, cur_e2e_data, avg_e2e_data, wst_e2e_data, cur_batch_data, cur_uei_data,
            avg_uei_data, wst_uei_data;
};

#endif //BATHCH_AUTH_UP_UE_H
