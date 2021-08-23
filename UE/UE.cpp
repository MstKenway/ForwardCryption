//
// Created by alicia on 10/8/20.
//

#include "UE.h"
#include "Socket.h"
#include <cstring>
#include "Utils.h"
#include <chrono>

using namespace std;
using namespace chrono;

#define UE_INIT_TIME_COST_LABEL "UE initial time cost:"
#define UE_E2E_CUR_TIME_COST_LABEL "UE current e2e authorisation time:"
#define UE_E2E_AVG_TIME_COST_LABEL "UE average e2e authorisation time:"
#define UE_E2E_WST_TIME_COST_LABEL "UE worst e2e authorisation time:"


std::vector<std::string> lb_ue_init_time_cost{"Element Initial Time(ms)", "Register Time(ms)",
                                              "UE Certificate For Batch Auth Generation Time(ms)",
                                              "Communication Time(ms)", "Total Time Cost(ms)"},

        lb_ue_e2e_cur_time_cost{"Certificate Generate Time(ms)", "Certificate Verify Time(ms)",
                                "Communication Time(ms)", "Total Time Cost(ms)"},
        lb_ue_e2e_avg_time_cost{"Total Key Generate Time", "Certificate Generate Time(ms)",
                                "Certificate Verify Time(ms)",
                                "Communication Time(ms)", "Total Time Cost(ms)"},
        &lb_ue_e2e_wst_time_cost(lb_ue_e2e_cur_time_cost);


///initialize UE
///basically initialize UE's elements
UE::UE(int i) {
    no = i;
    system_clock::time_point begintime, endtime;
    std::cout << "UE" << no << " Initialize...";
    begintime = system_clock::now();
    /// init
    init_pairing();
    init_elements();
    /// get random id for current user
    element_random(id);

//    element_random(ti);
//    element_pow_zn(Ti, g, ti);
    endtime = system_clock::now();
    init_time = duration<double, milli>(endtime - begintime).count();
    cout << "COMPLETE" << endl;
}

///destructor
///free memory
UE::~UE() {
    free_elements();
    free_pairing();
}

/// generate public key
/// \param kgc_g g from kgc
/// \param kgc_Ppub Ppub from kgc
/// \return 0 as success or -1 as error.
int UE::Keygen(element_t &kgc_g, element_t &kgc_Ppub) {
    system_clock::time_point begintime, endtime;
    int ret = 0;
    bool isVerify;
    std::cout << "UE get key from KGC...";
    element_t temp1, temp2;
    element_t e;
    ///initialize element g and Ppub
    element_init_same_as(g, kgc_g);
    element_init_same_as(Ppub, kgc_Ppub);
    ///copy g and Ppub
    element_set(g, kgc_g);
    element_set(Ppub, kgc_Ppub);

    begintime = system_clock::now();
    int pk_len = element_length_in_bytes(pk), pk_id_len = element_length_in_bytes(pk) + element_length_in_bytes(id);
    unsigned char pk_id_string[element_length_in_bytes(pk) + element_length_in_bytes(id)];
    element_to_bytes(pk_id_string, pk);
    element_to_bytes(pk_id_string + element_length_in_bytes(pk), id);
//    std::string temp = Utils::myxor((const char *) pk_string, (const char *) id_string);
    string temp = get_hash(pk_id_string, pk_id_len, <#initializer#>);
    element_from_hash(h, (void *) temp.c_str(), temp.length());

    /*verify in step 3*/
    element_init_G1(temp1, pairing);
    element_init_G1(temp2, pairing);
    element_pow_zn(temp1, g, sk);
    element_pow_zn(temp2, Ppub, h);
    element_mul(temp2, pk, temp2);
    isVerify = !element_cmp(temp1, temp2);
    if (isVerify)
        std::cout << "Verification of the Key from KGC Succeed!" << std::endl;
    else {
        std::cout << "Error! Verification of the Key from KGC FAIL!" << std::endl;
        ret = -1;
    }
    element_random(t);
    element_pow_zn(T, g, t);

    element_add(SK_help, sk, t);//加法,n=a+b
    element_init_Zr(e, pairing);
    element_set1(e);
    element_div(SK, e, SK_help);
//    element_invert(SK,SK_help);

    endtime = system_clock::now();
    keygen_time = duration<double, milli>(endtime - begintime).count();
    element_clear(temp1);
    element_clear(temp2);
    element_clear(e);
    return ret;
}

/// register the ue, get public key from kgc
/// \param addr The Ip address of the kgc, with the port is preset as KGC_SERVER_PORT
/// \return 0 as success or -1 as error
int UE::Register(const std::string &addr) {
    system_clock::time_point begintime, endtime;
    int len = 0;
    int conn_fd;
    conn_fd = auth_connect(addr, KGC_SERVER_PORT);
    if (conn_fd < 0) {
        perror("UE register connect error:");
        exit(1);
    }
    begintime = system_clock::now();
    ///Get an id from client
    auth_send(conn_fd, 0, 1, &id, &id);
    int G1_num, Zr_num;
    element_t *G1_res, *Zr_res;
    auth_recv(conn_fd, G1_num, Zr_num, &G1_res, &Zr_res, pairing);
    endtime = system_clock::now();
    comm_keygen_time = duration<double, milli>(endtime - begintime).count();

    ///initialize element k. sk, pk
    element_init_same_as(k, Zr_res[0]);
    element_init_same_as(sk, Zr_res[1]);
    element_init_same_as(pk, G1_res[0]);

    ///set k,sk ,pk from kgc
    element_set(k, Zr_res[0]);
    element_set(sk, Zr_res[1]);
    element_set(pk, G1_res[0]);

    ///compute and return
    Keygen(G1_res[1], G1_res[2]);
    ///free memory
    for (int i = 0; i < G1_num; ++i) {
        element_clear(G1_res[i]);
    }
    for (int i = 0; i < Zr_num; ++i) {
        element_clear(Zr_res[i]);
    }
    auth_close(conn_fd);
    ///generate batch certificate
//    Cergen_Bathch();
    ///output
    init_data.clear();
    init_data.push_back(VOIDDATA{DOUBLE, 0, init_time});
    init_data.push_back(VOIDDATA{DOUBLE, 0, keygen_time});
    init_data.push_back(VOIDDATA{DOUBLE, 0, batch_cer_gen_time});
    init_data.push_back(VOIDDATA{DOUBLE, 0, comm_keygen_time});
    init_data.push_back(VOIDDATA{DOUBLE, 0, init_time + keygen_time + comm_keygen_time});
    draw_table(UE_INIT_TIME_COST_LABEL, lb_ue_init_time_cost, init_data);
    std::cout << std::endl;
    return 0;
}


/// Generate certification by other's h(Zr), pk(G1), T(G1)
/// \param h_others Other's Zr
/// \param pk_others Other's G1
/// \param T_others Other's G1
/// \return 0 as success
void UE::Cergen_E2E(element_t h_others, element_t pk_others, element_t T_others) {
    system_clock::time_point begintime, endtime;
    std::cout << "UE generate certificate for E2E...";
    begintime = system_clock::now();
    ///definition
    element_t r1, r2;
    element_t phi;

    ///initialize element
    element_init_Zr(r1, pairing);
    element_init_Zr(r2, pairing);
    element_init_G1(phi, pairing);
    ///compute
    element_random(r1);
    element_sub(r2, r1, SK_help);

    element_pow_zn(Q1, Ppub, h_others);
    element_mul(Q1, Q1, pk_others);
    element_mul(Q1, Q1, T_others);
    element_pow_zn(Q1, Q1, r1);

    element_pow_zn(Q2, g, r2);

    element_pow_zn(phi, Ppub, h);

    unsigned char Q1_string[element_length_in_bytes(Q1)];
    unsigned char Q2_string[element_length_in_bytes(Q2)];
    unsigned char phi_string[element_length_in_bytes(phi)];
    unsigned char pk_string[element_length_in_bytes(pk)];
    unsigned char T_string[element_length_in_bytes(T)];
    element_to_bytes(Q1_string, Q1);
    element_to_bytes(Q2_string, Q2);
    element_to_bytes(phi_string, phi);
    element_to_bytes(pk_string, pk);
    element_to_bytes(T_string, T);
    std::string temp = Utils::myxor((const char *) Q1_string, (const char *) Q2_string);
    temp = Utils::myxor(temp, (const char *) phi_string);
    temp = Utils::myxor(temp, (const char *) pk_string);
    temp = Utils::myxor(temp, (const char *) T_string);

    element_from_hash(E2E_Sign, (void *) temp.c_str(), temp.length());

    endtime = system_clock::now();
    e2e_cer_gen_time = duration<double, milli>(endtime - begintime).count();
    total_e2e_cer_gen_time += e2e_cer_gen_time;
    wst_e2e_cer_gen_time = e2e_cer_gen_time > wst_e2e_cer_gen_time ? e2e_cer_gen_time : wst_e2e_cer_gen_time;
    e2e_cer_gen_count++;
    std::cout << "SUCCESS\n";

    ///free temp var
    element_clear(r1);
    element_clear(r2);
    element_clear(phi);
}

/// Verify the certification of the other's
/// \param Q1_ver Other's G1
/// \param Q2_ver Other's G1
/// \param h_others Other's Zr
/// \param pk_others Other's G1
/// \param T_others Other's G1
/// \return 0 as verification success or -1 as error/failure
int
UE::CertVerify_E2E(element_t Q1_ver, element_t Q2_ver, element_t h_others, element_t pk_others, element_t T_others) {
    system_clock::time_point begintime, endtime;
    int ret = 0;
    std::cout << "UE Verify Certificate for E2E...";
    begintime = system_clock::now();

    /// definition of temp var
    element_t temp1, temp2;

    ///initialize temp var
    element_init_G1(temp1, pairing);
    element_init_G1(temp2, pairing);

    element_pow_zn(temp1, Q1_ver, SK);
    element_div(temp1, temp1, Q2_ver);

    element_pow_zn(temp2, Ppub, h_others);
    element_mul(temp2, temp2, pk_others);
    element_mul(temp2, temp2, T_others);

    bool isVerify = !element_cmp(temp1, temp2);
    if (isVerify)
        std::cout << "UE  E2E Verification Succeed!" << std::endl;
    else {
        std::cout << "UE E2E Verification Failure!" << std::endl;
        ret = -1;
    }

    endtime = system_clock::now();
    e2e_verify_time = duration<double, milli>(endtime - begintime).count();
    total_e2e_cer_ver_time += e2e_verify_time;
    wst_e2e_cer_ver_time = e2e_verify_time > wst_e2e_cer_ver_time ? e2e_verify_time : wst_e2e_cer_ver_time;
    ///free temp var
    element_clear(temp1);
    element_clear(temp2);
    return ret;
}

/// launch an E2E access authorization
/// \param addr Server's IP
/// \param port Server's port
/// \return -1 as error
int UE::verify_e2e_launch(const std::string &addr, unsigned short port) {
    ///send a Zr h and 2 G1 T & pk
    ///verify the return value Q1 & Q2 with return h, T & pk
    ///first, verify the server
    system_clock::time_point begintime, endtime;
    int len = 0, ret = 0;
    int conn_fd;
    conn_fd = auth_connect(addr, port);
    if (conn_fd < 0) {
        perror("UE conn error:");
        return -1;
    }
    ///send data to server
    ///define 2 G1 array and initialize the same as pk and T (while data won't be copied)
    element_t G1_req[2];
    element_init_same_as(G1_req[0], pk);
    element_init_same_as(G1_req[1], T);
    ///now set the data of the array
    element_set(G1_req[0], pk);
    element_set(G1_req[1], T);

    begintime = system_clock::now();
    ///send G1 array with pk and T, and one Zr h
    len = auth_send(conn_fd, 2, 1, G1_req, &h);

    ///free the memory of the array
    for (auto &i : G1_req) {
        element_clear(i);
    }
    if (len < 0) {
        perror("UE send error");
        goto end;
    }


    int G1_num_1st, Zr_num_1st, G1_num_2nd, Zr_num_2nd;
    G1_num_1st = 0;
    Zr_num_1st = 0;
    G1_num_2nd = 0;
    Zr_num_2nd = 0;
    element_t *G1_res_1st, *Zr_res_1st, *G1_res_2nd, *Zr_res_2nd;
    ///rec Q1 Q2 pk T and Zr h
    auth_recv(conn_fd, G1_num_1st, Zr_num_1st, &G1_res_1st, &Zr_res_1st, pairing);
    if (G1_num_1st != 4 || Zr_num_1st != 1) {
        perror("UE verify respond element number error:");
        ret = -1;
        goto free_recv_1st;
    }
    endtime = system_clock::now();
    comm_e2e_response_time = duration<double, milli>(endtime - begintime).count();
    ///verify
    len = CertVerify_E2E(G1_res_1st[0], G1_res_1st[1], Zr_res_1st[0], G1_res_1st[2], G1_res_1st[3]);

    if (len < 0) {
        ret = len;
        goto free_recv_1st;
    }

    begintime = system_clock::now();
    /// second, recv server data to get verified
    ///rec  pk T and Zr h
    auth_recv(conn_fd, G1_num_2nd, Zr_num_2nd, &G1_res_2nd, &Zr_res_2nd, pairing);
    if (G1_num_2nd != 2 || Zr_num_2nd != 1) {
        perror("UE recv element number error:");
        ret = -1;
        goto free_recv_2nd;
    }
    endtime = system_clock::now();
    comm_e2e_response_time += duration<double, milli>(endtime - begintime).count();


    element_printf("Receive the identity is %B\n", G1_res_2nd[0]);
    element_printf("Receive the Zr is %B\n", Zr_res_2nd[0]);
    element_printf("The length of Zr is %d\n", element_length_in_bytes(Zr_res_2nd[0]));
    Cergen_E2E(Zr_res_2nd[0], G1_res_2nd[0], G1_res_2nd[1]);

    ///respond to the server
    element_t G1_respond[4];
    element_init_same_as(G1_respond[0], Q1);
    element_init_same_as(G1_respond[1], Q2);
    element_init_same_as(G1_respond[2], pk);
    element_init_same_as(G1_respond[3], T);

    element_set(G1_respond[0], Q1);
    element_set(G1_respond[1], Q2);
    element_set(G1_respond[2], pk);
    element_set(G1_respond[3], T);

    begintime = system_clock::now();
    ///send data to server
    len = auth_send(conn_fd, 4, 1, G1_respond, &h);
    endtime = system_clock::now();
    comm_e2e_response_time += duration<double, milli>(endtime - begintime).count();

    ///free
    for (auto &i : G1_respond) {
        element_clear(i);
    }

    free_recv_2nd:
    for (int i = 0; i < G1_num_2nd; ++i) {
        element_clear(G1_res_2nd[i]);
    }
    for (int i = 0; i < Zr_num_2nd; ++i) {
        element_clear(Zr_res_2nd[i]);
    }

    free_recv_1st:
    for (int i = 0; i < G1_num_1st; ++i) {
        element_clear(G1_res_1st[i]);
    }
    for (int i = 0; i < Zr_num_1st; ++i) {
        element_clear(Zr_res_1st[i]);
    }

    end:
    auth_close(conn_fd);
    ///output
    cur_e2e_data.clear();
    cur_e2e_data.push_back(VOIDDATA{DOUBLE, 0, e2e_cer_gen_time});
    cur_e2e_data.push_back(VOIDDATA{DOUBLE, 0, e2e_verify_time});
    cur_e2e_data.push_back(VOIDDATA{DOUBLE, 0, comm_e2e_response_time});
    cur_e2e_data.push_back(VOIDDATA{DOUBLE, 0, e2e_cer_gen_time + e2e_verify_time + comm_e2e_response_time});
    draw_table(UE_E2E_CUR_TIME_COST_LABEL, lb_ue_e2e_cur_time_cost, cur_e2e_data);
    return len;
}


/// Listen to the port and wait for new e2e verification
/// \return -1 as error
[[noreturn]] void UE::verify_e2e_respond() {
    system_clock::time_point begintime, endtime;

    ///send a Zr h and 2 G1 T & pk
    ///verify the return value Q1 & Q2 with return h, T & pk
    ///first, verify the server
    int len = 0;
    int socket_fd, client_fd;
    sockaddr_in addr;
    ///bind and listen local port
    socket_fd = auth_listen(SATELLITE_SERVER_PORT);
    if (socket_fd < 0) {
        perror("UE listen error:");
        exit(1);
    }

    while (true) {
        ///wait for new connection
        client_fd = auth_accept(socket_fd, addr);
        if (client_fd < 0) {
            perror("UE accept error:");
            goto end;
        }
        int G1_num_1st, Zr_num_1st, G1_num_2nd, Zr_num_2nd;
        element_t *G1_res_1st, *Zr_res_1st, *G1_res_2nd, *Zr_res_2nd;
        G1_num_1st = 0;
        Zr_num_1st = 0;
        G1_num_2nd = 0;
        Zr_num_2nd = 0;
        G1_res_1st = Zr_res_1st = G1_res_2nd = Zr_res_2nd = nullptr;
        /// first, recv server data to get verified
        ///rec  pk T and Zr h
        begintime = system_clock::now();
        auth_recv(client_fd, G1_num_1st, Zr_num_1st, &G1_res_1st, &Zr_res_1st, pairing);
        endtime = system_clock::now();
        comm_e2e_response_time = duration<double, milli>(endtime - begintime).count();

        if (G1_num_1st != 2 || Zr_num_1st != 1) {
            perror("UE recv element number error:");
            goto free_recv_1st;
        }

        element_printf("Receive the identity is %B\n", G1_res_1st[0]);
        Cergen_E2E(Zr_res_1st[0], G1_res_1st[0], G1_res_1st[1]);
        ///respond to the server
        element_t G1_respond[4];
        element_init_same_as(G1_respond[0], Q1);
        element_init_same_as(G1_respond[1], Q2);
        element_init_same_as(G1_respond[2], pk);
        element_init_same_as(G1_respond[3], T);

        element_set(G1_respond[0], Q1);
        element_set(G1_respond[1], Q2);
        element_set(G1_respond[2], pk);
        element_set(G1_respond[3], T);

        begintime = system_clock::now();
        ///send data to server
        len = auth_send(client_fd, 4, 1, G1_respond, &h);
        endtime = system_clock::now();
        comm_e2e_response_time += duration<double, milli>(endtime - begintime).count();

        for (auto &i : G1_respond) {
            element_clear(i);
        }
        ///second,get verified
        ///send data to server
        element_t G1_req[2];
        element_init_same_as(G1_req[0], pk);
        element_init_same_as(G1_req[1], T);
        element_set(G1_req[0], pk);
        element_set(G1_req[1], T);

        begintime = system_clock::now();
        auth_send(client_fd, 2, 1, G1_req, &h);

        for (auto &i : G1_req) {
            element_clear(i);
        }

        ///rec Q1 Q2 pk T and Zr h
        auth_recv(client_fd, G1_num_2nd, Zr_num_2nd, &G1_res_2nd, &Zr_res_2nd, pairing);
        endtime = system_clock::now();
        comm_e2e_response_time += duration<double, milli>(endtime - begintime).count();

        if (G1_num_2nd != 4 || Zr_num_2nd != 1) {
            perror("UE verify respond element number error:");
            goto free_recv_2nd;
        }
        ///verify
        len = CertVerify_E2E(G1_res_2nd[0], G1_res_2nd[1], Zr_res_2nd[0], G1_res_2nd[2], G1_res_2nd[3]);

        if (len < 0) {
            perror("UE certification verify error");
        }

        free_recv_2nd:
        for (int i = 0; i < G1_num_2nd; ++i) {
            element_clear(G1_res_2nd[i]);
        }
        for (int i = 0; i < Zr_num_2nd; ++i) {
            element_clear(Zr_res_2nd[i]);
        }

        free_recv_1st:
        for (int i = 0; i < G1_num_1st; ++i) {
            element_clear(G1_res_1st[i]);
        }
        for (int i = 0; i < Zr_num_1st; ++i) {
            element_clear(Zr_res_1st[i]);
        }
        end:
        auth_close(client_fd);
        total_e2e_comm_time += comm_e2e_response_time;
        wst_e2e_comm_time = comm_e2e_response_time > wst_e2e_comm_time ? comm_e2e_response_time : wst_e2e_comm_time;
        ///output
        cur_e2e_data.clear();
        cur_e2e_data.push_back(VOIDDATA{DOUBLE, 0, e2e_cer_gen_time});
        cur_e2e_data.push_back(VOIDDATA{DOUBLE, 0, e2e_verify_time});
        cur_e2e_data.push_back(VOIDDATA{DOUBLE, 0, comm_e2e_response_time});
        cur_e2e_data.push_back(VOIDDATA{DOUBLE, 0, e2e_cer_gen_time + e2e_verify_time + comm_e2e_response_time});
        draw_table(UE_E2E_CUR_TIME_COST_LABEL, lb_ue_e2e_cur_time_cost, cur_e2e_data);

        avg_e2e_data.clear();
        avg_e2e_data.push_back(VOIDDATA{INT, (int) e2e_cer_gen_count});
        avg_e2e_data.push_back(VOIDDATA{DOUBLE, 0, total_e2e_cer_gen_time / e2e_cer_gen_count});
        avg_e2e_data.push_back(VOIDDATA{DOUBLE, 0, total_e2e_cer_ver_time / e2e_cer_gen_count});
        avg_e2e_data.push_back(VOIDDATA{DOUBLE, 0, total_e2e_comm_time / e2e_cer_gen_count});
        avg_e2e_data.push_back(
                VOIDDATA{DOUBLE, 0, (total_e2e_cer_gen_time + total_e2e_cer_ver_time + total_e2e_comm_time) /
                                    e2e_cer_gen_count});
        draw_table(UE_E2E_AVG_TIME_COST_LABEL, lb_ue_e2e_avg_time_cost, avg_e2e_data);

        wst_e2e_data.clear();
        wst_e2e_data.push_back(VOIDDATA{DOUBLE, 0, wst_e2e_cer_gen_time});
        wst_e2e_data.push_back(VOIDDATA{DOUBLE, 0, wst_e2e_cer_ver_time});
        wst_e2e_data.push_back(VOIDDATA{DOUBLE, 0, wst_e2e_comm_time});
        wst_e2e_data.push_back(VOIDDATA{DOUBLE, 0, wst_e2e_cer_gen_time + wst_e2e_cer_ver_time +
                                                   wst_e2e_comm_time});
        draw_table(UE_E2E_WST_TIME_COST_LABEL, lb_ue_e2e_wst_time_cost, wst_e2e_data);
    }
    auth_close(socket_fd);
}


void UE::start_new_ue_accept_thread() {
    isReady = true;
    new_ue_accept = std::thread{&UE::accept_new_ue, this, UEN_VRF_UE_PORT};
    printf("New thread for ue accept start.\n");
}

void UE::stop_new_ue_accept_thread() {
    isReady = false;
    new_ue_accept.join();
    printf("Thread for ue accept stop.\n");
}

void UE::init_pairing() {
    pairing_init_set_buf(pairing, TYPEA_PARAMS, strlen(TYPEA_PARAMS));
}

void UE::init_elements() {
//    element_init_Zr(ti, pairing);
//    element_init_G1(Ti,pairing);
    ///initialize left elements
    element_init_Zr(h, pairing);
    element_init_Zr(t, pairing);
    element_init_G1(T, pairing);
    element_init_Zr(SK_help, pairing);
    element_init_Zr(SK, pairing);
    element_init_G1(Q1, pairing);
    element_init_G1(Q2, pairing);
    element_init_Zr(E2E_Sign, pairing);


    ///initialize elements for ue_cergen_batch
    element_init_G1(U, pairing);
    element_init_Zr(s, pairing);
    element_init_Zr(m, pairing);
    element_init_Zr(gamma, pairing);
    element_init_Zr(hn_gamma, pairing);
    element_init_G1(Tn_gamma, pairing);
    element_init_G1(pkn_gamma, pairing);
    element_init_G1(Un_gamma, pairing);
}

void UE::free_elements() {
    ///free elements
    element_clear(id);
    element_clear(h);
    element_clear(t);
    element_clear(T);
    element_clear(SK_help);
    element_clear(SK);
    element_clear(Q1);
    element_clear(Q2);
    element_clear(E2E_Sign);

    ///free elements for ue_cergen_batch
    element_clear(U);
    element_clear(s);
    element_clear(m);
    element_clear(gamma);
    element_clear(hn_gamma);
    element_clear(Tn_gamma);
    element_clear(pkn_gamma);
    element_clear(Un_gamma);
}

void UE::free_pairing() {
    ///free pairing
    pairing_clear(pairing);
}

