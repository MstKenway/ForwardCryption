//
// Created by alicia on 10/8/20.
//
#include "Utils.h"
#include "FCAE.h"
#include<string>
#include "KGC.h"
#include "Socket.h"
#include <chrono>

using namespace std;
using namespace chrono;
static std::vector<std::string> lb_cur_data = {"Compute Time(ms)", "Communication Time(ms)", "Total Time Cost(ms)"},
        lb_avg_data = {"Total Key Generate Time", "Compute Time(ms)", "Communication Time(ms)", "Total Time Cost(ms)"},
        &lb_wst_data(lb_cur_data);


KGC::KGC() {
    steady_clock::time_point begin_time, end_time;
    std::cout << "KGC Initialize...";
    begin_time = steady_clock::now();
    init_pairing();
    init_elements();
    kgc_key_gen();
    end_time = steady_clock::now();
    init_time = duration<double, milli>(end_time - begin_time).count();
    std::cout << "COMPLETE" << std::endl;
    std::cout << "KGC initialization time is : " << init_time << "ms." << std::endl << std::endl;
}


KGC::~KGC() {
    free_elements();
    free_pairing();
}

/// Generate user key. Including public key and private key.
/// \param id The only Input is user's id. An element on Zr.
/// \param pk pk is the output as Public key. An element on G1.
/// \param sk sk is the output as part of private key. An element on Zr.
/// \param h h is an intermediate element on Zr.
void KGC::user_key_gen(element_ptr id, element_t &pk, element_t &sk, element_t &h) {
    steady_clock::time_point begin_time, end_time;
    std::cout << "KGC generate Public Key...";
    begin_time = steady_clock::now();
    ///definition
    element_t t;

    ///initialize
    element_init_Zr(t, pairing);

    ///compute pk for id_i
    element_random(t);
    element_pow_zn(pk, g, t);

    /// compute h
    unsigned hash_len = 0;
    unsigned char *temp = H1(pk, id, hash_len);
    element_from_hash(h, (void *) (temp), (int) (hash_len));
    /// compute sk
    element_mul(sk, s, h);
    element_add(sk, t, sk);

    end_time = steady_clock::now();
    key_gen_time = duration<double, milli>(end_time - begin_time).count();

    worst_keygen_time = key_gen_time > worst_keygen_time ? key_gen_time : worst_keygen_time;
    total_compute_time += key_gen_time;
    keygen_count++;
    std::cout << "SUCCESS\n";

    ///free the memory of the temporary elements
    end:
    element_clear(t);
    /// free hash result
    delete[] temp;
}

[[noreturn]] void KGC::run() {
    steady_clock::time_point begin_time, end_time;
    int listen_fd, client_fd;
    int len = 0;
    listen_fd = auth_listen(KGC_SERVER_PORT);
    if (listen_fd < 0) {
        perror("KGC listen error:");
        exit(1);
    }
    while (true) {
        ///wait for new connection
        sockaddr_in addr;
        client_fd = auth_accept(listen_fd, addr);
        if (client_fd < 0) {
            perror("KGC accept fail:");
            goto end;
        }
        //Get an id from client
        element_t *id, *nil;
        int G1_num, Zr_num;
        id = nullptr;
        begin_time = steady_clock::now();
        len = auth_recv(client_fd, G1_num, Zr_num, &nil, &id, pairing);
        if (len < 0) {
            perror("Auth recv error:");
            goto clear_id;
        }
        end_time = steady_clock::now();
        comm_keygen_time = duration<double, milli>(end_time - begin_time).count();


        //compute and return
        element_t G1_res[3], Zr_res[2];
        //initialize elements
        for (auto &G1_re : G1_res) {
            element_init_G1(G1_re, pairing);
        }
        for (auto &Zr_re : Zr_res) {
            element_init_Zr(Zr_re, pairing);
        }
        // todo: user key gen
//        user_key_gen(id[0], Zr_res[0], G1_res[0], Zr_res[1]);
        element_set(G1_res[1], g);
        element_set(G1_res[2], Ppub);

        begin_time = steady_clock::now();
        //return the respond
        len = auth_send(client_fd, 3, 2, G1_res, Zr_res);
        if (len <= 0) {
            perror("KGC send error:");
        }
        end_time = steady_clock::now();
        comm_keygen_time += duration<double, milli>(end_time - begin_time).count();


        //end,free
        for (auto &G1_re : G1_res) {
            element_clear(G1_re);
        }
        for (auto &Zr_re : Zr_res) {
            element_clear(Zr_re);
        }
        ///the operation in the end
        clear_id:
        if (id != nullptr)element_clear(*id);
        end:
        auth_close(client_fd);
        worst_comm_keygen_time = comm_keygen_time > worst_comm_keygen_time ? comm_keygen_time : worst_comm_keygen_time;
        total_comm_time += comm_keygen_time;
        ///output result
        // output_result();
        std::cout << std::endl;
    }
    auth_close(listen_fd);
}

void KGC::output_result() {
    cur_data.clear();
    cur_data.push_back(VOIDDATA{DOUBLE, 0, key_gen_time});
    cur_data.push_back(VOIDDATA{DOUBLE, 0, comm_keygen_time});
    cur_data.push_back(VOIDDATA{DOUBLE, 0, key_gen_time + comm_keygen_time});
    draw_table("Current connection time cost:", lb_cur_data, cur_data);

    avg_data.clear();
    avg_data.push_back(VOIDDATA{INT, (int) keygen_count});
    avg_data.push_back(VOIDDATA{DOUBLE, 0, total_compute_time / keygen_count});
    avg_data.push_back(VOIDDATA{DOUBLE, 0, total_comm_time / keygen_count});
    avg_data.push_back(VOIDDATA{DOUBLE, 0, (total_compute_time + total_comm_time) / keygen_count});
    draw_table("Average time cost:", lb_avg_data, avg_data);

    wst_data.clear();
    wst_data.push_back(VOIDDATA{DOUBLE, 0, worst_keygen_time});
    wst_data.push_back(VOIDDATA{DOUBLE, 0, worst_comm_keygen_time});
    wst_data.push_back(VOIDDATA{DOUBLE, 0, worst_keygen_time + worst_comm_keygen_time});
    draw_table("Worst time cost:", lb_wst_data, wst_data);

}

void KGC::init_pairing() {
    pbc_pairing_init_file(pairing, (char *) PARAM_FILE_NAME);
}

void KGC::init_elements() {
    /// init element on Zr
    element_init_Zr(s, pairing);
    /// init element on G1
    element_init_G1(g, pairing);
    element_init_G1(Ppub, pairing);
}

void KGC::free_elements() {
    element_clear(s);
    element_clear(g);
    element_clear(Ppub);
}

void KGC::free_pairing() {
    pairing_clear(pairing);
}

void KGC::kgc_key_gen() {
    element_random(s);
    element_random(g);
    element_pow_zn(Ppub, g, s);
}

element_ptr KGC::get_g() {
    return g;
}

element_ptr KGC::get_Ppub() {
    return Ppub;
}

