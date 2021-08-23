//
// Created by  Du的mbp 13 on 10/28/20.
//

#ifndef UNTITLED_SOCKET_H
#define UNTITLED_SOCKET_H


//#define DEBUG

#include "pbc.h"
#include<string>

#if defined(__unix__) || defined(__linux__) || defined(__APPLE__)

#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#elif defined(_WIN32)
#include <winsock.h>
#include <winsock2.h>
#include <windows.h>
#include<ws2tcpip.h>
#endif

#define SERVER_PORT 18888
#define KGC_SERVER_PORT 18888
#define SATELLITE_SERVER_PORT 15555
#define SATELLITE_BATCH_SERVER_PORT 15556
#define UE_SERVER_PORT 16666

#define  G1_len 128
#define  Zr_len 20

#define CONN_QUEUE_LEN 20

#define SOCKET_BUFFER_LEN 2048

typedef unsigned char byte;

int auth_accept(int fd, sockaddr_in &clientAddr);

int auth_listen(unsigned short port);

int auth_connect(const std::string &addr, unsigned short port);

void auth_close(int fd);

int auth_send(const int &socket, int num_G1, int num_Zr, element_t *G1, element_t *Zr);

int auth_recv(int socket, int &G1_num, int &Zr_num, element_t **G1_p, element_t **Zr_p, pairing_t &pairing);

#endif //UNTITLED_SOCKET_H
