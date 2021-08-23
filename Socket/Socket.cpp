#include "Socket.h"

#include <ctime>
#include <cstring>
#include <iostream>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <cerrno>
#include <unistd.h>

/// Access Auth listen on the default port and accept all the connect request.
/// \param port The port to be listened on
/// \return The socket file description.
int auth_listen(unsigned short port) {
    int fd;
    struct sockaddr_in server_addr, clientAddr;
    int addr_len = sizeof(clientAddr);

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creating error:");
        return -1;
    }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("Socket binding error:");
        return -1;
    }
    if (listen(fd, CONN_QUEUE_LEN) < 0) {
        perror("Socket listening:");
        return -1;
    }
    printf("Listen success! The listening port is: %d\n", port);
    return fd;
}

/// Socket accept for access auth.
/// \param fd The file description of the listen socket.
/// \param clientAddr The information of the client.
/// \return -1 as failure or the new socket description
int auth_accept(int fd, sockaddr_in &clientAddr) {
    int client;
    int addr_len = sizeof(clientAddr);
    client = accept(fd, (struct sockaddr *) &clientAddr, (socklen_t *) &addr_len);
    if (client < 0) {
        perror("Socket accept:");
        return -1;
    }
    printf("New Connection Established.\n");
    printf("Client's IP is %s\t", inet_ntoa(clientAddr.sin_addr));
    printf("Client's Port is %d\n", htons(clientAddr.sin_port));
    return client;
}

/// Access Auth to specific addr.
/// \param addr The string of the addr in ipv4.
/// \return -1 as error or new socket description.
int auth_connect(const std::string &addr, unsigned short port) {
    struct sockaddr_in serverAddr;
    int clientSocket;
    if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creating:");
        return -1;
    }
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);

    serverAddr.sin_addr.s_addr = inet_addr(addr.c_str());
    if (connect(clientSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) < 0) {
        perror("Socket connecting:");
        return -1;
    }
    printf("Connecting... success\n");
    return clientSocket;
}


//// Close the file description.
void auth_close(int fd) {
    close(fd);
    printf("The socket description %d CLOSED.\n", fd);
}


/// 功能 发送一串点和数字
/// \param socket   client的名字
/// \param num_G1      准备发送的点的数量
/// \param num_Zr     准备发送的数的数量
/// \param G1          点存放的数组
/// \param Zr         数字存放数组
/// \return -1 as error or return sent data length
int auth_send(const int &socket, int num_G1, int num_Zr, element_t *G1, element_t *Zr) {
    int len = 0;
    byte *buf_pointer;
    byte send_buf[SOCKET_BUFFER_LEN];
    ///initialize send buffer
    memset(send_buf, 0, SOCKET_BUFFER_LEN);
    buf_pointer = send_buf;  ////指向sendbuf的指针，可以通过这个指针来对sendbuf进行修改

    ////assemble all G1 element to string
    send_buf[0] = (unsigned char) num_G1;
    buf_pointer++;
    for (int i = 0; i < num_G1; i++) {
#ifdef DEBUG
        element_printf("Sending %d G1……%B\t",i,G1[i]);
#endif
        element_to_bytes(buf_pointer, G1[i]);
        buf_pointer += G1_len;
    }
    ////assemble all Zr element to string
    *buf_pointer = (unsigned char) num_Zr;
    buf_pointer++;
    for (int i = 0; i < num_Zr; i++) {
#ifdef DEBUG
        element_printf("Sending %d Zr……%B\t",i,Zr[i]);
#endif
        element_to_bytes(buf_pointer, Zr[i]);
        buf_pointer += Zr_len;
    }
    len = send(socket, send_buf, num_G1 * G1_len + num_Zr * Zr_len + 2, 0);
    if (len < 0) {
        perror("Socket send error:");
        return -1;
    }
    return len;
}

/// 功能：  接受一串字节流，然后将其点们读取point_p中，将数们读取到num_p中
/// \param socket     Socket的标识符
/// \param G1_num        返回值   返回收取的点的个数
/// \param Zr_num       返回值   返回收取的数字的个数
/// \param G1_p          返回值   返回收取的点的数组
/// \param Zr_p            返回值   返回收取的数字的数组
/// \return -1 as error or 0 as success
int auth_recv(int socket, int &G1_num, int &Zr_num, element_t **G1_p, element_t **Zr_p, pairing_t &pairing) {
    unsigned char recv_buf[2048];
    element_t zero;
    element_init_G1(zero, pairing);
    element_set0(zero);
    memset(recv_buf, 0, 2048);
    int len = 0;
    ////get the number of point
    len = recv(socket, recv_buf, 1, 0);
    if (len != 1) {
        perror("recv error:");
        return -1;
    }
    ////read all points from buffer
    G1_num = recv_buf[0];
    len = recv(socket, recv_buf, G1_num * G1_len, 0);
    if (len != G1_num * G1_len) {
        perror("recv G1 error");
        return -1;
    }
    if (G1_num > 0) {
        *G1_p = (element_t *) malloc(G1_num * sizeof(element_t));
        byte *point_pointer = recv_buf;
        for (int i = 0; i < G1_num; i++) {
            element_init_G1((*G1_p)[i], pairing);
            len = element_from_bytes((*G1_p)[i], point_pointer);
            if (!element_cmp((*G1_p)[i], zero)) {
                element_set0((*G1_p)[i]);
            }
#ifdef DEBUG
            element_printf("Receiving %d G1……%B\t",i,(*G1_p)[i]);
#endif
            point_pointer += G1_len;
        }
    } else
        *G1_p = nullptr;

    len = recv(socket, recv_buf, 1, 0);
    if (len != 1) {
        perror("recv error");
        return -1;
    }
    ////read all numbers from buffer
    Zr_num = recv_buf[0];
    len = recv(socket, recv_buf, Zr_num * Zr_len, 0);
    if (len != Zr_num * Zr_len) {
        perror("recv points error");
        return -1;
    }
    if (Zr_num > 0) {
        *Zr_p = (element_t *) malloc(Zr_num * sizeof(element_t));
        byte *number_pointer = recv_buf;
        for (int i = 0; i < Zr_num; i++) {
            element_init_Zr((*Zr_p)[i], pairing);
            len = element_from_bytes((*Zr_p)[i], number_pointer);
#ifdef DEBUG
            element_printf("Receiving %d Zr……%B\t",i,(*Zr_p)[i]);
#endif
            number_pointer += Zr_len;
        }
    } else
        *Zr_p = nullptr;
    element_clear(zero);
    return 0;
}
