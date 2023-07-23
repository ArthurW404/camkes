/*
 * Copyright 2019, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <camkes.h>
#include <autoconf.h>
#include <stdio.h>
#include <string.h>
#include <picoserver.h>
#include <assert.h>
#include <echo_listener_common.h>
#include <arpa/inet.h>

#define WHOAMI "100 IPBENCH V1.0\n"
#define HELLO "HELLO\n"
#define OK_READY "200 OK (Ready to go)\n"
#define LOAD "LOAD cpu_target_lukem\n"
#define OK "200 OK\n"
#define SETUP "SETUP args::\"\"\n"
#define START "START\n"
#define STOP "STOP\n"
#define QUIT "QUIT\n"
#define RESPONSE "220 VALID DATA (Data to follow)\n" \
                 "Content-length: %d\n" \
                 "%s\n"
#define IDLE_FORMAT ",%ld,%ld"
#define msg_match(msg, match) (strncmp(msg, match, strlen(match))==0)

extern void *echo_send_buf;
extern void *echo_recv_buf;

int listener_socket = 0;
int socket_in;
int utiliz_socket;
int peer_socket = -1;



seL4_CPtr echo_control_notification();

static handle_tcp_echo_notification(uint16_t events, int socket) {
    char ip_string[16] = {0};
    int ret = 0;
    if (events & PICOSERVER_CONN) {
        if (socket != listener_socket) {
            picoserver_peer_t peer = echo_control_accept(socket);
            if (peer.result == -1) {
                assert(!"Failed to accept a peer");
            }
            pico_ipv4_to_string(ip_string, peer.peer_addr);
            printf("%s: Connection established with %s on socket %d\n", get_instance_name(), ip_string, socket);
        }
    }
    if (events & PICOSERVER_READ) {
        printf("%s: Received a message on socket %d, going to echo to Listener\n", get_instance_name(), socket);
        ret = echo_recv_recv(socket, 4096, 0);
        strncpy(echo_send_buf, echo_recv_buf, ret);
        ret = echo_send_send(socket, strlen(echo_send_buf), 0);
        memset(echo_recv_buf, 0, 4096);
        memset(echo_send_buf, 0, 4096);
    }
    if (events & PICOSERVER_CLOSE) {
        ret = echo_control_shutdown(socket, PICOSERVER_SHUT_RDWR);
        printf("%s: Connection closing on socket %d\n", get_instance_name(), socket);
    }
    if (events & PICOSERVER_FIN) {
        printf("%s: Connection closed on socket %d\n", get_instance_name(), socket);
    }
    if (events & PICOSERVER_ERR) {
        printf("%s: Error with socket %d, going to die\n", get_instance_name(), socket);
        assert(0);
    }
}

static void handle_tcp_utiliz_notification(uint16_t events, int socket) {
    int ret = 0;
    char ip_string[16] = {0};

    if (events & PICOSERVER_CONN) {
        picoserver_peer_t peer = echo_control_accept(socket);
        if (peer.result == -1) {
            ZF_LOGF("Failed to accept a peer");
        }
        peer_socket = peer.socket;
        inet_ntop(AF_INET, &peer.peer_addr, ip_string, 16);
        printf("%s: Connection established with %s on socket %d\n", get_instance_name(), ip_string, socket);

        memcpy(echo_send_buf, WHOAMI, strlen(WHOAMI));
        echo_send_send(peer_socket, strlen(WHOAMI), 0);
        
    }

    if (events & PICOSERVER_READ) {
        ret = echo_recv_recv(socket, 0x1000, 0);
        if (ret == -1) {
            printf("received -1\n");
        } else if (ret == 0) {
            printf("Error\n");
        }
        if (msg_match(echo_recv_buf, HELLO)) {
            memcpy(echo_send_buf, OK_READY, strlen(OK_READY));
            echo_send_send(socket, strlen(OK_READY), 0);
        } else if (msg_match(echo_recv_buf, LOAD)) {
            memcpy(echo_send_buf, OK, strlen(OK));
            echo_send_send(socket, strlen(OK), 0);
        } else if (msg_match(echo_recv_buf, SETUP)) {
            memcpy(echo_send_buf, OK, strlen(OK));
            echo_send_send(socket, strlen(OK), 0);
        } else if (msg_match(echo_recv_buf, START)) {
            // idle_start();
        } else if (msg_match(echo_recv_buf, STOP)) {
            uint64_t total, kernel, idle;
            // idle_stop(&total, &kernel, &idle);
            char *util_msg;
            int len = asprintf(&util_msg, IDLE_FORMAT, idle, total);
            if (len == -1) {
                ZF_LOGE("asprintf: Failed to print string");
            } else {
                len = snprintf(echo_send_buf, 0x1000, RESPONSE, len + 1, util_msg);
                if (len == -1) {
                    ZF_LOGE("asprintf: Failed to print string");
                } else {
                    echo_send_send(socket, len, 0);
                }
                free(util_msg);
            }
            echo_control_shutdown(socket, PICOSERVER_SHUT_RDWR);
        } else if (msg_match(echo_recv_buf, QUIT)) {
        } else {
            printf("Couldn't match message: %s\n", (char *)echo_recv_buf);
        }

        memset(echo_recv_buf, 0, 4096);
        memset(echo_send_buf, 0, 4096);

    }

    if (events & PICOSERVER_CLOSE) {
        ret = echo_control_shutdown(socket, PICOSERVER_SHUT_RDWR);
        printf("%s: Connection closing on socket %d\n", get_instance_name(), socket);
    }
    if (events & PICOSERVER_FIN) {
        printf("%s: Connection closed on socket %d\n", get_instance_name(), socket);
        peer_socket = -1;
    }
    if (events & PICOSERVER_ERR) {
        printf("%s: Error with socket %d, going to die\n", get_instance_name(), socket);
    }
}


void handle_picoserver_notification(void)
{
    picoserver_event_t server_event = echo_control_event_poll();
    int socket = 0;
    uint16_t events = 0;

    while (server_event.num_events_left > 0 || server_event.events) {
        socket = server_event.socket_fd;
        events = server_event.events;

        if (socket == utiliz_socket  || socket == peer_socket) {
            handle_tcp_utiliz_notification(events, socket);
            server_event = echo_control_event_poll();
        } else {
        // } else if (socket == socket_in) {
            handle_tcp_echo_notification(events, socket);
            server_event = echo_control_event_poll();
        }
        //  else {
        //     ZF_LOGE("Got event for socket: %d but no registered handler", socket);
        // }
        server_event = echo_control_event_poll();
    }
}


static int setup_utilization_socket()
{
    utiliz_socket = echo_control_open(false);
    if (utiliz_socket == -1) {
        ZF_LOGE("Failed to open a socket for listening!");
        return -1;
    }

    int ret = echo_control_bind(utiliz_socket, PICOSERVER_ANY_ADDR_IPV4, UTILIZATION_PORT);
    if (ret) {
        ZF_LOGE("Failed to bind a socket for listening!");
        return ret;
    }

    ret = echo_control_listen(utiliz_socket, 1);
    if (ret) {
        ZF_LOGE("Failed to listen for incoming connections!");
        return ret;
    }

    return 0;

}


int run(void)
{
    printf("%s instance starting up, going to be listening on %s:%d\n",
           get_instance_name(), ip_addr, ECHO_PORT);

    socket_in = echo_control_open(false);
    if (socket_in == -1) {
        assert(!"Failed to open a socket for listening!");
    }

    listener_socket = echo_control_open(false);
    if (listener_socket == -1) {
        assert(!"Failed to open a socket for echoing!");
    }

    int ret = echo_control_bind(socket_in, PICOSERVER_ANY_ADDR_IPV4, ECHO_PORT);
    if (ret) {
        assert(!"Failed to bind a socket for listening!");
    }

    ret = echo_control_listen(socket_in, 1);
    if (ret) {
        assert(!"Failed to listen for incoming connections!");
    }

    ret = setup_utilization_socket();
    if (ret) {
        assert("Utilization socket failed\n");
    } else {
        printf("Util soc success\n");
    }
    // uint32_t ip = 0;
    // pico_string_to_ipv4(ip_addr, &ip);
    // ret = echo_control_connect(listener_socket, ip, LISTENER_PORT);
    // if (ret) {
    //     assert(!"Failed to connect to the listener!");
    // }

    /* Now poll for events and handle them */
    seL4_Word badge;

    while (1) {
        seL4_Wait(echo_control_notification(), &badge);
        handle_picoserver_notification();
    }
}
