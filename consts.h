#pragma once

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

// Maximum payload size
#define MAX_PAYLOAD 1012

// Retransmission time
#define TV_DIFF(end, start)                                                    \
    (end.tv_sec * 1000000) - (start.tv_sec * 1000000) + end.tv_usec -          \
        start.tv_usec
#define RTO 1000000

// Window size
#define MAX_WINDOW 20 * MAX_PAYLOAD
#define DUP_ACKS 3

// States
#define SERVER_AWAIT 0
#define CLIENT_START 1
#define SERVER_SYN 2
#define ClIENT_AWAIT 3
#define SERVER_AWAIT_2 4
#define CLIENT_AWAIT_2 5
#define NORMAL 6

// Security states
#define SERVER_CLIENT_HELLO_AWAIT 0
#define CLIENT_CLIENT_HELLO_SEND 1
#define SERVER_SERVER_HELLO_SEND 2
#define CLIENT_SERVER_HELLO_AWAIT 3
#define SERVER_KEY_EXCHANGE_REQUEST_AWAIT 4
#define CLIENT_KEY_EXCHANGE_REQUEST_SEND 5
#define SERVER_FINISHED_SEND 6
#define CLIENT_FINISHED_AWAIT 7
#define DATA_STATE 8

// Security sizes
#define NONCE_SIZE 32
#define SECRET_SIZE 32
#define MAC_SIZE 32
#define IV_SIZE 16
#define PLAINTEXT_OFFSET (12 + IV_SIZE + MAC_SIZE)

// Security types
#define CLIENT_HELLO 0x00
#define NONCE_CLIENT_HELLO 0x01

#define CERTIFICATE 0xA0
#define PUBLIC_KEY 0xA1
#define SIGNATURE 0xA2

#define SERVER_HELLO 0x10
#define NONCE_SERVER_HELLO 0x11
#define NONCE_SIGNATURE_SERVER_HELLO 0x12

#define KEY_EXCHANGE_REQUEST 0x20
#define NONCE_SIGNATURE_KEY_EXCHANGE_REQUEST 0x22

#define FINISHED 0x30

#define DATA 0x40
#define INITIALIZATION_VECTOR 0x41
#define CIPHERTEXT 0x42
#define MESSAGE_AUTHENTICATION_CODE 0x43

// Diagnostic messages
#define RECV 0
#define SEND 1
#define RTOD 2
#define DUPA 3

// Structs
typedef struct {
    uint32_t ack;
    uint32_t seq;
    uint16_t length;
    uint8_t flags; // LSb 0 SYN, LSb 1 ACK
    uint8_t unused;
    uint8_t payload[0];
} packet;

struct buffer_node {
    struct buffer_node* next;
    packet pkt;
} typedef buffer_node;

// Helpers
static inline void print(char* txt) { fprintf(stderr, "%s\n", txt); }

static inline void print_diag(packet* pkt, int diag) {
    switch (diag) {
    case RECV:
        fprintf(stderr, "RECV");
        break;
    case SEND:
        fprintf(stderr, "SEND");
        break;
    case RTOD:
        fprintf(stderr, "RTOS");
        break;
    case DUPA:
        fprintf(stderr, "DUPS");
        break;
    }

    bool syn = pkt->flags & 0b01;
    bool ack = pkt->flags & 0b10;
    fprintf(stderr, " %u ACK %u SIZE %hu FLAGS ", ntohl(pkt->seq),
            ntohl(pkt->ack), ntohs(pkt->length));
    if (!syn && !ack) {
        fprintf(stderr, "NONE");
    } else {
        if (syn) {
            fprintf(stderr, "SYN ");
        }
        if (ack) {
            fprintf(stderr, "ACK ");
        }
    }
    fprintf(stderr, "\n");
}

static inline void print_buf(buffer_node* node) {
    fprintf(stderr, "BUF ");

    while (node != NULL) {
        fprintf(stderr, "%u ", htonl(node->pkt.seq));
        node = node->next;
    }
    fprintf(stderr, "\n");
}

static inline void print_hex(uint8_t* buf, size_t len) {
    for (int i = 0; i < len; i++) {
        fprintf(stderr, "%02x ", *(buf + i));
    }
    fprintf(stderr, "\n");
}

#define MIN(a, b) (a < b) ? a : b
static inline void print_tlv(uint8_t* buffer, size_t len) {
    uint8_t* buf = buffer;

    while (buf - buffer < len) {
        uint8_t type = *buf;
        fprintf(stderr, "Type: 0x%02x\n", type);
        buf += 1;
        if (buf - buffer >= len)
            return;

        uint16_t length = ntohs(*((uint16_t*) buf));
        buf += 2;
        fprintf(stderr, "Length: %hu\n", length);

        if (type == CLIENT_HELLO || type == SERVER_HELLO ||
            type == KEY_EXCHANGE_REQUEST || type == FINISHED ||
            type == CERTIFICATE || type == DATA)
            continue;
        else {
            uint16_t min_length = MIN(len - (buf - buffer), length);
            print_hex(buf, min_length);
            buf += min_length;
        }
    }
}