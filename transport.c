#include "consts.h"
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/time.h>
#include <unistd.h>

int state = 0;           // Current state for handshake
int window = 0;          // Total number of bytes in sending window
int dup_acks = 0;        // Duplicate acknowledgements received
uint32_t ack = 0;        // Acknowledgement number
uint32_t seq = 0;        // Sequence number
uint32_t last_ack = 0;   // Last ACK number to keep track of duplicate ACKs
bool force_ack = false;  // Require ACK to be sent out
packet* base_pkt = NULL; // Minimum packet to be sent out

buffer_node* recv_buf =
    NULL; // Linked list storing out of order received packets
buffer_node* send_buf =
    NULL; // Linked list storing packets that were sent but not acknowledged

ssize_t (*input)(uint8_t*, size_t); // Get data from layer
void (*output)(uint8_t*, size_t);   // Output data from layer

struct timeval start; // Last packet sent at this time
struct timeval now;   // Temp for current time

// On ACK receipt, clear all in send buffer that are less than
void clear_send_buf(uint32_t other_ack) {
    buffer_node* prev_node = NULL;
    buffer_node* node = send_buf;

    while (node != NULL) {
        // Other side acknowledged
        if (ntohl(node->pkt.seq) < other_ack) {
            if (prev_node)
                prev_node->next = node->next;
            else
                send_buf = node->next;
            window -= ntohs(node->pkt.length);
            free(node);
            prev_node = NULL;
            node = send_buf;
        } else {
            prev_node = node;
            node = node->next;
        } 
    }

    // Recompute base packet
    buffer_node* min_node = send_buf;
    node = send_buf;
    
    while (node != NULL) {
        if (ntohl(node->pkt.seq) < ntohl(min_node->pkt.seq)) {
            min_node = node;
        }
        node = node->next;
    }
    base_pkt = min_node != NULL ? &min_node->pkt : NULL;

    print_buf(send_buf);
}

// Clear recv buf to write out sequential packets
void clear_recv_buf() {
    bool found = false;
    // Until no more found ACKs
    do {
        found = false;
        buffer_node* prev_node = NULL;
        buffer_node* node = recv_buf;
        // Iterate over linked list
        while (node != NULL) {
            // If found packet with next expected
            if (ntohl(node->pkt.seq) == ack) {
                found = true;

                // Set ACK to next expected
                uint32_t sack = ntohl(node->pkt.seq) + ntohs(node->pkt.length);
                if (sack > ack)
                    ack = sack;

                // Skip over this node
                if (prev_node) {
                    prev_node->next = node->next;
                } else {
                    recv_buf = node->next;
                }

                // Output contents
                output(node->pkt.payload, ntohs(node->pkt.length));

                // Remove node from memory
                free(node);
                break;
            }
            prev_node = node;
            node = node->next;
        }
    } while (found);
}

// Push packet to buffer
packet* push(buffer_node** buf, packet* pkt) {
    size_t s = ntohs(pkt->length);
    buffer_node* new_node = malloc(sizeof(buffer_node) + s);
    memset(new_node, 0, sizeof(buffer_node) + s);
    memcpy(&new_node->pkt, pkt, sizeof(packet) + s);

    if (*buf == NULL) {
        *buf = new_node;
    } else {
        buffer_node* cur = (*buf);
        while (true) {
            if (cur->next == NULL) {
                cur->next = new_node;
                break;
            } else {
                cur = cur->next;
            }
        }
    }

    if (buf == &send_buf) {
        clear_send_buf(0);
    }

    return &new_node->pkt;
}

// Set ACK in packet to current ACK
void set_ack_packet(packet* pkt) {
    if (state != NORMAL)
        return;
    pkt->flags = pkt->flags | 0b10; // Set ACK flag
    pkt->ack = htonl(ack);
}

// Get data from standard input / make handshake packets
packet* get_data() {
    switch (state) {
    case SERVER_AWAIT:
        return NULL;
    case CLIENT_START: {
        packet pkt = {0};
        pkt.flags = 0b01; // SYN
        pkt.seq = htonl(seq);
        seq++;
        state = ClIENT_AWAIT;
        return push(&send_buf, &pkt);
    }
    case SERVER_SYN: {
        packet pkt = {0};
        pkt.flags = 0b11; // SYN ACK
        pkt.seq = htonl(seq);
        seq++;
        pkt.ack = htonl(ack);
        state = SERVER_AWAIT_2;
        return push(&send_buf, &pkt);
    }
    case ClIENT_AWAIT:
        return NULL;
    case SERVER_AWAIT_2:
        return NULL;
    case CLIENT_AWAIT_2:
    default: {
        // Get rest of window or max payload
        uint16_t length = MAX_WINDOW - window < MAX_PAYLOAD
                              ? MAX_WINDOW - window
                              : MAX_PAYLOAD;
        if (length <= 0)
            return NULL;

        // Get data from layer
        char buffer[sizeof(packet) + MAX_PAYLOAD] = {0};
        packet* pkt = (packet*) &buffer;
        length = input(pkt->payload, length);
        if (length <= 0 && state != CLIENT_AWAIT_2)
            return NULL;

        // Return packet
        set_ack_packet(pkt);
        pkt->seq = htonl(seq);
        pkt->length = htons(length);
        window += length;
        seq += length == 0 && state == CLIENT_AWAIT_2 ? 1 : length;
        state = NORMAL;
        return push(&send_buf, pkt);
    }
    }
}

// Process data received from socket
void recv_data(packet* pkt) {
    switch (state) {
    case SERVER_AWAIT: {
        // If not a handshake packet, drop
        if (!(pkt->flags & 0b01))
            break;
        ack = ntohl(pkt->seq) + 1;
        state = SERVER_SYN;
    }
    case CLIENT_START:
        break;
    case SERVER_SYN:
        break;
    case ClIENT_AWAIT: {
        // If not a handshake packet, drop
        if (!(pkt->flags & 0b11))
            break;
        ack = ntohl(pkt->seq) + 1;
        clear_send_buf(ntohl(pkt->ack));
        state = CLIENT_AWAIT_2;
        break;
    }
    case SERVER_AWAIT_2:
        state = NORMAL;
        force_ack = true;
        if (pkt->length == 0)
            ack = ntohl(pkt->seq) + 1;
    default: {
        // If ACK flag set
        if (pkt->flags & 0b10) {
            uint32_t other_ack = ntohl(pkt->ack);
            if (other_ack == last_ack)
                dup_acks++;
            else
                last_ack = other_ack;
            clear_send_buf(other_ack);
        }

        // If data in packet, must send ACK
        if (htons(pkt->length) > 0) {
            force_ack = true;
        }

        push(&recv_buf, pkt);
        clear_recv_buf();
    }
    }
}

// Main function of transport layer; never quits
void listen_loop(int sockfd, struct sockaddr_in* addr, int initial_state,
                 ssize_t (*input_p)(uint8_t*, size_t),
                 void (*output_p)(uint8_t*, size_t)) {

    // Set initial state (whether client or server)
    state = initial_state;

    // Set input and output function pointers
    input = input_p;
    output = output_p;

    // Set socket for nonblocking
    int flags = fcntl(sockfd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(sockfd, F_SETFL, flags);

    // Set initial sequence number
    uint32_t r;
    int rfd = open("/dev/urandom", 'r');
    read(rfd, &r, sizeof(uint32_t));
    close(rfd);
    srand(r);
    seq = (rand() % 10) * 1000000;
    /* seq = initial_state == SERVER_AWAIT ? 1000000 : 2000000; */

    // Setting timers
    gettimeofday(&now, NULL);
    gettimeofday(&start, NULL);

    // Create buffer for incoming data
    char buffer[sizeof(packet) + MAX_PAYLOAD] = {0};
    packet* pkt = (packet*) &buffer;
    socklen_t addr_size = sizeof(struct sockaddr_in);

    // Start listen loop
    while (true) {
        // Get data from socket
        int bytes_recvd = recvfrom(sockfd, &buffer, sizeof(buffer), 0,
                                   (struct sockaddr*) addr, &addr_size);
        // If data, process it
        if (bytes_recvd > 0) {
            print_diag(pkt, RECV);
            recv_data(pkt);
        }

        packet* tosend = get_data();
        // Data available to send
        if (tosend != NULL) {
            set_ack_packet(tosend);
            print_diag(tosend, SEND);
            sendto(sockfd, tosend, sizeof(packet) + ntohs(tosend->length), 0,
                   (struct sockaddr*) addr, sizeof(struct sockaddr_in));
        }
        // Received a packet and must send an ACK
        else if (force_ack) {
            packet tosend = {0};
            set_ack_packet(&tosend);
            print_diag(&tosend, SEND);
            sendto(sockfd, &tosend, sizeof(packet), 0, (struct sockaddr*) addr,
                   sizeof(struct sockaddr_in));
        }
        force_ack = false;

        // Check if timer went off
        gettimeofday(&now, NULL);
        if (TV_DIFF(now, start) >= RTO && base_pkt != NULL) {
            set_ack_packet(base_pkt);
            print_diag(base_pkt, RTOD);
            sendto(sockfd, base_pkt, sizeof(packet) + ntohs(base_pkt->length),
                   0, (struct sockaddr*) addr, sizeof(struct sockaddr_in));
            gettimeofday(&start, NULL);

        }
        // Duplicate ACKS detected
        else if (dup_acks == DUP_ACKS && base_pkt != NULL) {
            dup_acks = 0;
            set_ack_packet(base_pkt);
            print_diag(base_pkt, DUPA);
            sendto(sockfd, base_pkt, sizeof(packet) + ntohs(base_pkt->length),
                   0, (struct sockaddr*) addr, sizeof(struct sockaddr_in));

        }
        // No data to send, so restart timer
        else if (base_pkt == NULL) {
            gettimeofday(&start, NULL);
        }
    }
}
