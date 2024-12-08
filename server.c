#include "consts.h"
#include "sec.h"
#include "transport.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: server <port>\n");
        exit(1);
    }

    /* Create sockets */
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    // use IPv4  use UDP

    /* Construct our address */
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET; // use IPv4
    server_addr.sin_addr.s_addr =
        INADDR_ANY; // accept all connections
                    // same as inet_addr("0.0.0.0")
                    // "Address string to network bytes"
    // Set receiving port
    int PORT = atoi(argv[1]);
    server_addr.sin_port = htons(PORT); // Big endian

    /* Let operating system know about our config */
    int did_bind =
        bind(sockfd, (struct sockaddr*) &server_addr, sizeof(server_addr));

    struct sockaddr_in client_addr; // Same information, but about client
    socklen_t s = sizeof(struct sockaddr_in);
    char buffer;

    // Wait for client connection
    while (1) {
        int bytes_recvd = recvfrom(sockfd, &buffer, sizeof(buffer), MSG_PEEK,
                                   (struct sockaddr*) &client_addr, &s);
        if (bytes_recvd > 0)
            break;
    }

    init_sec(SERVER_CLIENT_HELLO_AWAIT);
    listen_loop(sockfd, &client_addr, SERVER_AWAIT, input_sec, output_sec);

    return 0;
}
