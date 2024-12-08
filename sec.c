#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "consts.h"
#include "io.h"
#include "security.h"

int state_sec = 0;              // Current state for handshake
uint8_t nonce[NONCE_SIZE];      // Store generated nonce to verify signature
uint8_t peer_nonce[NONCE_SIZE]; // Store peer's nonce to sign

#define MAX_PUBKEYSIGN_SIZE 72

void init_sec(int initial_state) {
    state_sec = initial_state;
    init_io();

    if (state_sec == CLIENT_CLIENT_HELLO_SEND) {
        generate_private_key();
        derive_public_key();
        derive_self_signed_certificate();
        load_ca_public_key("ca_public_key.bin");
    } else if (state_sec == SERVER_CLIENT_HELLO_AWAIT) {
        load_certificate("server_cert.bin");
        load_private_key("server_key.bin");
        derive_public_key();
    }
    
    generate_nonce(nonce, NONCE_SIZE);
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    ssize_t packet_length = 0;
    switch (state_sec) {
    case CLIENT_CLIENT_HELLO_SEND: {
        print("SEND CLIENT HELLO");
        packet_length = 38;
        if (max_length < packet_length)
            return 0;
        buf[0] = 0;
        buf[1] = (35 >> 8) & 0xFF;
        buf[2] = 35 & 0xFF;
        buf[3] = 0x01;
        buf[4] = (32 >> 8) & 0xFF;
        buf[5] = 32 & 0xFF;
        memcpy(buf+6, nonce, NONCE_SIZE);
        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        return packet_length;
    }
    case SERVER_SERVER_HELLO_SEND: {
        print("SEND SERVER HELLO");
        print(peer_nonce);
        // Calculate lengths
        uint8_t sign_buf[MAX_PUBKEYSIGN_SIZE];
        uint8_t nonce_sign_buf[MAX_PUBKEYSIGN_SIZE];
        ssize_t sign_length = sign(public_key, pub_key_size, sign_buf);
        ssize_t nonce_sign_length = sign(peer_nonce, NONCE_SIZE, nonce_sign_buf);
        // ssize_t cert_length = 6 + pub_key_size + sign_length;
        packet_length = 41 + cert_size + nonce_sign_length;

        if (max_length < packet_length+3)
            return 0;
        
        // Server hello
        buf[0] = SERVER_HELLO;
        buf[1] = (packet_length >> 8) & 0xFF;
        buf[2] = packet_length & 0xFF;
        // Nonce
        buf[3] = NONCE_SERVER_HELLO;
        buf[4] = (32 >> 8) & 0xFF;
        buf[5] = 32 & 0xFF;
        memcpy(buf+6, nonce, NONCE_SIZE);
        // Certificate
        memcpy(buf+38, certificate, cert_size);
        // Nonce signature
        buf[41+cert_size-3] = NONCE_SIGNATURE_SERVER_HELLO;
        buf[41+cert_size-3+1] = (nonce_sign_length >> 8) & 0xFF;
        buf[41+cert_size-3+2] = nonce_sign_length & 0xFF;
        memcpy(buf+41+cert_size-3+3, nonce_sign_buf, nonce_sign_length);
        
        state_sec = SERVER_KEY_EXCHANGE_REQUEST_AWAIT;
        print_tlv(buf, packet_length);
        return packet_length+3;
    }
    case CLIENT_KEY_EXCHANGE_REQUEST_SEND: {
        print("SEND KEY EXCHANGE REQUEST");

        print_hex(peer_nonce, 32);
        uint8_t nonce_sign_buf[MAX_PUBKEYSIGN_SIZE];
        ssize_t nonce_sign_length = sign(peer_nonce, NONCE_SIZE, nonce_sign_buf);
        packet_length = 6 + cert_size + nonce_sign_length;
        if (max_length < packet_length)
            return 0;
        buf[0] = KEY_EXCHANGE_REQUEST;
        buf[1] = (packet_length-3 >> 8) & 0xFF;
        buf[2] = (packet_length-3) & 0xFF;
        // Certificate
        memcpy(buf+3, certificate, cert_size);
        // Sign server nonce
        derive_keys();
        buf[3+cert_size] = NONCE_SIGNATURE_KEY_EXCHANGE_REQUEST;
        buf[4+cert_size] = (nonce_sign_length >> 8) & 0xFF;
        buf[5+cert_size] = nonce_sign_length & 0xFF;
        memcpy(buf+6+cert_size, nonce_sign_buf, nonce_sign_length);

        state_sec = CLIENT_FINISHED_AWAIT;
        print_tlv(buf, packet_length);
        return packet_length;
    }
    case SERVER_FINISHED_SEND: {
        print("SEND FINISHED");

        derive_keys();
        buf[0] = FINISHED;
        buf[1] = 0;
        buf[2] = 0;

        state_sec = DATA_STATE;
        return 3;
    }
    case DATA_STATE: {
        uint8_t in_buf[943];
        ssize_t bytes_read = input_io(in_buf, 500);
        if (bytes_read>0) {
            print("HERE");
            buf[0] = DATA;
            buf[3] = INITIALIZATION_VECTOR;
            buf[4] = (16 >> 8) & 0xFF;
            buf[5] = 16 & 0xFF;
            buf[22] = CIPHERTEXT;
            uint16_t cipher_size = encrypt_data(in_buf, bytes_read, buf+6, buf+25);
            buf[23] = (cipher_size >> 8) & 0xFF;
            buf[24] = cipher_size & 0xFF;
            buf[25+cipher_size] = MESSAGE_AUTHENTICATION_CODE;
            buf[26+cipher_size] = (32 >> 8) & 0xFF;
            buf[27+cipher_size] = 32 & 0xFF;
            uint8_t ivcipher[1000];
            memcpy(ivcipher, buf+6, 16);
            memcpy(ivcipher+16, buf+25, cipher_size);
            hmac(ivcipher, 16+cipher_size, buf+28+cipher_size);
            packet_length = 57+cipher_size;
            buf[1] = (packet_length >> 8) & 0xFF;
            buf[2] = packet_length & 0xFF;

            // PT refers to the amount you read from stdin in bytes
            // CT refers to the resulting ciphertext size
            fprintf(stderr, "SEND DATA PT %ld CT %lu\n", bytes_read, cipher_size);
            return packet_length+3;
        }
    }
    default:
        return 0;
    }
}

void output_sec(uint8_t* buf, size_t length) {
    switch (state_sec) {
    case SERVER_CLIENT_HELLO_AWAIT: {
        if (*buf != CLIENT_HELLO)
            exit(4);
        print("RECV CLIENT HELLO");
        if (length < 38) {
            fprintf(stderr, "Received client hello packet of size less than expected: %d", length);
            break;
        }
        memcpy(peer_nonce, buf+6, 32);

        state_sec = SERVER_SERVER_HELLO_SEND;
        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT: {
        if (*buf != SERVER_HELLO)
            exit(4);

        print("RECV SERVER HELLO");
        uint16_t packet_len = (buf[1] << 8) | (buf[2] & 0xFF);
        print_tlv(buf, packet_len + 3);
        // Verify certificate
        uint16_t pubkey_len = (buf[42] << 8) | buf[43];
        uint8_t pubkey[91];
        memcpy(pubkey, buf+44, pubkey_len);
        uint16_t pubkeysign_len = (buf[45+pubkey_len] << 8) | buf[46+pubkey_len];
        int verified = verify(pubkey, pubkey_len, buf+47+pubkey_len, pubkeysign_len, ec_ca_public_key);
        if (verified != 1) {
            fprintf(stderr, "Failed to verify, exit status 1.\n");
            exit(1);
        }
        load_peer_public_key(pubkey, pubkey_len);
        derive_secret();
        // Verify nonce
        size_t servnoncesign_len = (buf[48+pubkey_len+pubkeysign_len] << 8) | buf[49+pubkey_len+pubkeysign_len];
        verified = verify(nonce, NONCE_SIZE, buf+50+pubkey_len+pubkeysign_len, servnoncesign_len, ec_peer_public_key);
        if (verified != 1) {
            fprintf(stderr, "Failed to verify, exit status 2- code %d.\n", verified);
            exit(2);
        }
        memcpy(peer_nonce, buf+6, 32);

        state_sec = CLIENT_KEY_EXCHANGE_REQUEST_SEND;
        
        break;
    }
    case SERVER_KEY_EXCHANGE_REQUEST_AWAIT: {
        if (*buf != KEY_EXCHANGE_REQUEST)
            exit(4);

        print("RECV KEY EXCHANGE REQUEST");
        uint16_t packet_len = (buf[1] << 8) | (buf[2] & 0xFF);
        print_tlv(buf, packet_len + 3);
        // Verify certificate
        uint16_t pubkey_len = (buf[7] << 8) | buf[8];
        uint8_t pubkey[100];
        memcpy(pubkey, buf+9, pubkey_len);
        uint16_t pubkeysign_len = (buf[10+pubkey_len] << 8) | buf[11+pubkey_len];
        load_peer_public_key(pubkey, pubkey_len);
        int verified = verify(pubkey, pubkey_len, buf+12+pubkey_len, pubkeysign_len, ec_peer_public_key);
        if (verified != 1) {
            fprintf(stderr, "Failed to verify, exit status 1.\n");
            exit(1);
        }
        load_peer_public_key(pubkey, pubkey_len);
        derive_secret();
        // Verify nonce
        size_t servnoncesign_len = (buf[13+pubkey_len+pubkeysign_len] << 8) | buf[14+pubkey_len+pubkeysign_len];
        verified = verify(nonce, NONCE_SIZE, buf+15+pubkey_len+pubkeysign_len, servnoncesign_len, ec_peer_public_key);
        if (verified != 1) {
            fprintf(stderr, "Failed to verify, exit status 2- code %d.\n", verified);
            exit(2);
        }
        state_sec = SERVER_FINISHED_SEND;
        break;
    }
    case CLIENT_FINISHED_AWAIT: {
        if (*buf != FINISHED)
            exit(4);

        print("RECV FINISHED");

        state_sec = DATA_STATE;
        break;
    }
    case DATA_STATE: {
        if (*buf != DATA)
            exit(4);
        uint16_t packet_len = (buf[1] << 8) | (buf[2] & 0xFF);
        print_tlv(buf, packet_len + 3);
        uint8_t ivcipher[1016];
        uint16_t cipher_size = (buf[23] << 8) | (buf[24] & 0xFF);
        fprintf(stderr, "cipher size: %d\n", cipher_size);
        memcpy(ivcipher, buf+6, 16);
        memcpy(ivcipher+16, buf+25, cipher_size);
        uint8_t hmacdigest[32];
        hmac(ivcipher, 16+cipher_size, hmacdigest);
        print_hex(ivcipher, 16+cipher_size);
        print_hex(hmacdigest, 32);
        print_hex(buf+28+cipher_size, 32);
        if (memcmp(hmacdigest, buf+28+cipher_size, 32)) {
            fprintf(stderr, "MAC mismatch\n");
            exit(3);
        }
        uint8_t data_buf[943];
        uint16_t data_len = decrypt_cipher(ivcipher+16, cipher_size, ivcipher, data_buf);
        output_io(data_buf, data_len);
        // PT refers to the resulting plaintext size in bytes
        // CT refers to the received ciphertext size
        fprintf(stderr, "RECV DATA PT %ld CT %hu\n", data_len, cipher_size);

        break;
    }
    default:
        break;
    }
}
