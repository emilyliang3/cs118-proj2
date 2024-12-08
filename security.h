#pragma once

#include <openssl/evp.h>
#include <stdint.h>

// libcrypto internal representation of keys; use these to verify

// Public key of your peer (use `load_peer_public_key` on data from the Server
// Hello/Key Exchange Request first)
extern EVP_PKEY* ec_peer_public_key;

// Public key of the certificate authority (use `load_ca_public_key` first)
extern EVP_PKEY* ec_ca_public_key;

// TLV 0xA0 encoded certificate (use `load_certificate` first)
extern uint8_t* certificate;
extern size_t cert_size;

// DER encoded public key (use `derive_public_key` first)
extern uint8_t* public_key;
extern size_t pub_key_size;

// From file, load DER formatted private key
void load_private_key(char* filename);

// From buffer, load DER formatted peer key into `ec_peer_public_key`
void load_peer_public_key(uint8_t* peer_key, size_t size);

// From file, load DER formatted certificate authority public key into
// `ec_ca_public_key`
void load_ca_public_key(char* filename);

// From file, load 0xA0 type certificate into buffer `certificate`
// with size `cert_size`
void load_certificate(char* filename);

// Generate private key from the NID_X9_62_prime256v1 elliptic curve
void generate_private_key();

// From private key (make sure to call `load_private_key` or
// `generate_private_key` first), derive public key point on elliptic curve
// Loads into buffer `public_key` with size `pub_key_size`
void derive_public_key();

// From private key (make sure to call `load_private_key` or
// `generate_private_key` first) and peer key (make sure to call
// `load_peer_public_key` first), generate ECDH shared secret
void derive_secret();

// Derive ENC key and MAC key using HKDF SHA-256
void derive_keys();

// Using private key (make sure to call `load_private_key` or
// `generate_private_key` first), sign a buffer by hashing it with SHA-256 then
// applying ECDSA
// Returns size of signature
size_t sign(uint8_t* data, size_t size, uint8_t* signature);

// Using a certain authority (typically `ec_peer_public_key` or
// `ec_ca_public_key`), verify the authenticity of an ECDSA signature
// Returns 1 if verified successfully, other values if not
int verify(uint8_t* data, size_t size, uint8_t* signature, size_t sig_size,
           EVP_PKEY* authority);

// Generate cryptographically secure random data
void generate_nonce(uint8_t* buf, size_t size);

// Encrypt data using derived shared secret (make sure to call `derive_secret`
// first). Uses AES-256-CBC with PKCS7 padding. Buffers `iv` and `cipher` will
// have the resulting initial vector and ciphertext. Returns size of ciphertext
size_t encrypt_data(uint8_t* data, size_t size, uint8_t* iv, uint8_t* cipher);

// Decrypt data using derived shared secret (make sure to call `derive_secret`
// first). Uses AES-256-CBC with PKCS7 padding. Buffer `data` will have
// the resulting decrypted data.
// Returns size of data
size_t decrypt_cipher(uint8_t* cipher, size_t size, uint8_t* iv, uint8_t* data);

// Using the MAC key, generate an HMAC SHA-256 digest of `data` and place it in
// the buffer `digest`. Digest will always be 32 bytes (since SHA-256).
void hmac(uint8_t* data, size_t size, uint8_t* digest);

// Derive own self-signed certificate (0xA0)
void derive_self_signed_certificate();

// Clean up all buffers and keys
void clean_up();
