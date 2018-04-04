//
// Created by Toby Babu on 11/11/17.
//
#include <openssl/aes.h>
#ifndef HW3_ENCRYPTION_H
#define HW3_ENCRYPTION_H

AES_KEY key;
unsigned char iv_client_server[AES_BLOCK_SIZE + 1], iv_server_client[AES_BLOCK_SIZE + 1];
struct ctr_state state_client_server, state_server_client;

struct ctr_state
{
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
};

int init_ctr(struct ctr_state *state, const unsigned char iv[16]);

void create_encrypt_string(char* string_to_encrypt, const unsigned char* enc_key, unsigned char *final_string,
                           AES_KEY key_encrypt, struct ctr_state state_encrypt, int size);

void create_decrypt_string(unsigned char* string_to_decrypt, const unsigned char* enc_key, unsigned char *final_string,
                           AES_KEY key_decrypt, struct ctr_state state_decrypt, int size);

#endif //HW3_ENCRYPTION_H

