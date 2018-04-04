//
// Created by Toby Babu on 11/11/17.
//

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <string.h>
#include "encryption.h"

int init_ctr(struct ctr_state *state, const unsigned char iv[16]) {
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);
    memset(state->ivec + 8, 0, 8);
    memcpy(state->ivec, iv, 8);
}

void create_encrypt_string(char* string_to_encrypt, const unsigned char* enc_key, unsigned char *final_string,
                           AES_KEY key_encrypt, struct ctr_state state_encrypt, int size) {
    char temp_string[AES_BLOCK_SIZE];
    unsigned char encrypted_block[AES_BLOCK_SIZE];
    int num_read = AES_BLOCK_SIZE, length_encrypted = 0;

    while (num_read == AES_BLOCK_SIZE) {
        memset(encrypted_block, 0, AES_BLOCK_SIZE);
        memset(temp_string, 0, AES_BLOCK_SIZE);
        if (size < AES_BLOCK_SIZE)
            num_read = size;
        else
            num_read = AES_BLOCK_SIZE;

        // Copy 16 byte block to encrypt to a temp string
        for (int i = 0; i < num_read; i++) {
            temp_string[i] = string_to_encrypt[i + length_encrypted];
        }

        AES_ctr128_encrypt(temp_string, encrypted_block, num_read, &key_encrypt, state_encrypt.ivec, state_encrypt.ecount, &state_encrypt.num);
        for (int i = 0, j = length_encrypted; i < num_read; i++, j++) {
            final_string[j] = encrypted_block[i];
        }

        length_encrypted+= num_read;
        size-= num_read;
    }
    final_string[length_encrypted] = '\0';
}

void create_decrypt_string(unsigned char* string_to_decrypt, const unsigned char* enc_key, unsigned char *final_string,
                           AES_KEY key_decrypt, struct ctr_state state_decrypt, int size) {
    unsigned char temp_string[AES_BLOCK_SIZE];
    unsigned char encrypted_block[AES_BLOCK_SIZE];
    int num_read = AES_BLOCK_SIZE, length_decrypted = 0;

    while (num_read == AES_BLOCK_SIZE) {
        memset(encrypted_block, 0, AES_BLOCK_SIZE);
        memset(temp_string,0,AES_BLOCK_SIZE);
        if (size < AES_BLOCK_SIZE)
            num_read = size;
        else
            num_read = AES_BLOCK_SIZE;

        // Copy 16 byte block to decrypt to a temp string
        for (int i = 0; i < num_read; i++) {
            temp_string[i] = string_to_decrypt[i + length_decrypted];
        }

        AES_ctr128_encrypt(temp_string, encrypted_block, num_read, &key_decrypt, state_decrypt.ivec, state_decrypt.ecount, &state_decrypt.num);
        for (int i = 0, j = length_decrypted; i < num_read; i++, j++) {
            final_string[j] = encrypted_block[i];
        }
        length_decrypted+=num_read;
        size -= num_read;
    }
    final_string[length_decrypted] = '\0';
}
