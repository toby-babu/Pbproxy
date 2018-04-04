//
// Created by Toby Babu on 11/11/17.
//


#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include "encryption.h"
#include "proxy_client.h"

int client_descriptor;

void* client_read_function(void * func_param) {
    while(1)
    {
        unsigned char server_string[2048], decrypted_string[2048] = "";
        memset(server_string,0,2048);
        memset(decrypted_string, 0, 2048);
        fflush(stdout);

        // Check if anything is present in the stream to be read
        int length_to_read = (int) recv(client_descriptor, server_string, sizeof(server_string) - 1, MSG_PEEK);

        if (length_to_read <= 0) {
            // Nothing to read and peek gave 0 value. Close port.
            shutdown(client_descriptor,SHUT_RD);
            fflush(stdout);
            close(client_descriptor);
            exit(1);
        }

        if(length_to_read > 0)
        {
            memset(&server_string, 0, sizeof(server_string));
            // Read till length to read and procesed read are equal
            for(int processed_read = 0, current_read = 0; processed_read != length_to_read; processed_read+= current_read) {
                current_read = (int) recv(client_descriptor, server_string + processed_read, (size_t) length_to_read, 0);
            }
            
            // Decrypt the string
            create_decrypt_string(server_string, iv_server_client, decrypted_string, key, state_server_client, length_to_read);

            // Write all the items that were read
            for(int processed_write = 0, current_write = 0; processed_write != length_to_read; processed_write+= current_write) {
                current_write = (int) write(1, decrypted_string + processed_write, (size_t) length_to_read);
            }
            usleep(25000);
        }
    }
}

void run_proxy_client(char *remoteHost, int portNumber, char *client_key) {
    struct hostent *hp = gethostbyname(remoteHost);
    struct sockaddr_in server_address;
    char iv_string_server[2048];

    memset(&server_address, 0, sizeof(server_address));
    memcpy((char *)&server_address.sin_addr, hp->h_addr, hp->h_length);
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons((u_short)portNumber);
    if((client_descriptor = socket(AF_INET, SOCK_STREAM, 0))==-1)
    {
        fprintf(stderr, "Client Socket failed\n");
        return;
    }

    if( connect(client_descriptor, (struct sockaddr *)&server_address, sizeof(server_address)) < 0)
    {
        fprintf(stderr, "\n Client Connect Failed \n");
        return;
    }

    // Reset IV and State of client-server communication
    memset(&iv_client_server, 0, sizeof(iv_client_server));
    memset(&state_client_server, 0, sizeof(state_client_server));

    // Reset IV and State of server-client communication
    memset(&iv_server_client, 0, sizeof(iv_server_client));
    memset(&state_server_client, 0, sizeof(state_server_client));

    // Read random value from urandom for IV of client-server communication
    long randval;
    FILE *f = fopen("/dev/urandom", "r");
    fread(&randval, 7, 1, f);
    fclose(f);

    const int n = snprintf(NULL, 0, "%ld", randval);
    char buf[n+1];
    memset(buf, 0, sizeof(buf));
    int c = snprintf(buf, n+1, "%ld", randval);
    strncpy(iv_client_server, buf, 16);
    iv_client_server[16] = '\0';

    // Write IV and initialize the state for server-client communication
    int iv_length_write = 0;
    while(iv_length_write != AES_BLOCK_SIZE)
    {
        int iv_length_current = (int) write(client_descriptor, iv_client_server + iv_length_write, AES_BLOCK_SIZE);
        iv_length_write=iv_length_write + iv_length_current;
    }

    if (AES_set_encrypt_key(client_key, 128, &key) < 0)
    {
        fprintf(stderr, "Could not set decryption key.");
        exit(1);
    }
    init_ctr(&state_client_server, iv_client_server);

    // Read IV and initialize the state for server-client communication
    memset(iv_string_server, 0, sizeof(iv_string_server));
    ssize_t iv_length_read = 0;
    while(iv_length_read != AES_BLOCK_SIZE)
    {
        int iv_length_current = (int) recv(client_descriptor, iv_string_server + iv_length_read, AES_BLOCK_SIZE, 0);
        iv_length_read = iv_length_read + iv_length_current;
    }
    memset(&iv_server_client,0,sizeof(iv_server_client));
    strncpy(iv_server_client, iv_string_server, 16);
    iv_server_client[16] = '\0';
    memset(&state_server_client,0,sizeof(state_server_client));
    init_ctr(&state_server_client, iv_server_client);

    pthread_t read_thread;
    fflush(stdin);
    fflush(stdout);

    // Create a new thread for write to stdout and read from pbproxy server
    int thread_id = pthread_create( &read_thread, NULL, client_read_function, (void*)"Child");
    if(thread_id)
    {
        fprintf(stderr,"Error - pthread_create() return code: %d\n", thread_id);
        return;
    }

    // Read from stdin and write to pbproxy server
    while(1)
    {
        char client_string[2048], temp_string[2048];
        unsigned char encrypted_string[2048] = "";
        memset(client_string, 0, 2048);
        memset(encrypted_string, 0, 2048);

        // Read from stdin
        int length_to_read = (int) read(0, client_string, sizeof(client_string));
        if (length_to_read > 0) {
            client_string[length_to_read] = '\0';

            // Encrypt the string which was read
            create_encrypt_string(client_string, iv_client_server, encrypted_string, key, state_client_server, length_to_read);

            // Write everything which was read
            for(int processed_write = 0, current_write = 0; processed_write != length_to_read; processed_write+= current_write) {
                current_write = (int) write(client_descriptor, encrypted_string + processed_write, (size_t) length_to_read);
            }
            usleep(25000);
        }
    }
}
