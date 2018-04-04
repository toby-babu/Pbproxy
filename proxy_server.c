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
#include "encryption.h"
#include "proxy_server.h"

int final_server_descriptor, pbproxy_client_descriptor, pbproxy_server_descriptor;
void* server_write_function(void * func_param) {
    while(1)
    {
        unsigned char encrypted_string[2048] = "";
        char server_string[2048];
        memset(server_string, 0, 2048);
        memset(encrypted_string, 0, 2048);

        // Check if anything is present in the stream to be read
        int length_to_read = (int) recv(final_server_descriptor, server_string, sizeof(server_string) - 1, MSG_PEEK);
        if(length_to_read > 0)
        {
            memset(&server_string, 0, sizeof(server_string));

            // Read till length to read and procesed read are equal
            for(int processed_read = 0, current_read = 0; processed_read != length_to_read; processed_read+= current_read) {
                current_read = (int) recv(final_server_descriptor, server_string + processed_read,
                                          (size_t) length_to_read, 0);
            }
            server_string[length_to_read] = '\0';

            // Encrypt the string
            create_encrypt_string(server_string, iv_server_client, encrypted_string, key, state_server_client, length_to_read);

            // Write all the items that were read
            for(int processed_write = 0, current_write = 0; processed_write != length_to_read; processed_write+= current_write) {
                current_write = (int) write(pbproxy_server_descriptor, encrypted_string + processed_write,
                                            (size_t) length_to_read);
            }
            usleep(25000);
        }
        if(length_to_read <= 0) {
            return 0;
        }
    }
}


void run_proxy_server(char *remoteHost, int portNumber, int final_port_number, char *server_key) {

    struct hostent *pbproxy_server = gethostbyname(remoteHost);
    struct hostent *local_server = gethostbyname(remoteHost);
    struct sockaddr_in client_address;
    memset(&client_address, 0, sizeof(client_address));
    client_address.sin_family = AF_INET;
    memcpy(&(client_address.sin_addr),  pbproxy_server->h_addr, pbproxy_server->h_length);
    client_address.sin_port = htons(portNumber);

    if((pbproxy_client_descriptor = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        fprintf(stderr, "ERROR:Socket failed\n");
        return;
    }

    if(bind(pbproxy_client_descriptor, (struct sockaddr *)&client_address, sizeof(client_address)) == -1)
    {
        fprintf(stderr, "ERROR:Binding on server\n");
        close(pbproxy_client_descriptor);
        return;
    }

    listen(pbproxy_client_descriptor, 5);

    while(1) {

        if ((pbproxy_server_descriptor = accept(pbproxy_client_descriptor, NULL, NULL)) < 0) {
            fprintf(stderr, "Error in Accept in server\n");
            close(pbproxy_client_descriptor);
            return;
        }
        fprintf(stderr, "Connection accepted!\n");
        struct sockaddr_in final_server_address;
        char iv_string_client[2048];
        memset(iv_string_client, 0, 2048);

        // Reset IV and State of client-server communication
        memset(&iv_client_server, 0, sizeof(iv_client_server));
        memset(&state_client_server, 0, sizeof(state_client_server));

        // Reset IV and State of server-client communication
        memset(&state_server_client, 0, sizeof(state_server_client));
        memset(&iv_server_client, 0, sizeof(iv_server_client));

        // Read IV and initialize the state for client-server communication
        int iv_length_read = 0;
        while(iv_length_read != AES_BLOCK_SIZE)
        {
            int iv_length_current = (int) recv(pbproxy_server_descriptor, iv_string_client + iv_length_read, AES_BLOCK_SIZE, 0);
            iv_length_read = iv_length_read + iv_length_current;
        }
        strncpy(iv_client_server, iv_string_client, 16);
        iv_client_server[16] = '\0';
        init_ctr(&state_client_server, iv_client_server);

        // Read random value from urandom for IV of server-client communication
        long randval = 0;
        FILE *f = fopen("/dev/urandom", "r");
        fread(&randval, 7, 1, f);
        fclose(f);
        const int n = snprintf(NULL, 0, "%ld", randval);
        char buffer[n+1];
        memset(buffer, 0, sizeof(buffer));
        int c = snprintf(buffer, n+1, "%ld", randval);
        strncpy(iv_server_client, buffer, 16);
        iv_server_client[16] = '\0';

        // Write IV and initialize the state for server-client communication
        int iv_length_write = 0;
        while(iv_length_write != AES_BLOCK_SIZE)
        {
            int iv_length_current = (int) write(pbproxy_server_descriptor, iv_server_client + iv_length_write, AES_BLOCK_SIZE);
            iv_length_write = iv_length_write + iv_length_current;
        }
        init_ctr(&state_server_client, iv_server_client);

        // Create socket to connection to final server
        if ((final_server_descriptor = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
            fprintf(stderr, "ERROR:Socket failed\n");
            return;
        }

        memset(&final_server_address, 0, sizeof(final_server_address));
        bzero((char *)&final_server_address, sizeof(final_server_address));
        memcpy(&(final_server_address.sin_addr),  local_server->h_addr, local_server->h_length);
        final_server_address.sin_family = AF_INET;
        final_server_address.sin_port = htons((u_short)final_port_number);

        // Connect to final server
        if (connect(final_server_descriptor, (struct sockaddr *) &final_server_address, sizeof(final_server_address)) <
            0) {
            fprintf(stderr, "\n Error : Connect SD2 Failed \n");
            return;
        }

        // Read and encrypt key from file
        if (AES_set_encrypt_key(server_key, 128, &key) < 0) {
            fprintf(stderr, "Could not set decryption key.");
            exit(1);
        }
        fprintf(stderr, "Connected!\n");

        pthread_t write_thread;

        // Create a new thread for write to pbproxy client
        int thread_id = pthread_create(&write_thread, NULL, server_write_function, (void *) "Child");
        if (thread_id) {
            fprintf(stderr, "Error - pthread_create() return code: %d\n", thread_id);
            return;
        }

        // Read from pbproxy client, decrypt and write to final server
        while (1) {
            unsigned char client_string[2048], decrypted_string[2048];
            memset(client_string, 0, 2048);
            memset(decrypted_string, 0, 2048);

            // Check if anything is present in the stream to be read
            int length_to_read = (int) recv(pbproxy_server_descriptor, client_string, sizeof(client_string) - 1, MSG_PEEK);
            if(length_to_read>0)
            {
                memset(&client_string,0,sizeof(client_string));

                // Read till length to read and processed read are equal
                for(int processed_read = 0, current_read = 0; processed_read != length_to_read; processed_read+= current_read) {
                    current_read = (int) recv(pbproxy_server_descriptor, client_string + processed_read,
                                              (size_t) length_to_read, 0);
                }

                // Decrypt the string
                create_decrypt_string(client_string, iv_client_server, decrypted_string, key, state_client_server, length_to_read);

                // Write all the items that were read
                for(int processed_write = 0, current_write = 0; processed_write != length_to_read; processed_write+= current_write) {
                    current_write = (int) write(final_server_descriptor, decrypted_string + processed_write,
                                                (size_t) length_to_read);
                }
                usleep(25000);
            }
            if (length_to_read <= 0) {
                close(pbproxy_server_descriptor);
                fflush(stdout);
                break;
            }
        }
    }
}
