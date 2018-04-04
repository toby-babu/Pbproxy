//
// Created by Toby Babu on 11/8/17.
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "proxy_client.h"
#include "proxy_server.h"

int main(int argc , char * argv[])
{
    int portNumber = 0, isServer = 0, final_port_number = 0, key_specified = 0;
    char *remoteHost, *key_file_name, *key;
    key_file_name = (char*) malloc(2048);
    key = (char*) malloc(2048);

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-k") == 0) {
            i++;
            strcpy(key_file_name, argv[i]);
            key_specified = 1;
        } else if (strcmp(argv[i], "-l") == 0) {
            i++;
            final_port_number = atoi(argv[i]);
            isServer = 1;
        } else if (i != 0) {
            remoteHost = argv[i];
            i++;
            portNumber = atoi(argv[i]);
        }
    }

    if(key_specified == 0) {
        fprintf(stderr, "No key file has been specified. Program will exit now.\n");
    }

    FILE *key_file_descriptor = fopen(key_file_name, "r");
    fread(key, 2048, 1, key_file_descriptor);
    if (feof(key_file_descriptor))
    {
        key[strlen(key) - 1] = '\0';
    }

    fclose(key_file_descriptor);
    if (isServer == 0) {
        run_proxy_client(remoteHost, portNumber, key);
    }
    else {
        run_proxy_server(remoteHost, final_port_number, portNumber, key);
    }

}


