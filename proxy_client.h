//
// Created by Toby Babu on 11/11/17.
//

#ifndef HW3_PROXY_CLIENT_H
#define HW3_PROXY_CLIENT_H

void* client_read_function(void * func_param);
void run_proxy_client(char *remoteHost, int portNumber, char *client_key);

#endif //HW3_PROXY_CLIENT_H

