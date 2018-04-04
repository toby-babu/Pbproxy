//
// Created by Toby Babu on 11/11/17.
//

#ifndef HW3_PROXY_SERVER_H
#define HW3_PROXY_SERVER_H

void* server_write_function(void * func_param);
void run_proxy_server(char *remoteHost, int portNumber, int final_port_number, char *server_key);

#endif //HW3_PROXY_SERVER_H

