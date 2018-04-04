CC=gcc
CFLAGS=-I.
DEPS = encryption.h proxy_client.h proxy_server.h

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

make: encryption.c proxy_client.c proxy_server.c pbproxy.c
	$(CC) -o pbproxy encryption.c proxy_client.c proxy_server.c pbproxy.c -lcrypto -pthread

clean:
	rm pbproxy
