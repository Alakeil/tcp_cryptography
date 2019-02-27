CC = gcc
CFLAGS =  -Wall -pedantic -g
LIBSSL = -lssl -lcrypto

TARGETS = server client demo

all: $(TARGETS)

server: server.c cs457_crypto.o
	$(CC) $(CFLAGS) $(LIBSSL) $^ -o $@

client: client.c cs457_crypto.o
	$(CC) $(CFLAGS) $(LIBSSL) $^ -o $@

demo: crypto_demo.c cs457_crypto.o
	$(CC) $(CFLAGS) $(LIBSSL) $^ -o $@

clean:
	rm -f $(TARGETS) *.o
