CC = gcc
CFLAGS =  -Wall -pedantic -g
LIBSSL = -lssl -lcrypto

TARGETS = server client demo

all: $(TARGETS)

server: server.c crypto.o
	$(CC) $(CFLAGS)  $^ -o $@ $(LIBSSL)

client: client.c crypto.o
	$(CC) $(CFLAGS)  $^ -o $@ $(LIBSSL)

demo: 	demo.c crypto.o
	$(CC) $(CFLAGS) $^ -o $@ $(LIBSSL)

clean:
	rm -f $(TARGETS) *.o
