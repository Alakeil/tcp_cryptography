#include <sys/socket.h>
#include <netinet/in.h> 

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "cs457_crypto.h"

/* 
 * Default server port 
 *
 * Be careful when using this port on 
 * CSD's machines. Read the README file 
 * and select an other port by changing 
 * this value or by using -p <port> 
 */
#define DEFAULT_PORT	5000


/*
 * prints the usage message
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    server [-p port]\n"
	    "    server -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    "  -p  port       Server's port\n"
	    "  -h             This help message\n" 
	);
	exit(EXIT_FAILURE);
}


/*
 * simple chat server with RSA-based AES 
 * key-exchange for encrypted communication
 */ 
int
main(int argc, char *argv[])
{
	int lfd;				/* listen file descriptor */
	int cfd;				/* comm file descriptor   */
	int port;				/* server port		  */
	int err;				/* errors		  */
	int opt;				/* cmd options		  */
	int optval;				/* socket options	  */
	int plain_len;				/* plaintext size	  */
	int cipher_len;				/* ciphertext size	  */
	size_t rxb;				/* received bytes	  */
	size_t txb;				/* transmitted bytes	  */
	struct sockaddr_in srv_addr;		/* server socket address  */
	unsigned char *aes_key;			/* AES key		  */
	unsigned char plaintext[BUFLEN];	/* plaintext buffer	  */
	unsigned char ciphertext[BUFLEN];	/* plaintext buffer	  */
	RSA *s_prv_key;				/* server private key	  */
	RSA *c_pub_key;				/* client public key	  */


	/* initialize */
	lfd = -1;
	cfd = -1;
	optval = 1;
	port = DEFAULT_PORT;
	memset(&srv_addr, 0, sizeof(srv_addr));


	/* get options */
	while ((opt = getopt(argc, argv, "p:h")) != -1) {
		switch (opt) {
		case 'p':
			port = atoi(optarg);
			break;
		case 'h':
		default:
			usage();
		}
	}


	/* socket init */


	/*
	 * this will save them from:
	 * "ERROR on binding: Address already in use"
	 */


	/* 
	 * bind and listen the socket
	 * for new client connections
	 */


	/* load keys */


	/* accept a new client connection */


	/* wait for a key exchange init */


	/* send the AES key */
		

	/* receive the encrypted message */


	/* Decrypt the message and print it */


	/* cleanup */

	return 0;
}

/* EOF */
