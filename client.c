#include <sys/socket.h>
#include <netinet/in.h> 
#include <arpa/inet.h> 

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "cs457_crypto.h"


/*
 * prints the usage message
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    client -i IP -p port -m message\n"
	    "    client -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    "  -i  IP         Server's IP address (xxx.xxx.xxx.xxx)\n"
	    "  -p  port       Server's port\n"
	    "  -m  message    Message to server\n"
	    "  -h             This help message\n" 
	);
	exit(EXIT_FAILURE);
}


/*
 * checks the cmd arguments
 */
void
check_args(char *ip, unsigned char *msg, int port)
{
	int err;

	err = 0;
	if (!ip) {
		printf("No IP provided\n");
		err = 1;
	}
	if (!msg) {
		printf("No message provided\n");
		err = 1;
	}
	if (port == -1) {
		printf("No port provided\n");
		err = 1;
	}
	if (err)
		usage();
}


/*
 * simple chat client with RSA-based AES 
 * key-exchange for encrypted communication
 */ 
int
main(int argc, char *argv[])
{
	int cfd;				/* comm file descriptor	 */
	int port;				/* server port		 */
	int err;				/* errors		 */
	int opt;				/* cmd options		 */
	int plain_len;				/* plaintext size	 */
	int cipher_len;				/* ciphertext size	 */
	size_t rxb;				/* received bytes	 */
	size_t txb;				/* transmitted bytes	 */
	char *sip;				/* server IP		 */
	struct sockaddr_in srv_addr;		/* server socket address */
	unsigned char *msg;			/* message to server	 */
	unsigned char *aes_key;			/* AES key		 */
	unsigned char plaintext[BUFLEN];	/* plaintext buffer	 */
	unsigned char ciphertext[BUFLEN];	/* plaintext buffer	 */
	RSA *c_prv_key;				/* client private key	 */
	RSA *s_pub_key;				/* server public key	 */


	/* initialize */
	cfd = -1;
	port = -1;
	sip = NULL;
	msg = NULL;
	memset(&srv_addr, 0, sizeof(srv_addr));


	/* get options */
	while ((opt = getopt(argc, argv, "i:m:p:h")) != -1) {
		switch (opt) {
		case 'i':
			sip = strdup(optarg);
			break;
		case 'm':
			msg = (unsigned char *)strdup(optarg);
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'h':
		default:
			usage();
		}
	}


	/* check cmd args */
	check_args(sip, msg, port);


	/* socket init */


	/* connect to server */


	/* load keys */


	/* perform the AES key exchange */

	/* 
	 * encrypt the init message
	 * and send it to the server
	 */


	/*
	 * receive the key from the server,
	 * decrypt it and register it
	 */


	/* encrypt the message with the AES key */


	/* send the encrypted message */


	/* cleanup */

	return 0;
}

/* EOF */
