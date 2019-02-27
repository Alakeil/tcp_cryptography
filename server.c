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
	int server_sock;    /*server socket descriptor*/
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
	int addr_size=sizeof(srv_addr);
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
	if((server_sock=socket(AF_INET,SOCK_STREAM,0))<0){
		printf("Server socket creation failed!\n");
		exit(EXIT_FAILURE);
	}

	/*
	 * this will save them from:
	 * "ERROR on binding: Address already in use"
	 */

	srv_addr.sin_family = AF_INET; 
    srv_addr.sin_addr.s_addr = INADDR_ANY; 
    srv_addr.sin_port = htons( DEFAULT_PORT ); 


	/* 
	 * bind and listen the socket
	 * for new client connections
	 */
	if (bind(server_sock,(struct sockaddr *)&srv_addr,addr_size)<0){ 
        perror("Could not bind server socket!\n"); 
        exit(EXIT_FAILURE); 
    } 
	printf("Listening for connection...\n");
    if (listen(server_sock,1)<0) 
    { 
        perror("Could not listen!\n"); 
        exit(EXIT_FAILURE); 
    } 


	/* load keys */


	/* accept a new client connection */
	if ((cfd=accept(server_sock, (struct sockaddr *)&srv_addr,(socklen_t*)&addr_size))<0){ 
        perror("Failed to accept connection!\n"); 
        exit(EXIT_FAILURE); 
    } 
	printf("Connection accepted!\n");
    if(read(cfd,plaintext,BUFLEN)<-1){
		perror("Could not read client message!\n");
		exit(EXIT_FAILURE);
	}
    printf("Client message is:%s\n",plaintext ); 
    send(cfd , "HELLO FROM SERVER!",19,0); 
    printf("Hello message sent\n"); 


	/* wait for a key exchange init */


	/* send the AES key */
		

	/* receive the encrypted message */


	/* Decrypt the message and print it */


	/* cleanup */

	return 0;
}

/* EOF */
