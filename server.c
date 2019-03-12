#include <sys/socket.h>
#include <netinet/in.h> 

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "crypto.h"

/*
 * @author:John Korniotakis
 */


/* 
 * Default server port 
 *
 * Be careful when using this port on 
 * CSD's machines. Read the README file 
 * and select an other port by changing 
 * this value or by using -p <port> 
 */
#define DEFAULT_PORT	3208


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

	int cfd;				/* comm file descriptor   */
	int port;				/* server port		  */

	int opt;				/* cmd options		  */
	
	int iv_cipher_len;
	int iv_cipher_len_tmp;
	int plain_len;				/* plaintext size	  */
	int cipher_len;				/* ciphertext size	  */
	int cipher_len_tmp;
	size_t rxb;				/* received bytes	  */
	
	struct sockaddr_in srv_addr;		/* server socket address  */
	int addr_size=sizeof(srv_addr);

	
	unsigned char iv_cipher[BUFLEN];
	unsigned char iv_cipher_tmp[BUFLEN];

	unsigned char *iv=NULL;
	unsigned char *aes_key;			/* AES key		  */
	unsigned char plaintext[BUFLEN];	/* plaintext buffer	  */
	unsigned char ciphertext[BUFLEN];	/* ciphertext buffer	  */
	unsigned char ciphertext_tmp[BUFLEN];	/*buffer used for the first decryption*/
	RSA *s_prv_key;				/* server private key	  */
	RSA *c_pub_key;				/* client public key	  */


	/* initialize */
	server_sock = -1;
	cfd = -1;

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
    	srv_addr.sin_port = htons(port ); 


	/* 
	 * bind and listen the socket
	 * for new client connections
	 */
	if (bind(server_sock,(struct sockaddr *)&srv_addr,addr_size)<0){ 
        	perror("Could not bind server socket!\n"); 
        	exit(EXIT_FAILURE); 
    	} 
	printf("Listening for connection...\n");
    	if (listen(server_sock,3)<0) 
    	{ 
        	perror("Could not listen!\n"); 
        	exit(EXIT_FAILURE); 
    	} 


	/* load keys */
	s_prv_key=rsa_read_key(S_PRV_KF);
	c_pub_key=rsa_read_key(C_PUB_KF);

	/* accept a new client connection */
	if ((cfd=accept(server_sock, (struct sockaddr *)&srv_addr,(socklen_t*)&addr_size))<0){ 
        	perror("Failed to accept connection!\n"); 
        	exit(EXIT_FAILURE); 
    	} 
	printf("Connection accepted!\n");
	rxb=recv(cfd,ciphertext,BUFLEN,0);
    	if((int)rxb<-1){
		perror("Could not read client message!\n");
		exit(EXIT_FAILURE);
	}


	/*Decrypting the message received from client*/
	cipher_len=rsa_prv_decrypt(ciphertext,(int)rxb,s_prv_key,ciphertext_tmp);
	plain_len=rsa_pub_decrypt(ciphertext_tmp,cipher_len,c_pub_key,plaintext);

	plaintext[plain_len]='\0';
	if(strcmp((const char*)plaintext,"hello")==0){
		printf("Message received is hello! Server will proceed with sending the AES key to client!\n");

		/*Loading the aes key from file*/
		aes_key=aes_read_key();
		iv=generateIV();
		printf("The IV generated is:");
		print_hex(iv,8);

		/*With the aes key loaded, we now need to encrypt it*/
		printf("\nTHE AES KEY LOADED IS:");
		print_hex(aes_key,16);

		cipher_len_tmp=rsa_prv_encrypt(aes_key,16,s_prv_key,ciphertext_tmp);
		cipher_len=rsa_pub_encrypt(ciphertext_tmp,cipher_len_tmp,c_pub_key,ciphertext);

		/*We need to encrypt the IV before sending it*/
    		if(iv!=NULL){
   			iv_cipher_len_tmp=rsa_prv_encrypt(iv,16,s_prv_key,iv_cipher_tmp);
			iv_cipher_len=rsa_pub_encrypt(iv_cipher_tmp,iv_cipher_len_tmp,c_pub_key,iv_cipher);
		}

		

		


		/* send the AES key */
		send(cfd ,ciphertext,cipher_len,0); 

		/*Server must notify client if an IV will be used*/
		if(iv==NULL){
			printf("\nServer will not send any iv to client\n");
			send(cfd,"NO",3,0);
		}else{
			printf("\nServer will send IV to client\n");
			send(cfd,"YES",4,0);
			send(cfd,iv_cipher,iv_cipher_len,0);
		}



		/* receive the encrypted message */
		rxb=recv(cfd,ciphertext,BUFLEN,0);

		/* Decrypt the message and print it */
		plain_len=aes_decrypt(ciphertext,rxb,aes_key,iv,plaintext);
		plaintext[plain_len]='\0';
		printf("Server received from the client the following message: %s\n",plaintext);
	}else{
		printf("Incorrect message received! Server will now terminate connection with client!\n");

	}  
	/* cleanup */

	close(server_sock);
	close(cfd);
	return 0;
}

/* EOF */
