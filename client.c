#include <sys/socket.h>
#include <netinet/in.h> 
#include <arpa/inet.h> 

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "crypto.h"

/*
 *@author John Korniotakis
 */



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
	int client_sock;  /*socket descriptor*/

	int port;				/* server port		 */
	
	int opt;				/* cmd options		 */

	int cipher_len_tmp;			/* size of first ciphertext, encrypted by client's private key*/
	int cipher_len;				/* ciphertext size	 */
	size_t rxb;				/* received bytes	 */
	char iv_status[4];
	char *sip;				/* server IP		 */
	struct sockaddr_in srv_addr;		/* server socket address */
	unsigned char *iv=NULL;
	unsigned char *msg;			/* message to server	 */
	unsigned char aes_key[16];			/* AES key		 */
	unsigned char ciphertext_tmp[BUFLEN];   /*buffer of first ciphertext, encrypted by client's private key*/
	unsigned char plaintext[BUFLEN];	/* plaintext buffer	 */
	unsigned char ciphertext[BUFLEN];	/* ciphertext buffer	 */
	unsigned char iv_cipher[BUFLEN];
	unsigned char iv_cipher_tmp[BUFLEN];
	unsigned char iv_plain[BUFLEN];
	RSA *c_prv_key;				/* client private key	 */
	RSA *s_pub_key;				/* server public key	 */


	/* initialize */
	client_sock = -1;
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
	printf("IP IS %s\n",sip);

	/* socket init */
	if((client_sock=socket(AF_INET,SOCK_STREAM,0))<0){
		perror("Socket could not be created!\n");
		exit(EXIT_FAILURE);
	}
	srv_addr.sin_family = AF_INET; 
    	srv_addr.sin_port = htons(port); 
	srv_addr.sin_addr.s_addr=inet_addr(sip);
	//if(inet_pton(AF_INET, sip, &srv_addr.sin_addr)<=0){ 
        //	perror("\nInvalid address/ Address not supported \n"); 
        //	exit(EXIT_FAILURE);
    //	} 

	/* connect to server */
	if (connect(client_sock, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0){ 
        	perror("\nConnection Failed \n"); 
        	exit(EXIT_FAILURE);
    	}	 


	/* PERFORMING THE AES KEY EXCHANGE */

	/* loading the  keys needed*/
	c_prv_key=rsa_read_key(C_PRV_KF);
	s_pub_key=rsa_read_key(S_PUB_KF);

	/*Encrypting the hello message first with client's private key and then with the server's private key*/
	memcpy(plaintext,"hello",strlen("hello"));
      	printf("plaintext is %s\n",plaintext);	
	cipher_len_tmp=rsa_prv_encrypt(plaintext,strlen((const char*)plaintext),c_prv_key,ciphertext_tmp);
	cipher_len=rsa_pub_encrypt(ciphertext_tmp,cipher_len_tmp,s_pub_key,ciphertext);
	printf("CIphertext to be sent to socker is\n");   
	BIO_dump_fp (stdout, (const char *)ciphertext,cipher_len);
	/*Sending the encrypted hello message to server*/
    	send(client_sock,ciphertext,cipher_len,0); 
	printf("Encrypted hello message sent to server\n"); 


	/*Receiving the encrypted AES key, and we have to decrypt it*/
	rxb=recv(client_sock,ciphertext,BUFLEN,0);
	cipher_len_tmp=rsa_prv_decrypt(ciphertext,rxb,c_prv_key,ciphertext_tmp);
	rsa_pub_decrypt(ciphertext_tmp,cipher_len_tmp,s_pub_key,plaintext);
	printf("The decrypted AES key the client got is:");
	print_hex(plaintext,16);
	memcpy(aes_key,plaintext,16);

	recv(client_sock,iv_status,4,0); /*Receive a response from server, if it will send an IV or NOT*/
	if(strcmp(iv_status,"YES")==0){ /*If the server sends an IV, then decrypt the message to get it */
		
		rxb=recv(client_sock,iv_cipher,BUFLEN,0);
		cipher_len_tmp=rsa_prv_decrypt(iv_cipher,rxb,c_prv_key,iv_cipher_tmp);
		rsa_pub_decrypt(iv_cipher_tmp,cipher_len_tmp,s_pub_key,iv_plain);
		printf("The decrypted IV received by client is:");
		
		iv=iv_plain;
		print_hex(iv,8);	
	}	

	/* ENCRYPTING THE INITIAL MESSAGE WITH AES KEY AND SENDING IT TO SERVER*/
	
	
	
	cipher_len=aes_encrypt(msg,strlen((const char*)msg),aes_key,iv,ciphertext);
    	send(client_sock,ciphertext,cipher_len,0); 
   	printf("Message encrypted with AES key, sent!\n"); 
    

	/* cleanup */   
	close(client_sock);
	return 0;
}
 
/* EOF */
