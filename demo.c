#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "crypto.h"


/*
 * small demo to check function correctness
 */
int
main(int argc, char **argv)
{
	RSA *prv_key,*client_pub_key=rsa_read_key("keys/cli_pub.pem"),*server_priv_key=rsa_read_key("keys/srv_priv.pem")
		,*client_priv_key=rsa_read_key("keys/cli_priv.pem"),*server_pub_key=rsa_read_key("keys/srv_pub.pem");
	unsigned char ciphertext[1024],srv_ciphertext[1024],plaintext[1024]="hello",deciphertext[1024],srv_deciphertext[1024];
	int cipher_len,srv_cipher_len,decipher_len,i,srv_decipher_len;
	



	printf("Size of message to be encrypted is %d bytes\n\n",strlen(plaintext));
	printf("Text to be encrypted is:\n%s\n\n\n",plaintext);
	cipher_len=rsa_prv_encrypt(plaintext,strlen((char*)plaintext),client_priv_key,ciphertext);
	printf("Client public ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, cipher_len);

	srv_cipher_len=rsa_pub_encrypt(ciphertext,cipher_len,server_pub_key,srv_ciphertext);
	//printf("Server ciphertext is:\n");
	//BIO_dump_fp (stdout, (const char *)srv_ciphertext, srv_cipher_len);

	srv_decipher_len=rsa_prv_decrypt(srv_ciphertext,srv_cipher_len,server_priv_key,srv_deciphertext);
	printf("Server decipher text is:\n");
	BIO_dump_fp (stdout, (const char *)srv_deciphertext, srv_decipher_len);
	
	decipher_len=rsa_pub_decrypt(srv_deciphertext,srv_decipher_len,client_pub_key,deciphertext);
	deciphertext[decipher_len]='\0';
	printf("Decrypted is %d bytes\n\n",decipher_len);
	printf("The decrypted text is:\n%s\n",deciphertext);
	
	return 0;
}

/* EOF */
