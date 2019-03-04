#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>


/* error reporting helpers */
#define ERRX(ret, str) \
    do { fprintf(stderr, str "\n"); exit(ret); } while (0)
#define ERR(ret, str) \
    do { fprintf(stderr, str ": %s\n", strerror(errno)); exit(ret); } while (0)

/* buffer size */
#define BUFLEN	2048

/* key files*/
#define AES_KF		"keys/aes_key.txt"
#define S_PUB_KF	"keys/srv_pub.pem"
#define S_PRV_KF	"keys/srv_priv.pem"
#define C_PUB_KF	"keys/cli_pub.pem"
#define C_PRV_KF	"keys/cli_priv.pem"

/* AES block size */
#define AES_BS 16

int padding=RSA_PKCS1_PADDING;
/* --------------------------- conversion helpers --------------------------- */


/*
 * converts half printable hex value to integer
 */
int
half_hex_to_int(unsigned char c)
{
	if (isdigit(c))
		return c - '0';

	if ((tolower(c) >= 'a') && (tolower(c) <= 'f'))
		return tolower(c) + 10 - 'a';

	return 0;
}


/*
 * converts a printable hex array to bytes
 */
char *
hex_to_bytes(char *input)
{
	int i;
	char *output;

	output = NULL;
	if (strlen(input) % 2 != 0)
		ERRX(0, "reading hex string");

	output = calloc(strlen(input) / 2, sizeof(unsigned char));
	if (!output)
		ERRX(1, "h2b calloc");

	for (i = 0; i < strlen(input); i+= 2) {
		output[i / 2] = ((unsigned char)half_hex_to_int(input[i])) *
		    16 + ((unsigned char)half_hex_to_int(input[i + 1]));
	}
	
	return output;
}


/*
 * Prints the hex value of the input
 * 16 values per line
 */
void
print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/* ----------------------------- key management ----------------------------- */


/*
 * retrieves an AES key from the key file
 */
unsigned char *aes_read_key(void){
	FILE *f;
	char *q,*aes_key=NULL;
	size_t keySize=0;
	f=fopen(AES_KF,"r");
	getline(&aes_key,&keySize,f);
	q=aes_key;
	while(*q!='\n')
		q++;
	*q='\0';
	return hex_to_bytes(aes_key);
}


/* 
 * retrieves an RSA key from the key file
 */
RSA * rsa_read_key(char *kfile){
	FILE *f=fopen(kfile,"rb"); /*Opening a filestream to the file that contains rsa key*/
	RSA *rsa=RSA_new(); /*Initialising a new RSA key*/
	if(strcmp(kfile,S_PUB_KF)==0||strcmp(kfile,C_PUB_KF)==0)
		rsa=PEM_read_RSA_PUBKEY(f,&rsa,NULL,NULL); /*Reading the public RSA key from file*/
	else if(strcmp(kfile,S_PRV_KF)==0||strcmp(kfile,C_PRV_KF)==0)
		rsa=PEM_read_RSAPrivateKey(f,&rsa,NULL,NULL); /*Reading the private RSA key from file*/
	fclose(f);
	return rsa;
}


/* ----------------------------- AES functions ------------------------------ */


/*
 * encrypts the data with 128-bit AES ECB
 */
int aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,unsigned char *iv, unsigned char *ciphertext){
	int length,cipher_len;
	EVP_CIPHER_CTX *ciph_context; /*Our cipher context*/

	/*Initializing the cipher context*/
	if(!(ciph_context=EVP_CIPHER_CTX_new())){
		perror("Could not initialize cipher context!\n");
		exit(EXIT_FAILURE);

	}

	/*Initializing the encryption operation with 128-bit AES ECB*/
	if(EVP_EncryptInit_ex(ciph_context,EVP_aes_128_ecb(),NULL,key,iv)!=1){
		perror("Failed to initialize encryption operation!\n");
		exit(EXIT_FAILURE);
	}

	/*Providing the message to be encrypted*/
	if(EVP_EncryptUpdate(ciph_context,ciphertext,&length,plaintext,plaintext_len)!=1){
		perror("Could not provide message for encryption!\n");
		exit(EXIT_FAILURE);
	}

	cipher_len=length;

	/*Finalizing encryption*/
	if(EVP_EncryptFinal_ex(ciph_context,ciphertext+length,&length)!=1){
		perror("Could not finalize encryption!\n");
		exit(EXIT_FAILURE);
	}

	cipher_len+=length;

	EVP_CIPHER_CTX_free(ciph_context);

	return cipher_len;
}


/*
 * decrypts the data and returns the plaintext size
 */
int aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,unsigned char *iv, unsigned char *plaintext){
	EVP_CIPHER_CTX *deciph_context;
	int length,plain_len;

	/*Initializing the decipher context*/
	if(!(deciph_context=EVP_CIPHER_CTX_new())){
		perror("Could not initialize decipher context!\n");
		exit(EXIT_FAILURE);
	} 

	/*Initializing the decryption operation*/
	if(EVP_DecryptInit_ex(deciph_context,EVP_aes_128_ecb(),NULL,key,iv)!=1){
		perror("Could not initialise decryption operation!\n");
		exit(EXIT_FAILURE);
	}
	  

	/*Providing the message to be decrypted*/
	if(EVP_DecryptUpdate(deciph_context,plaintext,&length,ciphertext,ciphertext_len)!=1){
		perror("Could not provide message for decryption\n");
		exit(EXIT_FAILURE);
	}
	plain_len=length;

	/*Finalising decryption*/
	if(EVP_DecryptFinal_ex(deciph_context,plaintext+length,&length)!=1){
		perror("Could not finalise decryption!\n");
		exit(EXIT_FAILURE);
	}
	plain_len+=length;

	EVP_CIPHER_CTX_free(deciph_context);

	return plain_len;

}


/* ----------------------------- RSA functions ------------------------------ */


/*
 * RSA public key encryption
 * Since we are using a 2048 bit key, RSA can encrypt 2048/8=256 bytes
 * max each time. We also use PKCS1 padding which is 11 bytes so the 
 * text to be encrypted can be 256-11=245 bytes max each time.
 */
int rsa_pub_encrypt(unsigned char *plaintext, int plaintext_len,RSA *key, unsigned char *ciphertext){
	int cipher_len=0;
	if(plaintext_len<=245){
		cipher_len=RSA_public_encrypt(plaintext_len,plaintext,ciphertext,key,padding);
	}else{
		q=plaintext;
		tmpq=plaintext;
			
	}
	return cipher_len;	
}


/*
 * RSA private key decryption
 */
int rsa_prv_decrypt(unsigned char *ciphertext, int ciphertext_len,RSA *key, unsigned char *plaintext){
	int plain_len=RSA_private_decrypt(ciphertext_len,ciphertext,plaintext,key,padding);
	return plain_len;
}


/*
 * RSA private key encryption
 */
int rsa_prv_encrypt(unsigned char *plaintext, int plaintext_len,RSA *key, unsigned char *ciphertext){
	

}


/*
 * RSA public key decryption
 */
int rsa_pub_decrypt(unsigned char *ciphertext, int ciphertext_len,RSA *key, unsigned char *plaintext){
	
}


/*
 * RSA Public(Private) encryption
 */
int
rsa_pub_priv_encrypt(unsigned char *plaintext, int plaintext_len,
    RSA *pub_k, RSA *priv_k, unsigned char *ciphertext)
{

}


/*
 * RSA Public(Private) decryption
 */
int
rsa_pub_priv_decrypt(unsigned char *ciphertext, int ciphertext_len,
    RSA *pub_k, RSA *priv_k, unsigned char *plaintext)
{

}



/* EOF */
