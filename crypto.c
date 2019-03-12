#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

/*
 * @author:John Korniotakis
 */

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

	/*Initializing the encryption operation with 128-bit AES ECB if no IV was given or with
	 * 128-bit AES CBC if IV was given*/
	if(iv==NULL){
		if(EVP_EncryptInit_ex(ciph_context,EVP_aes_128_ecb(),NULL,key,iv)!=1){
			perror("Failed to initialize encryption operation for ECB!\n");
			exit(EXIT_FAILURE);
		}
	}else{

		if(EVP_EncryptInit_ex(ciph_context,EVP_aes_128_cbc(),NULL,key,iv)!=1){
			perror("Failed to initialize encryption operation for CBC!\n");
			exit(EXIT_FAILURE);
		}
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

	/*Initializing the decryption operation for 128 ECB mode if no IV is given or 128 CBC mode if 
	 * IV is given*/
	if(iv==NULL){
		if(EVP_DecryptInit_ex(deciph_context,EVP_aes_128_ecb(),NULL,key,iv)!=1){
			perror("Could not initialise decryption operation for ECB!\n");
			exit(EXIT_FAILURE);
		}
	}else{
		if(EVP_DecryptInit_ex(deciph_context,EVP_aes_128_cbc(),NULL,key,iv)!=1){
			perror("Could not initialise decryption operation for CBC!\n");
			exit(EXIT_FAILURE);
		}
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

int rsa_prv_encrypt(unsigned char *plaintext, int plaintext_len,RSA *key, unsigned char *ciphertext){

	int counter=0,cipher_len=0,cipher_len_tmp=0,plaintext_len_scanned=0,offset=0,qlen;
	unsigned char q[246],*tmpq,ciphertext_tmp[256];
	if(plaintext_len<=245){
		cipher_len=RSA_private_encrypt(plaintext_len,plaintext,ciphertext,key,padding);
	}else{

		tmpq=plaintext;
		while(plaintext_len_scanned<plaintext_len){

			/*We are going to encrypt 245 bytes at a time*/
			if(plaintext_len-plaintext_len_scanned>245){
				qlen=245;
				memcpy(q,tmpq,245);
			}else{
				counter=0;
				while(tmpq[counter]!=plaintext[plaintext_len])
					counter++;
				qlen=counter;	
				memcpy(q,tmpq,counter);


			}
			tmpq+=245;
			/*q points to the first 245 bytes of the message to be encrypted*/
			cipher_len_tmp=RSA_private_encrypt(qlen,q,ciphertext_tmp,key,padding);

			cipher_len+=cipher_len_tmp;
			plaintext_len_scanned+=245; /*245 bytes encrypted*/
			memcpy(ciphertext+offset,ciphertext_tmp,256);
			offset+=256;
		}
		
	}
	return cipher_len;
}


/*
 * RSA private key decryption
 */

int rsa_pub_decrypt(unsigned char *ciphertext, int ciphertext_len,RSA *key, unsigned char *plaintext){
	int decipher_len=0,decipher_len_tmp=0,ciphertext_len_scanned=0,offset=0;
	unsigned char q[256],*tmpq,deciphertext_tmp[245];
	if(ciphertext_len<=256){
		decipher_len=RSA_public_decrypt(ciphertext_len,ciphertext,plaintext,key,padding);
	}else{

		tmpq=ciphertext;
		while(ciphertext_len_scanned<ciphertext_len){
		
	

			
			memcpy(q,tmpq,256);
			tmpq+=256;
			/*We are going to decrypt 256 bytes at a time*/
			/*q points to the first 256 bytes of the message to be encrypted*/



			decipher_len_tmp=RSA_public_decrypt(256,q,deciphertext_tmp,key,padding);
			//deciphertext_tmp[decipher_len_tmp]='\0';
	

			

			decipher_len+=decipher_len_tmp;
			ciphertext_len_scanned+=256; /*256 bytes decrypted*/
	
			
		
	

			memcpy(plaintext+offset,deciphertext_tmp,245);
			offset+=245;
			
		}
		
	}	
	return decipher_len;
}


/*
 * RSA private key encryption
 */

int rsa_pub_encrypt(unsigned char *plaintext, int plaintext_len,RSA *key, unsigned char *ciphertext){
	int counter=0,cipher_len=0,cipher_len_tmp=0,plaintext_len_scanned=0,offset=0,qlen;
	unsigned char q[246],*tmpq,ciphertext_tmp[256];
	if(plaintext_len<=245){
		cipher_len=RSA_public_encrypt(plaintext_len,plaintext,ciphertext,key,padding);
	}else{

		tmpq=plaintext;
		while(plaintext_len_scanned<plaintext_len){

			/*We are going to encrypt 245 bytes at a time*/
			if(plaintext_len-plaintext_len_scanned>245){
				qlen=245;
				memcpy(q,tmpq,245);
			}else{
				counter=0;
				while(tmpq[counter]!=plaintext[plaintext_len])
					counter++;
				qlen=counter;
				memcpy(q,tmpq,counter);


			}
			tmpq+=245;
			/*q points to the first 245 bytes of the message to be encrypted*/
			cipher_len_tmp=RSA_public_encrypt(qlen,q,ciphertext_tmp,key,padding);

			cipher_len+=cipher_len_tmp;
			plaintext_len_scanned+=245; /*245 bytes encrypted*/
			memcpy(ciphertext+offset,ciphertext_tmp,256);
			offset+=256;
		}
		
	}
	return cipher_len;

}


/*
 * RSA public key decryption
 */

int rsa_prv_decrypt(unsigned char *ciphertext, int ciphertext_len,RSA *key, unsigned char *plaintext){
	int decipher_len=0,decipher_len_tmp=0,ciphertext_len_scanned=0,offset=0;
	unsigned char q[256],*tmpq,deciphertext_tmp[257];
	if(ciphertext_len<=256){
		decipher_len=RSA_private_decrypt(ciphertext_len,ciphertext,plaintext,key,padding);
	}else{

		tmpq=ciphertext;
		while(ciphertext_len_scanned<ciphertext_len){



			
			memcpy(q,tmpq,256);
			tmpq+=256;
			/*We are going to decrypt 256 bytes at a time*/
			/*q points to the first 256 bytes of the message to be encrypted*/


			decipher_len_tmp=RSA_private_decrypt(256,q,deciphertext_tmp,key,padding);
	
						


			decipher_len+=decipher_len_tmp;
			ciphertext_len_scanned+=256; /*256 bytes decrypted*/




			memcpy(plaintext+offset,deciphertext_tmp,245);
			offset+=245;

			
		}
		
	}	
	return decipher_len;

}




unsigned char *generateIV(){
	char IV[16];
	static char *iv_bytes;
	int choice,i;		
	srand(time(NULL));
	for(i=0;i<16;i++){

		choice=rand()%2+1; /*Randomly choose if you generate a random A-F or 0-9*/
		if(choice==1)
			IV[i]=(char)(rand()%6+65); /*Generate a random char from A-F*/
		else
			IV[i]=rand()%10+'0'; /*Generate a random number from 0-9*/	
	}
	iv_bytes=hex_to_bytes(IV);
	return iv_bytes;
}


/* EOF */
