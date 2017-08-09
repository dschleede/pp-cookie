#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "rc4.h"
#include "base64.h"
#include "sha256.h"

//lets define some global variables... don't want to taint the func call too much
unsigned char *_SV_RC4_KEY_DATA = "sample";
int _SV_RC4_KEY_LEN = 6;
char *cookietemp;
long unsigned int outlen;

char *encode_cookie(char *cookie, char *user, char *ipaddr, int rand_num,int rand2,int rand3,int rand4)
{

        char rand_str[15] = {0, };
        char rc4_cipher[128];
        static char cookie_st[256];
        int cookie_len = sizeof(cookie_st);
        rc4_key rc4_ctx;
	unsigned char ephemeral_key[128];
	SHA256_CTX sha256_ctx;
	unsigned char tempcookie[256];

	// To use RC4 securely, we need to create an IV/nonce for each sessionid Generated. A short term key MUST
	// be derived from the combination of the long-term key and the nonce WITH a cryptographic hash function.
	// and NOT used by simply concatinating the nonce and key
	// the Nonce is NOT secret, and for decryption, the nonce can be appended to the beginning in plaintext
	// theoretically, you should NOT ever try to reuse a nonce without changing the long term key.
	// we need a minimal of 64 bits of entropy for the nonce if it is to be random

	

	memset(ephemeral_key, 0, sizeof(ephemeral_key));
	memcpy(ephemeral_key, &rand_num, sizeof(rand_num));  //copy binary representation to key, we want ALL bits to possibly change
	memcpy(ephemeral_key+sizeof(rand_num), &rand2, sizeof(rand_num));  //copy binary representation to key
	memcpy(ephemeral_key+sizeof(rand_num)*2, &rand3, sizeof(rand_num));  //copy binary representation to key
	memcpy(ephemeral_key+sizeof(rand_num)*3, &rand4, sizeof(rand_num));  //copy binary representation to key
	memcpy(ephemeral_key+sizeof(rand_num)*4, _SV_RC4_KEY_DATA, _SV_RC4_KEY_LEN);  // Append the master key
	
#ifdef DEBUG
	printf("Sizeof ephemeral_key = %lu\n",sizeof(rand_num)*4+_SV_RC4_KEY_LEN);
        for(int xy=0;xy<(sizeof(rand_num)*4+_SV_RC4_KEY_LEN);xy++){printf("%c",ephemeral_key[xy]);}printf("\n");
#endif

	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, ephemeral_key, sizeof(rand_num)*4 + _SV_RC4_KEY_LEN);
	sha256_final(&sha256_ctx, ephemeral_key); // Copy from SHA256 buffer back to the key, length is 32 bytes (fixed for SHA256)

#ifdef DEBUG
	printf("Binary Ephemeral key ->");
        for(int xa=0;xa<32;xa++){printf("%c",ephemeral_key[xa]);}printf("<-\n");
#endif


	//prepare_key((unsigned char *)_SV_RC4_KEY_DATA, _SV_RC4_KEY_LEN, &rc4_ctx);
	prepare_key((unsigned char *)ephemeral_key, SHA256_BLOCK_SIZE, &rc4_ctx);

	memset(rc4_cipher, 0, sizeof(rc4_cipher));
        memcpy(rc4_cipher, user, strlen(user));
        memcpy(&(rc4_cipher[strlen(user)  + 1]), ipaddr, strlen(ipaddr));

#ifdef DEBUG
	printf("Sizeof rand_num = %lu\n",sizeof(rand_num));printf("Len = %lu\n",strlen(user)+strlen(ipaddr)+2);
        for(int xx=0;xx<(strlen(user)+strlen(ipaddr)+2);xx++){printf("%c",rc4_cipher[xx]);}printf("\n");
#endif
	rc4((unsigned char *)rc4_cipher, strlen(user)+strlen(ipaddr)+2, &rc4_ctx);

        // We now need to append the IV to the front of the Cookie, and then call the base64 encode
	memset(tempcookie, 0, sizeof(tempcookie));
        memcpy(tempcookie, &rand_num, sizeof(rand_num));
	memcpy(&(tempcookie[sizeof(rand_num)]), &rand2, sizeof(rand_num));
	memcpy(&(tempcookie[sizeof(rand_num)*2]), &rand3, sizeof(rand_num));
	memcpy(&(tempcookie[sizeof(rand_num)*3]), &rand4, sizeof(rand_num));
        memcpy(&(tempcookie[sizeof(rand_num)*4]), rc4_cipher, strlen(user)+strlen(ipaddr)+2);


        //encode64(rc4_cipher, strlen(user)+strlen(ipaddr)+1, cookie_st, &cookie_len);
	outlen = (long unsigned int) cookie_len;
        cookietemp = base64_encode(tempcookie, sizeof(rand_num)*4+strlen(user)+strlen(ipaddr)+2, &outlen);
	// Lets copy this to the local buffer
	cookie_len = (int) outlen;
	strncpy(cookie_st, cookietemp,cookie_len);
	
	printf("%s\n",cookie_st);
        cookie_st[cookie_len] = 0x00;
        if (cookie) {
                sprintf(cookie, "%s", cookie_st);
                return cookie;
        } else return cookie_st;
}

int main()
{
  char cookie[256],user[256],ipaddr[256];
  int random,rand2,rand3,rand4;

  srand(time(NULL));
  
  //assign a random number
  //random = 4;  // everyone knows that 4 is considered a random number
  random = rand();
  rand2 = rand();
  rand3 = rand();
  rand4 = rand();
  strcpy(user, "USERNAME");
  strcpy(ipaddr, "192.168.0.1");
  
  encode_cookie(cookie,user,ipaddr,random,rand2,rand3,rand4);
}

