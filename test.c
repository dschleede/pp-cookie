#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "rc4.h"
#include "base64.h"

//lets define some global variables... don't want to taint the func call too much
unsigned char *_SV_RC4_KEY_DATA = "sample";
int _SV_RC4_KEY_LEN = 6;
char *cookietemp;
long unsigned int outlen;

char *encode_cookie(char *cookie, char *user, char *ipaddr, int rand_num)
{

        char rand_str[15] = {0, };
        char rc4_cipher[128];
        static char cookie_st[256];
        int cookie_len = sizeof(cookie_st);
        rc4_key rc4_ctx;

	//To use RC4 securely, we need to create an IV/nonce for each sessionid Generated. A short term key MUST
	// be derived from the combination of the long-term key and the nonce WITH a cryptographic hash function.
	// and NOT used by simply concatinating the nonce and key
	// the Nonce is NOT secret, and for decryption, the nonce can be appended to the beginning in plaintext
	// theoretically, you should NOT ever try to reuse a nonce without changing the long term key.
	// we need a minimal of 64 bits of entropy for the nonce if it is to be random

	prepare_key((unsigned char *)_SV_RC4_KEY_DATA, _SV_RC4_KEY_LEN, &rc4_ctx);

        memset(rc4_cipher, 0, sizeof(rc4_cipher));
	// creating the data to encrypt
	//we NEED to start first with the IV, this is CRITICAL, furhter IV should be 64 bits and FULLY compressed
	
        memcpy(rc4_cipher, &rand_num, sizeof(rand_num));

        memcpy(&(rc4_cipher[sizeof(rand_num)]), user, strlen(user));
        memcpy(&(rc4_cipher[sizeof(rand_num)+ strlen(user)  + 1]), ipaddr, strlen(ipaddr));

#ifdef DEBUG
	printf("Sizeof rand_num = %lu\n",sizeof(rand_num));
	printf("Len = %lu\n",strlen(user)+strlen(ipaddr)+sizeof(rand_num)+1);

	for(int xx=0;xx<(strlen(user)+strlen(ipaddr)+sizeof(rand_num)+1);xx++){
	  printf("%c",rc4_cipher[xx]);
	}
	printf("\n");
#endif
	rc4((unsigned char *)rc4_cipher, strlen(user)+strlen(ipaddr)+sizeof(rand_num)+1, &rc4_ctx);
        //encode64(rc4_cipher, strlen(user)+strlen(ipaddr)+strlen(rand_str)+2, cookie_st, &cookie_len);
	outlen = (long unsigned int) cookie_len;
        cookietemp = base64_encode(rc4_cipher, strlen(user)+strlen(ipaddr)+sizeof(rand_num)+1, &outlen);
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
  int random;

  srand(time(NULL));
  
  //assign a random number
  random = 4;  // everyone knows that 4 is considered a random number
  //random = rand();
  strcpy(user, "USERNAME");
  strcpy(ipaddr, "192.168.0.1");
  
  encode_cookie(cookie,user,ipaddr,random);
}

