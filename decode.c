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

char * decode_cookie(char *str, char *cookie, int *len)
{
        static char str_st[256];
        int str_len = sizeof(str_st);
	rc4_key rc4_ctx;
	long unsigned int dec_len;
	
	char *cookietemp;
	unsigned char ephemeral_key[128];
	SHA256_CTX sha256_ctx;

	
        //decode64(cookie, strlen(cookie), str_st, &str_len);
	// we have a different library, lets call the functional equivalent of the above statement
	dec_len = (long unsigned int) str_len;
	cookietemp = base64_decode(cookie, strlen(cookie), &dec_len);
	str_len = (int) dec_len;
	memset(str_st, 0, sizeof(str_st));
	memcpy(str_st, cookietemp, str_len);

        printf("%s  :  ",cookie);
#ifdef DEBUG
        printf("Base64 decoded cookie is (len=%d):\n",str_len);
        for(int xx=0;xx<str_len;xx++){printf("%c",str_st[xx]);}printf("\n");
#endif

	////////////////////////////////
	

	// Before we call the RC4 decode, we need to setup the key with the IV/Counter
	
	memset(ephemeral_key, 0, sizeof(ephemeral_key));
	memcpy(ephemeral_key, str_st, sizeof(int)*4);  //copy IV to key
	memcpy(ephemeral_key+sizeof(int)*4, _SV_RC4_KEY_DATA, _SV_RC4_KEY_LEN);  // Append the master key

	// We have the key, lets SHA256 it...
	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, ephemeral_key, (sizeof(int)*4) + _SV_RC4_KEY_LEN);
	sha256_final(&sha256_ctx, ephemeral_key); // Copy from SHA256 back to the key, length is 32 byte

	// lets reshift the encoded string and take out the IV
	memcpy(str_st, str_st+sizeof(int)*4,str_len-sizeof(int)*4);
	str_len -=sizeof(int)*4;

	//
	// (OLD) prepare_key(_SV_RC4_KEY_DATA, _SV_RC4_KEY_LEN, &rc4_ctx); // 20050803
	prepare_key((unsigned char *)ephemeral_key, SHA256_BLOCK_SIZE, &rc4_ctx); // 20050803
        rc4(str_st, str_len, &rc4_ctx);
        str_st[str_len] = 0x00;
        if (len) *len = str_len; // 20050205
	if (str) {
                //sprintf(str, "%s", str_st); // 20050204
                memcpy(str, str_st, str_len); // 20050204
                //separate_cookie(str);
                return str;
        } else {
                //separate_cookie(str_st);
                return str_st;
	}
}


int main(int argc, char *argv[])
{
  char cookie[256];
  unsigned char values[256];
  int random, val_len;

  strncpy(cookie, argv[1], sizeof(cookie)); cookie[256]=0;
  
  decode_cookie(values,cookie,&val_len);
  //printf("Decoded cookie is:\n");
  for(int xy=0;xy<val_len;xy++){printf("%c",values[xy]);}printf("\n");

}

