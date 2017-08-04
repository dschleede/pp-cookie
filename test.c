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

        prepare_key((unsigned char *)_SV_RC4_KEY_DATA, _SV_RC4_KEY_LEN, &rc4_ctx);

        memset(rc4_cipher, 0, sizeof(rc4_cipher));
        memcpy(rc4_cipher, user, strlen(user));
        memcpy(&(rc4_cipher[strlen(user)  + 1]), ipaddr, strlen(ipaddr));

        sprintf(rand_str, "%d", rand_num);
        memcpy(&(rc4_cipher[strlen(user) + strlen(ipaddr) + 2]), rand_str, strlen(rand_str));
        rc4((unsigned char *)rc4_cipher, strlen(user)+strlen(ipaddr)+strlen(rand_str)+2, &rc4_ctx);
        //encode64(rc4_cipher, strlen(user)+strlen(ipaddr)+strlen(rand_str)+2, cookie_st, &cookie_len);
	outlen = (long unsigned int) cookie_len;
        cookietemp = base64_encode(rc4_cipher, strlen(user)+strlen(ipaddr)+strlen(rand_str)+2, &outlen);
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
  //random = 4;  // everyone knows that 4 is considered a random number
  random = rand();
  strcpy(user, "USERNAME");
  strcpy(ipaddr, "192.168.0.1");
  
  encode_cookie(cookie,user,ipaddr,random);
}

