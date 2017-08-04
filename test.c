#include <stdio.h>
#include "rc4.h"
#include "base64.h"

unsigned *char _SV_RC4_KEY_DATA = "xyzzy";
int _SV_RC4_KEY_LEN = 5;

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

	printf("here\n");
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

  //assign a random number
  random = 4;  // everyone knows that 4 is considered a random number
  strcpy(user, "dschleed");
  strcpy(ipaddr, "192.168.1.1");
  
  encode_cookie(cookie,user,ipaddr,random);
}
