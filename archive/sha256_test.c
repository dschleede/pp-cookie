#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include "sha256.h"

/*********************** FUNCTION DEFINITIONS ***********************/
int sha256_test(char *key, char *data)
{
  BYTE buf[SHA256_BLOCK_SIZE];
  SHA256_CTX ctx;
  int len, i;
  char rbuffer[1000];

  unsigned char imei[4096];
  unsigned char secret[65];
  unsigned char secr[4096];
  unsigned char ipad[65];
  unsigned char opad[65];
  char *pos;
  int count;

  

  //strncpy(imei, "000000000000000000409DFFFF508324", 32);
  //strncpy(secret, "secret\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 64);

  if(strlen(key)>8192) { exit(1); } //no buffer overflow, we should fix with malloc
  if(strlen(key)>128) {
    // If key is greater than 64 bytes, then reset key to SHA256(key)

    pos = key;
    for(count=0;count < strlen(key)/2;count++) {
      sscanf(pos, "%2hhx", &secr[count]);
      pos += 2;
    }
    sha256_init(&ctx);
    sha256_update(&ctx, secr, strlen(key)/2);
    sha256_final(&ctx, buf);

    //zero string secret
    for(count=0;count<64;count++) secret[count]=0x00;
    strncpy(secret, buf, 32);  // copy over buf to secret
  } else {
    // secret is less than 64 bytes

    //zero string secret
    for(count=0;count<64;count++) secret[count]=0x00;
    // Convert into secret
    pos = key;
    for(count=0;count < strlen(key)/2;count++) {
      sscanf(pos, "%2hhx", &secret[count]);
      pos += 2;
    }
  }


  // convert Data from hex Representation
  pos = data;
  for(count=0;count < strlen(data)/2;count++) {
    sscanf(pos, "%2hhx", &imei[count]);
    pos += 2;
  }


  // Start HMAC
  strncpy(ipad, secret, 64);
  strncpy(opad, secret, 64);

  for(i=0;i<64;i++) {
    ipad[i] ^= 0x36;
    opad[i] ^= 0x5c;
  }
  
  /* Perform inner hash */
  sha256_init(&ctx);
  sha256_update(&ctx, ipad, 64);
  sha256_update(&ctx, imei, strlen(data)/2);
  sha256_final(&ctx, buf);

  /* Perform outer hash */
  sha256_init(&ctx);
  sha256_update(&ctx, opad, 64);
  sha256_update(&ctx, buf, 32);
  sha256_final(&ctx, buf);


  /* Print out the final HMAC */
  //printf("Final HMAC is :");
  for(len=0;len<SHA256_BLOCK_SIZE;len++) {
    printf("%02x",buf[len]);
  }
  printf("\n");


}

int main(int argc, char *argv[])
{
  if (argc!=3) {
    printf("Error, need to provide 2 arguments in hex : %s KEY  VALUE\n",argv[0]);
    return(1);
  }

  //printf("SHA256 HMAC tests\n");
  sha256_test(argv[1],argv[2]); //key, data

  return(0);
}
