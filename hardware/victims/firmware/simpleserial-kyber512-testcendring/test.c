#include "randombytes.h"
#include "../hal/hal.h"
#include "kem.h"
#include "simpleserial.h"

#include <string.h>

unsigned char sk[KYBER_SECRETKEYBYTES];
unsigned char pk[KYBER_PUBLICKEYBYTES];
unsigned char ss_a[KYBER_SSBYTES], ss_b[KYBER_SSBYTES];
unsigned char send[KYBER_CIPHERTEXTBYTES];

int i = 0;

static int test_keys(void)
{
  
  
  simpleserial_put('r', 48, pk);
  //Alice generates a public key
  PQCLEAN_KYBER512_CLEAN_crypto_kem_keypair(pk, sk);

  //Bob derives a secret key and creates a response
  //PQCLEAN_KYBER512_CLEAN_crypto_kem_enc(send, ss_b, pk);

  //Alice uses Bobs response to get her secret key
  //PQCLEAN_KYBER512_CLEAN_crypto_kem_dec(ss_a, send, sk);

  simpleserial_put('f', 48, pk);
  return 0;
}

static int get_pk(void)
{
  
  int len = KYBER_PUBLICKEYBYTES;

  if (i < len) {
        char chunk[97]; // 32 chars plus a null terminator       
        strncpy(chunk, pk + i, 96); // copy chunk 96 into the chunk array        
        chunk[96] = '\0'; // add a null terminator to the end of the chunk
        simpleserial_put('p', 96, chunk);
        i += 96;

  }

  return 0;
}

static int reset(void)
{
  i = 0;

  return 0;
}


int main(void)
{
  platform_init();
	init_uart();
	trigger_setup();

  simpleserial_init();

  simpleserial_addcmd('k', 0, test_keys);
  simpleserial_addcmd('p', 0, get_pk);
  simpleserial_addcmd('r', 0, reset);

  while(1)
		simpleserial_get();
 
  return 0;
}
