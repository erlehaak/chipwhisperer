#include "randombytes.h"
#include "../hal/hal.h"
#include "kem.h"
#include "simpleserial.h"

#include <string.h>

unsigned char sk[KYBER_SECRETKEYBYTES];
unsigned char pk[KYBER_PUBLICKEYBYTES];
unsigned char ss_a[KYBER_SSBYTES], ss_b[KYBER_SSBYTES];
unsigned char ct[KYBER_CIPHERTEXTBYTES];

int i = 0;

static int key_gen(void)
{
  simpleserial_put('p', 48, pk);
  PQCLEAN_KYBER512_CLEAN_crypto_kem_keypair(pk, sk);
  simpleserial_put('p', 48, pk);
  return 0;
}

static int encrypt(void)
{
  PQCLEAN_KYBER512_CLEAN_crypto_kem_enc(ct, ss_b, pk);
}

static int decrypt(void)
{
  PQCLEAN_KYBER512_CLEAN_crypto_kem_dec(ss_a, ct, sk);
}

static int get_pk(void)
{
  
  int len = KYBER_PUBLICKEYBYTES; 

  if (i < len) {
        char chunk[33]; // 32 chars plus a null terminator       
        memcpy(chunk, pk + i, 32); // copy next 32 chars into the chunk array        
        chunk[32] = '\0'; // add a null terminator to the end of the chunk
        simpleserial_put('p', 32, chunk);
        i += 32;
  }
  return 0;
}

static int get_sk(void)
{
  int len = KYBER_SECRETKEYBYTES; //1632 bytes

  if (i < len) {
        char chunk[33]; // 32 chars plus a null terminator       
        memcpy(chunk, pk + i, 32); // copy next 32 chars into the chunk array        
        chunk[32] = '\0'; // add a null terminator to the end of the chunk
        simpleserial_put('s', 32, chunk);
        i += 32;
  }
  return 0;
}

static int get_ct(void)
{
  int len = KYBER_CIPHERTEXTBYTES; //768 bytes

  if (i < len) {
        char chunk[33]; // 32 chars plus a null terminator       
        memcpy(chunk, ct + i, 32); // copy next 32 chars into the chunk array        
        chunk[32] = '\0'; // add a null terminator to the end of the chunk
        simpleserial_put('s', 32, chunk);
        i += 32;
  }
  return 0;
}

static int get_ss_a(void){
  simpleserial_put('a', KYBER_SSBYTES, ss_a);
}

static int get_ss_b(void){
  simpleserial_put('a', KYBER_SSBYTES, ss_b);
}

static int get_255_pk(void)
{
	simpleserial_put('p', 255, pk); //uint8_t maks 255 byte :(
	return 0;
}

static int get_255_sk(void)
{
	simpleserial_put('s', 255, sk); //uint8_t maks 255 byte :(
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
  //reserverte simpleserial komandoer: 'v', 'y', 'w'
  simpleserial_addcmd('k', 0, key_gen);
  simpleserial_addcmd('e', 0, encrypt);
  simpleserial_addcmd('d', 0, decrypt);
  simpleserial_addcmd('p', 0, get_pk); 
  simpleserial_addcmd('s', 0, get_sk);
  simpleserial_addcmd('s', 0, get_ct);
  simpleserial_addcmd('a', 0, get_ss_a);
  simpleserial_addcmd('b', 0, get_ss_b);
  simpleserial_addcmd('f', 0, get_255_pk); 
  simpleserial_addcmd('g', 0, get_255_sk);
  simpleserial_addcmd('r', 0, reset);
  while(1)
		simpleserial_get();
 
  return 0;
}
