#include "randombytes.h"
#include "../hal/hal.h"
#include "kem.h"
#include "simpleserial.h"
#include "indcpa.h"

#include <string.h>

uint8_t sk[KYBER_SECRETKEYBYTES];
uint8_t pk[KYBER_PUBLICKEYBYTES];
uint8_t ss_a[KYBER_SSBYTES], ss_b[KYBER_SSBYTES];
uint8_t ct[KYBER_CIPHERTEXTBYTES];
uint8_t m[KYBER_INDCPA_MSGBYTES];
/*
int i = 0;

static uint8_t key_gen(uint8_t* m, uint8_t len)
{
  //simpleserial_put('p', 48, pk);
  PQCLEAN_KYBER512_CLEAN_crypto_kem_keypair(pk, sk);
  //simpleserial_put('p', 48, pk);
  return 0;
}

static uint8_t encrypt(uint8_t* m, uint8_t len)
{
  PQCLEAN_KYBER512_CLEAN_crypto_kem_enc(ct, ss_b, pk);
  return 0;
}

static uint8_t decrypt(uint8_t* m, uint8_t len)
{
  PQCLEAN_KYBER512_CLEAN_crypto_kem_dec(ss_a, ct, sk);
  return 0;
}

static uint8_t encrypt_indcpa(uint8_t* m, uint8_t len)
{
  uint8_t coins[KYBER_SYMBYTES];
  randombytes(coins, KYBER_SYMBYTES);
  simpleserial_put('$', KYBER_SYMBYTES, coins);
  PQCLEAN_KYBER512_CLEAN_indcpa_enc(ct, m, pk, coins);
  return 0;
}

static uint8_t get_pk(uint8_t* m, uint8_t inputLen)
{
  
  int len = KYBER_PUBLICKEYBYTES; 

  if (i < len) {
        uint8_t chunk[33]; // 32 chars plus a null terminator       
        memcpy(chunk, pk + i, 32); // copy next 32 chars into the chunk array        
        chunk[32] = '\0'; // add a null terminator to the end of the chunk
        simpleserial_put('p', 32, chunk);
        i += 32;
  }
  return 0;
}

static uint8_t get_sk(uint8_t* m, uint8_t inputLen)
{
  int len = KYBER_SECRETKEYBYTES; //1632 bytes

  if (i < len) {
        uint8_t chunk[33]; // 32 chars plus a null terminator       
        memcpy(chunk, pk + i, 32); // copy next 32 chars into the chunk array        
        chunk[32] = '\0'; // add a null terminator to the end of the chunk
        simpleserial_put('s', 32, chunk);
        i += 32;
  }
  return 0;
}

static uint8_t get_ct(uint8_t* m, uint8_t inputLen)
{
  int len = KYBER_CIPHERTEXTBYTES; //768 bytes

  if (i < len) {
        uint8_t chunk[33]; // 32 chars plus a null terminator       
        memcpy(chunk, ct + i, 32); // copy next 32 chars into the chunk array        
        chunk[32] = '\0'; // add a null terminator to the end of the chunk
        simpleserial_put('c', 32, chunk);
        i += 32;
  }
  return 0;
}

static uint8_t get_ss_a(uint8_t* m, uint8_t len){
  simpleserial_put('a', KYBER_SSBYTES, ss_a);
  return 0;
}

static uint8_t get_ss_b(uint8_t* m, uint8_t len){
  simpleserial_put('b', KYBER_SSBYTES, ss_b);
  return 0;
}

static uint8_t get_255_pk(uint8_t* m, uint8_t len)
{
	simpleserial_put('p', 255, pk); //uint8_t maks 255 byte :(
	return 0;
}

static uint8_t get_255_sk(uint8_t* m, uint8_t len)
{
	simpleserial_put('s', 255, sk); //uint8_t maks 255 byte :(
	return 0;
}

static uint8_t reset(uint8_t* m, uint8_t len)
{
  i = 0;
  return 0;
}
*/
int main(void)
{
  
  platform_init();
	init_uart();
	trigger_setup();

  simpleserial_init();
  /*
  //reserverte simpleserial komandoer: 'v', 'y', 'w'
  simpleserial_addcmd('k', 0, key_gen);
  simpleserial_addcmd('e', 0, encrypt);
  simpleserial_addcmd('d', 0, decrypt);
  simpleserial_addcmd('i', 0, encrypt_indcpa);
  simpleserial_addcmd('p', 0, get_pk); 
  simpleserial_addcmd('s', 0, get_sk);
  simpleserial_addcmd('c', 0, get_ct);
  simpleserial_addcmd('a', 0, get_ss_a);
  simpleserial_addcmd('b', 0, get_ss_b);
  simpleserial_addcmd('f', 0, get_255_pk); 
  simpleserial_addcmd('g', 0, get_255_sk);
  simpleserial_addcmd('r', 0, reset);

  while(1)
		simpleserial_get();
*/
//For debugging:
  putch('1');
  PQCLEAN_KYBER512_CLEAN_crypto_kem_keypair(pk, sk);
  putch('2');
  PQCLEAN_KYBER512_CLEAN_crypto_kem_enc(ct, ss_b, pk);
  putch('3');
  PQCLEAN_KYBER512_CLEAN_crypto_kem_dec(ss_a, ct, sk);
  putch('4');
  simpleserial_put('a', KYBER_SSBYTES, ss_a);
  simpleserial_put('b', KYBER_SSBYTES, ss_b);
 
  return 0;
}
