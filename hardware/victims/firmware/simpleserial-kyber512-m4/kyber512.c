/*
    This file is part of the ChipWhisperer Example Targets
    Copyright (C) 2012-2017 NewAE Technology Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "../hal/hal.h"
#include "simpleserial.h"
#include "params.h"
#include "indcpa.h"
#include "randombytes.h"
#include <string.h>

//uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES];
//uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES]; 
uint8_t ct[KYBER_INDCPA_BYTES]; 
uint8_t m_input[KYBER_INDCPA_MSGBYTES];
uint8_t m_output[KYBER_INDCPA_MSGBYTES];
uint8_t coin[KYBER_SYMBYTES];

uint8_t static_sk[] = {54, 234, 119, 184, 119, 11, 107, 165, 191, 181, 75, 41, 167, 48, 13, 173, 33, 199, 21, 168, 119, 101, 66, 127, 237, 119, 28, 224, 219, 136, 160, 36, 107, 228, 240, 150, 163, 210, 48, 55, 208, 137, 241, 56, 145, 11, 203, 126, 163, 22, 78, 115, 92, 120, 46, 59, 126, 9, 42, 80, 72, 139, 135, 117, 182, 64, 156, 32, 173, 189, 130, 4, 5, 161, 191, 222, 244, 24, 239, 101, 40, 214, 20, 176, 68, 160, 134, 59, 74, 181, 143, 17, 3, 122, 193, 205, 117, 65, 59, 1, 37, 44, 85, 102, 104, 125, 236, 201, 59, 70, 10, 150, 247, 185, 188, 37, 22, 243, 179, 34, 85, 59, 156, 67, 224, 201, 73, 17, 24, 194, 23, 124, 160, 76, 68, 102, 186, 46, 77, 37, 170, 181, 234, 164, 197, 121, 204, 35, 38, 101, 244, 120, 170, 53, 42, 20, 115, 193, 138, 80, 212, 171, 211, 146, 179, 78, 51, 22, 255, 18, 166, 86, 164, 66, 109, 224, 33, 122, 144, 130, 175, 248, 14, 193, 4, 27, 172, 88, 132, 7, 4, 10, 63, 245, 118, 32, 232, 181, 66, 4, 10, 13, 152, 141, 56, 35, 139, 131, 200, 76, 213, 21, 99, 54, 138, 185, 223, 49, 153, 160, 244, 34, 86, 10, 135, 161, 121, 144, 5, 234, 38, 36, 68, 98, 95, 0, 9, 90, 194, 184, 144, 161, 175, 52, 163, 142, 57, 124, 162, 6, 241, 163, 197, 149, 189, 230, 230, 51, 6, 230, 206, 240, 92, 63, 209, 124, 84, 24, 83, 133, 53, 44, 71, 245, 164, 86, 204, 152, 174, 224, 50, 84, 12, 213, 48, 92, 180, 155, 100, 90, 186, 109, 156, 151, 189, 106, 72, 31, 56, 188, 98, 209, 166, 223, 209, 182, 216, 184, 32, 78, 133, 26, 78, 203, 202, 3, 138, 163, 85, 50, 72, 233, 1, 39, 228, 16, 122, 183, 171, 27, 110, 249, 20, 157, 131, 134, 14, 17, 40, 168, 3, 9, 183, 183, 108, 120, 131, 89, 31, 92, 102, 33, 35, 94, 159, 2, 41, 23, 163, 163, 167, 211, 33, 97, 152, 97, 226, 86, 30, 130, 128, 10, 237, 51, 36, 218, 33, 23, 51, 115, 30, 60, 177, 207, 103, 170, 35, 174, 3, 170, 92, 27, 92, 189, 37, 99, 110, 25, 98, 137, 197, 39, 185, 178, 46, 225, 60, 75, 105, 193, 17, 138, 244, 183, 49, 83, 169, 127, 100, 78, 233, 55, 159, 8, 70, 17, 215, 57, 12, 160, 196, 130, 247, 17, 3, 227, 228, 132, 76, 165, 46, 192, 181, 191, 39, 120, 166, 111, 204, 149, 55, 10, 42, 134, 137, 159, 224, 215, 39, 13, 217, 9, 229, 76, 118, 91, 50, 155, 196, 113, 180, 212, 240, 95, 214, 35, 141, 49, 199, 151, 158, 72, 186, 128, 132, 43, 195, 66, 85, 246, 50, 199, 239, 183, 178, 113, 137, 107, 151, 49, 177, 173, 188, 19, 53, 182, 10, 172, 28, 190, 10, 0, 169, 176, 169, 49, 63, 184, 73, 192, 19, 30, 232, 220, 38, 222, 36, 175, 231, 169, 108, 183, 22, 180, 110, 10, 86, 205, 6, 26, 151, 215, 32, 146, 163, 128, 98, 145, 191, 87, 177, 9, 167, 119, 171, 44, 211, 98, 204, 151, 39, 201, 161, 44, 246, 197, 58, 236, 98, 19, 129, 24, 34, 209, 10, 114, 166, 96, 72, 114, 147, 84, 71, 147, 73, 155, 36, 15, 250, 137, 104, 35, 134, 101, 91, 36, 81, 169, 167, 12, 20, 76, 140, 239, 80, 191, 170, 165, 38, 48, 83, 36, 131, 172, 118, 39, 114, 197, 40, 135, 75, 247, 219, 62, 57, 196, 105, 134, 229, 136, 92, 81, 136, 21, 194, 98, 220, 247, 145, 82, 150, 7, 193, 136, 132, 219, 226, 95, 20, 181, 138, 154, 55, 195, 149, 152, 24, 0, 25, 30, 73, 213, 6, 208, 84, 113, 203, 241, 195, 60, 3, 58, 107, 59, 163, 174, 214, 110, 164, 38, 200, 244, 103, 35, 88, 86, 187, 223, 242, 25, 180, 132, 195, 0, 113, 173, 112, 50, 38, 243, 245, 3, 68, 53, 193, 27, 160, 104, 56, 185, 77, 33, 228, 14, 219, 242, 84, 69, 235, 176, 215, 2, 117, 174, 181, 89, 91, 138, 154, 11, 228, 47, 223, 160, 17, 172, 188, 170, 111, 59, 103, 155, 242, 60, 98, 246, 186, 142, 38, 55, 19, 236, 139, 2, 9, 49, 200, 24, 198, 238, 199, 165, 148, 217, 82, 120, 160, 150};
uint8_t static_pk[] = {236, 70, 23, 249, 128, 71, 17, 219, 205, 155, 33, 7, 201, 51, 12, 72, 199, 136, 238, 9, 36, 62, 25, 154, 143, 88, 8, 170, 82, 95, 114, 116, 204, 85, 180, 46, 244, 129, 111, 125, 34, 207, 5, 24, 97, 49, 84, 205, 226, 210, 155, 147, 131, 1, 69, 42, 53, 168, 169, 66, 147, 245, 117, 115, 36, 169, 228, 27, 189, 117, 43, 61, 40, 245, 154, 206, 116, 81, 108, 92, 39, 207, 176, 41, 49, 51, 123, 150, 136, 27, 75, 54, 181, 142, 58, 97, 88, 171, 161, 228, 149, 112, 88, 25, 43, 62, 72, 93, 78, 49, 112, 7, 69, 79, 63, 68, 84, 111, 48, 202, 148, 25, 24, 218, 244, 116, 1, 28, 84, 8, 243, 30, 12, 1, 122, 69, 171, 67, 85, 230, 80, 24, 84, 175, 149, 83, 114, 147, 139, 113, 226, 132, 19, 109, 163, 0, 75, 49, 184, 60, 96, 61, 14, 57, 151, 96, 148, 116, 25, 134, 8, 139, 248, 46, 29, 9, 182, 11, 252, 147, 188, 59, 161, 220, 124, 170, 16, 108, 12, 23, 37, 197, 83, 214, 92, 226, 161, 77, 93, 83, 187, 54, 214, 15, 157, 17, 183, 196, 154, 120, 91, 90, 89, 121, 3, 58, 228, 75, 16, 79, 209, 207, 175, 209, 193, 225, 135, 35, 211, 37, 168, 119, 6, 73, 15, 52, 111, 161, 16, 200, 48, 139, 27, 81, 213, 14, 143, 196, 122, 255, 144, 196, 247, 155, 40, 130, 156, 111, 190, 103, 136, 59, 92, 193, 95, 6, 198, 187, 169, 83, 3, 122, 67, 19, 89, 10, 162, 177, 142, 79, 235, 203, 244, 67, 127, 91, 53, 205, 141, 148, 47, 212, 180, 109, 135, 8, 39, 48, 75, 204, 1, 28, 139, 51, 36, 201, 228, 129, 43, 115, 115, 58, 249, 201, 203, 203, 164, 18, 18, 81, 73, 135, 203, 10, 63, 133, 159, 254, 241, 194, 103, 124, 57, 57, 20, 123, 213, 86, 26, 127, 33, 95, 169, 38, 165, 198, 19, 202, 218, 153, 179, 243, 58, 82, 101, 198, 82, 209, 178, 89, 130, 179, 147, 220, 248, 124, 36, 35, 148, 162, 178, 99, 88, 161, 88, 205, 124, 71, 77, 40, 136, 3, 66, 51, 37, 10, 59, 220, 59, 4, 255, 44, 157, 133, 83, 181, 110, 101, 98, 217, 66, 72, 105, 81, 98, 214, 148, 52, 54, 74, 151, 32, 180, 92, 29, 88, 66, 179, 201, 24, 183, 50, 194, 26, 117, 66, 128, 201, 165, 16, 3, 106, 237, 4, 58, 90, 33, 44, 108, 232, 119, 210, 250, 202, 51, 144, 183, 227, 169, 54, 217, 187, 71, 22, 198, 154, 203, 101, 51, 240, 58, 165, 157, 185, 187, 117, 86, 29, 116, 83, 33, 150, 70, 184, 247, 130, 153, 145, 75, 5, 114, 168, 38, 77, 67, 74, 12, 182, 141, 86, 112, 94, 139, 241, 206, 23, 8, 93, 39, 161, 126, 168, 169, 84, 31, 120, 146, 2, 117, 2, 248, 185, 193, 239, 70, 156, 183, 8, 131, 242, 136, 44, 217, 162, 182, 138, 33, 145, 87, 135, 29, 53, 156, 125, 142, 218, 9, 148, 137, 150, 233, 246, 96, 115, 34, 174, 69, 166, 162, 80, 148, 86, 140, 19, 35, 172, 195, 168, 175, 98, 90, 107, 52, 51, 209, 167, 169, 140, 43, 102, 186, 76, 74, 190, 246, 203, 254, 226, 112, 143, 249, 90, 43, 12, 103, 19, 9, 199, 199, 2, 10, 37, 92, 111, 131, 195, 47, 172, 54, 164, 118, 179, 123, 249, 164, 189, 109, 245, 153, 90, 163, 39, 13, 194, 137, 114, 58, 182, 176, 226, 161, 77, 96, 204, 192, 112, 149, 242, 34, 159, 148, 170, 160, 178, 220, 168, 159, 54, 78, 55, 169, 199, 161, 145, 166, 104, 68, 104, 184, 99, 58, 198, 3, 57, 52, 183, 189, 161, 177, 61, 212, 68, 15, 162, 140, 154, 103, 228, 25, 110, 248, 148, 62, 124, 189, 238, 156, 152, 216, 52, 85, 70, 167, 8, 250, 150, 111, 133, 160, 207, 6, 121, 166, 191, 162, 43, 180, 117, 138, 61, 80, 182, 99, 25, 84, 157, 22, 139, 203, 122, 163, 42, 43, 140, 58, 177, 18, 3, 18, 5, 201, 108, 51, 214, 177, 65, 56, 150, 157, 62, 184, 26, 1, 55, 173, 56, 138, 147, 165, 252, 76, 47, 3, 124, 245, 165, 195, 93, 166, 199, 60, 246, 79, 126, 99, 179, 213, 230, 132, 173, 219, 35, 190, 5, 74, 85, 137, 70, 249, 183, 203, 119, 214, 179, 133, 214, 152, 251, 45, 80, 106, 97, 161, 39, 231, 26, 175, 209, 181, 249, 96, 52, 168, 164, 222, 4, 242, 144, 11, 208};

int i = 0;

static uint8_t key_gen(uint8_t* m, uint8_t len)
{
  indcpa_keypair(static_pk, static_sk);
  return 0;
}

static uint8_t encrypt(uint8_t* m, uint8_t len)
{
  randombytes(coin, KYBER_SYMBYTES); //Random coin
  indcpa_enc(ct , m_input, static_pk, coin);
  return 0;
}

static uint8_t decrypt(uint8_t* m, uint8_t len)
{ 
  trigger_high();
  indcpa_dec(m_output, ct, static_sk);
  trigger_low(); 
  return 0;
}


static uint8_t get_pk(uint8_t* m, uint8_t inputLen)
{
  int len = KYBER_INDCPA_PUBLICKEYBYTES; 

  if (i < len) {
        uint8_t chunk[33]; // 32 chars plus a null terminator       
        memcpy(chunk, static_pk + i, 32); // copy next 32 chars into the chunk array        
        chunk[32] = '\0'; // add a null terminator to the end of the chunk
        simpleserial_put('p', 32, chunk);
        i += 32;
  }
  return 0;
}

static uint8_t get_sk(uint8_t* m, uint8_t inputLen)
{
  int len = KYBER_INDCPA_SECRETKEYBYTES; //1632 bytes

  if (i < len) {
        uint8_t chunk[33]; // 32 chars plus a null terminator       
        memcpy(chunk, static_sk + i, 32); // copy next 32 chars into the chunk array        
        chunk[32] = '\0'; // add a null terminator to the end of the chunk
        simpleserial_put('s', 32, chunk);
        i += 32;
  }
  return 0;
}

static uint8_t get_ct(uint8_t* m, uint8_t inputLen)
{
  int len = KYBER_INDCPA_BYTES; //768 bytes

  if (i < len) {
        uint8_t chunk[33]; // 32 chars plus a null terminator       
        memcpy(chunk, ct + i, 32); // copy next 32 chars into the chunk array        
        chunk[32] = '\0'; // add a null terminator to the end of the chunk
        simpleserial_put('c', 32, chunk);
        i += 32;
  }
  return 0;
}

static uint8_t get_plaintext_input(uint8_t* m, uint8_t len){
  randombytes(m_input, KYBER_INDCPA_MSGBYTES); // Generate new random input message
  simpleserial_put('i', KYBER_INDCPA_MSGBYTES, m_input);
  return 0;
}

static uint8_t get_plaintext_output(uint8_t* m, uint8_t len){
  simpleserial_put('o', KYBER_INDCPA_MSGBYTES, m_output);
  return 0;
}

static uint8_t reset_counter(uint8_t* m, uint8_t len)
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
  /*
  //Reserved simpleserial commands: 'v', 'y', 'w'
  simpleserial_addcmd('k', 0, key_gen);
  simpleserial_addcmd('e', 0, encrypt);
  simpleserial_addcmd('d', 0, decrypt);
  
  simpleserial_addcmd('r', 0, reset_counter);
  
  simpleserial_addcmd('p', 0, get_pk);
  simpleserial_addcmd('s', 0, get_sk);
  simpleserial_addcmd('c', 0, get_ct);
  simpleserial_addcmd('i', 0, get_plaintext_input);
  simpleserial_addcmd('o', 0, get_plaintext_output);
  /*
  while(1)
		simpleserial_get();
  
  /*
  */
  //Test just cpa functions
  
  //randombytes(m_input, KYBER_INDCPA_MSGBYTES); //random input plaintext
  //randombytes(coin, KYBER_SYMBYTES);  //random coins
  
  //uint8_t m_output[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,255};

  //indcpa_keypair(pk, sk);
  //indcpa_enc(ct , m_input, static_pk, coin);
  
  uint8_t ct[] = {0x15, 0x2d, 0xfb, 0x64, 0x10, 0x26, 0x71, 0x66, 0x7d, 0x88, 0x93, 0xcf, 0xc2, 0xff, 0xc4, 0x50, 0xe8, 0xb8, 0x6c, 0xaa, 0x32, 0x7c, 0x32, 0xf, 0xc, 0xbc, 0xe, 0x52, 0x28, 0x89, 0xdc, 0x84, 0xf2, 0xea, 0x96, 0x48, 0xaf, 0x3c, 0xe2, 0xdb, 0xdc, 0x21, 0xe5, 0x97, 0x7e, 0x60, 0xdc, 0x92, 0xe7, 0xdb, 0x5e, 0xaf, 0xd8, 0x2d, 0x69, 0xa3, 0x3, 0xcc, 0x5d, 0x34, 0x7a, 0xb5, 0x93, 0xa2, 0x3e, 0xa3, 0x4b, 0x8a, 0x24, 0x98, 0x91, 0xce, 0x2, 0x83, 0x23, 0x46, 0x17, 0x7c, 0x42, 0x53, 0xbe, 0xb, 0x70, 0x6c, 0xbb, 0x8e, 0x21, 0x16, 0xcf, 0x1a, 0xed, 0x79, 0x2f, 0x51, 0x37, 0x5, 0xe0, 0x4b, 0x25, 0x64, 0x4e, 0xd4, 0x8e, 0x73, 0x12, 0x61, 0xf3, 0x61, 0x9d, 0xc3, 0xd5, 0xe6, 0xca, 0x18, 0x2c, 0xef, 0xe1, 0x6a, 0x25, 0xd8, 0xe9, 0xb3, 0xcc, 0xe1, 0x77, 0xf6, 0xed, 0x93, 0xf7, 0xdf, 0x12, 0xad, 0x87, 0x65, 0x9, 0x2c, 0x36, 0x11, 0x42, 0xe2, 0xab, 0x3f, 0x8f, 0x43, 0xa8, 0xf2, 0x2f, 0xc1, 0xd0, 0x63, 0xd7, 0xf6, 0x1c, 0x21, 0x8a, 0x22, 0x1c, 0x5b, 0xe4, 0xc6, 0xfd, 0x58, 0x65, 0x2f, 0xfd, 0xf5, 0xfd, 0x47, 0x48, 0xf, 0x3, 0xbd, 0xc6, 0xf9, 0x51, 0x9, 0xa5, 0x91, 0xdd, 0x2c, 0x3, 0x18, 0xd9, 0xf2, 0xaa, 0x6b, 0xcf, 0x45, 0x4b, 0x23, 0xc6, 0x5b, 0xb0, 0xd8, 0x1a, 0x3e, 0x4, 0x7d, 0x6a, 0x3c, 0x5c, 0xff, 0x51, 0xa6, 0xc8, 0x4f, 0xa8, 0x99, 0x71, 0x6, 0x7a, 0x1b, 0x7b, 0x64, 0x63, 0x4f, 0x73, 0xd8, 0x7a, 0x5f, 0x0, 0xfb, 0xb7, 0xe4, 0xa0, 0xf, 0xe5, 0xd, 0x73, 0x5f, 0xf9, 0x37, 0x3e, 0xb2, 0xad, 0x3, 0x8e, 0xf0, 0xc5, 0x8f, 0xbf, 0xce, 0x81, 0x82, 0x95, 0x6e, 0x8b, 0xf7, 0x5f, 0x8b, 0x3d, 0x76, 0xd9, 0xa2, 0x7e, 0xc5, 0xf9, 0x31, 0x42, 0xb4, 0xca, 0x5a, 0xbc, 0x48, 0x7e, 0x63, 0x96, 0x73, 0x79, 0x68, 0x69, 0xc4, 0x75, 0xc4, 0xda, 0xf1, 0xa3, 0xbe, 0xc9, 0x5, 0x45, 0xb9, 0x54, 0x13, 0x87, 0xfe, 0xc7, 0xe0, 0x6e, 0xce, 0x27, 0xb0, 0x39, 0x9c, 0xb2, 0xe3, 0x42, 0x66, 0x75, 0x85, 0x9d, 0x38, 0x6b, 0x47, 0xee, 0x1c, 0x80, 0x86, 0x29, 0x3c, 0xf1, 0x84, 0x87, 0x55, 0xca, 0xc9, 0xe4, 0x59, 0x82, 0xef, 0xea, 0x51, 0xe4, 0x72, 0x58, 0x70, 0x49, 0xea, 0x86, 0x42, 0xc, 0x47, 0x4e, 0x1e, 0x89, 0x3, 0x47, 0xb1, 0x24, 0x34, 0x7d, 0xd1, 0xca, 0xa0, 0x86, 0x64, 0x1a, 0xfa, 0x85, 0xbe, 0x13, 0x83, 0x53, 0x6a, 0x72, 0x96, 0xfb, 0x8d, 0x60, 0x3e, 0x30, 0xda, 0xb1, 0xff, 0xdb, 0xc9, 0x74, 0x75, 0xf, 0x93, 0x39, 0x17, 0x97, 0x34, 0x76, 0x1, 0x20, 0xd7, 0xf0, 0x46, 0x77, 0x15, 0x75, 0xd4, 0x9e, 0x5a, 0x1d, 0xe6, 0xbf, 0x67, 0x95, 0xf1, 0x88, 0x15, 0x3d, 0xfe, 0x40, 0x3e, 0x1, 0x4a, 0xd1, 0x40, 0xa4, 0xd6, 0xba, 0x50, 0x60, 0x4d, 0x9, 0x41, 0x3a, 0x3, 0x89, 0xfb, 0x50, 0xe4, 0x8e, 0xa8, 0xb2, 0xbf, 0xcd, 0xcc, 0x6a, 0x18, 0x39, 0xe3, 0xdd, 0x63, 0xbe, 0x84, 0xea, 0x74, 0xa0, 0xcc, 0xd1, 0x35, 0xba, 0x6f, 0x87, 0xbe, 0x8f, 0xd6, 0xa4, 0xba, 0x66, 0xe, 0xe7, 0x1f, 0xcb, 0xab, 0xfc, 0x71, 0x51, 0xbd, 0xad, 0xaf, 0x6e, 0xe3, 0xb1, 0xd2, 0x37, 0xb, 0x50, 0xb3, 0x46, 0xa6, 0xeb, 0x66, 0x49, 0xfc, 0x78, 0x60, 0x24, 0x91, 0xa2, 0x27, 0x8f, 0x64, 0x2, 0xa9, 0x20, 0xac, 0x75, 0xa3, 0x9a, 0x3, 0x85, 0xaa, 0x54, 0xa4, 0x55, 0xda, 0xfa, 0xf2, 0xc6, 0x11, 0x14, 0x3d, 0xd1, 0xb1, 0x53, 0x38, 0x60, 0x98, 0x92, 0xa3, 0x6, 0xfa, 0xbe, 0x1f, 0xe1, 0xba, 0xfc, 0xf, 0xbd, 0x52, 0x44, 0x8e, 0x9d, 0xb5, 0xf6, 0xe1, 0xde, 0xd2, 0x7, 0x33, 0x3f, 0x1a, 0xcd, 0x91, 0x77, 0x32, 0x65, 0x5d, 0x46, 0xaf, 0x3b, 0xb6, 0x73, 0xe4, 0x52, 0x74, 0xe4, 0x1e, 0x92, 0xf3, 0xf4, 0x60, 0x5e, 0x9a, 0xa1, 0x78, 0x5e, 0x93, 0x9f, 0xce, 0x86, 0x77, 0xfd, 0x16, 0xa2, 0x99, 0xaa, 0x44, 0x46, 0xec, 0xa9, 0xa0, 0x9, 0xf0, 0xdb, 0x88, 0x32, 0xe2, 0xdd, 0x19, 0xc3, 0xf7, 0xe7, 0xbe, 0xcc, 0x9e, 0xf6, 0xcc, 0xd3, 0x8c, 0x84, 0x2a, 0x7f, 0x3f, 0xde, 0xb4, 0xa9, 0x2, 0xe3, 0xb8, 0xc5, 0x6e, 0x9b, 0x58, 0x25, 0xfe, 0x29, 0x77, 0x4b, 0xdf, 0xe9, 0xc2, 0x9f, 0x4b, 0x62, 0x14, 0x58, 0x2d, 0x8f, 0x6b, 0x7a, 0xb1, 0x4a, 0x35, 0xff, 0x62, 0xb7, 0xf4, 0xa1, 0x9f, 0x56, 0xc8, 0xf7, 0x10, 0x6c, 0x1e, 0xae, 0xad, 0x40, 0x39, 0xaf, 0xe4, 0xfe, 0x8b, 0x38, 0x20, 0xad, 0x7c, 0x2a, 0xba, 0x2, 0xc8, 0xed, 0x66, 0x3c, 0xcd, 0x83, 0x6d, 0x3d, 0xbb, 0xdd, 0x97, 0xbf, 0x92, 0x87, 0x90, 0x90, 0xb7, 0xa, 0xf2, 0x6b, 0xea, 0xb1, 0xc9, 0x5, 0x91, 0x28, 0x4e, 0x56, 0xe5, 0x9b, 0xdb, 0x73, 0x8b, 0x51, 0x8f, 0xf0, 0xda, 0x3f, 0x26, 0xe8, 0x2b, 0x5c, 0x7e, 0x29, 0x82, 0x5f, 0x35, 0x64, 0xf, 0x23, 0x39, 0x5d, 0x2c, 0xad, 0x9c, 0xb3, 0xaf, 0xae, 0xc1, 0x2, 0x90, 0xa5, 0x1d, 0x2c, 0x82, 0xab, 0x68, 0x3, 0x5b, 0x56, 0x9c, 0x68, 0x1c, 0xfd, 0x6e, 0xb1, 0xab, 0xc4, 0x26, 0xf7, 0x14, 0x59, 0xad, 0x5a, 0x9d, 0x47, 0xc8, 0x1f, 0xd4, 0x4d, 0x85, 0xc5, 0xa2, 0xa8, 0x45, 0x8, 0x66, 0x59, 0xfe, 0xbf, 0x90, 0x4e, 0xf1, 0xc7, 0xfe, 0xab, 0xed, 0x3c, 0x89, 0x2c, 0xf5, 0xd8, 0x49, 0x14, 0x2d, 0xbe, 0x57, 0xf7, 0xfd, 0x5, 0xb4};
  
  
  indcpa_dec(m_output, ct, static_sk);
  
  //simpleserial_put('i', KYBER_INDCPA_MSGBYTES, m_input);
  //simpleserial_put('o', KYBER_INDCPA_MSGBYTES, m_output);

	
}
