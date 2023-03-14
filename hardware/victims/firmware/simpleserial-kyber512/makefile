# Hey Emacs, this is a -*- makefile -*-
#----------------------------------------------------------------------------
#
# Makefile for ChipWhisperer SimpleSerial-AES Program
#
#----------------------------------------------------------------------------
# On command line:
#
# make all = Make software.
#
# make clean = Clean out built project files.
#
# make coff = Convert ELF to AVR COFF.
#
# make extcoff = Convert ELF to AVR Extended COFF.
#
# make program = Download the hex file to the device, using avrdude.
#                Please customize the avrdude settings below first!
#
# make debug = Start either simulavr or avarice as specified for debugging,
#              with avr-gdb or avr-insight as the front end for debugging.
#
# make filename.s = Just compile filename.c into the assembler code only.
#
# make filename.i = Create a preprocessed source file for use in submitting
#                   bug reports to the GCC project.
#
# To rebuild project do "make clean" then "make all".
#----------------------------------------------------------------------------

TGT_CFLAGS	= -O2 \
		  -Wall -Wextra -Wimplicit-function-declaration \
		  -Wredundant-decls -Wmissing-prototypes -Wstrict-prototypes \
		  -Wundef -Wshadow \
		  -I../../../include -fno-common \
		  -mcpu=cortex-m4 -mthumb -Wstrict-prototypes \
		  -ffunction-sections -fdata-sections -MD \
		  -mfloat-abi=hard -mfpu=fpv4-sp-d16 -DLPC43XX -DLPC43XX_M4


# Target file name (without extension).
# This is the name of the compiled .hex file.
TARGET = simpleserial-kyber512

# List C source files here.
# Header files (.h) are automatically pulled in.
SRC += simpleserial-kyber512.c

SRC += indcpa.c
SRC += randombytes.c 
SRC += fips202.c 
SRC += poly.c
SRC += polyvec.c
SRC += matacc.c
SRC += matacc.i
SRC += keccakf1600.c
SRC += symmetric-fips202.c
SRC += cbd.c
SRC += ntt.c
SRC += crypto_hashblocks_sha512.c
SRC += kem.c
SRC += nistseedexpander.c
SRC += sha2.c
SRC += sp800-185.c
SRC += test.c
SRC += verify.c

#Asembly source files

ASRC += macros.i
ASRC += reduce.S
ASRC += crypto_hashblocks_sha512_inner32.s
ASRC += fastaddsub.S
ASRC += fastbasemul.S
ASRC += fastinvntt.S
ASRC += fastntt.S
ASRC += keccakf1600.S
ASRC += poly_asm.S
ASRC += matacc_asm.S 

# -----------------------------------------------------------------------------

#ifeq ($(CRYPTO_OPTIONS),)
#CRYPTO_OPTIONS = AES128C
#endif

#Add simpleserial project to build
include ../simpleserial/Makefile.simpleserial

FIRMWAREPATH = ../.
include $(FIRMWAREPATH)/Makefile.inc

