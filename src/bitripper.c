/*
 * This file is part of BitRipper imageboard tripcode cracker,
 * Copyright (C) 2011 Truls Edvard Stokke
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "bitripper.h"

#define BANK_SIZE 0x1000
#define KEYS      DES_BS_DEPTH

#define IOBUF_SIZE  32
#define SALT_SIZE   14

const char * restrict salt =
  "................................"
  ".............../0123456789ABCDEF"
  "GABCDEFGHIJKLMNOPQRSTUVWXYZabcde"
  "fabcdefghijklmnopqrstuvwxyz....."
  "................................"
  "................................"
  "................................"
  "................................";

int banklen[BANK_SIZE];
char keybank[BANK_SIZE][KEYS][8];
ARCH_WORD saltbank[BANK_SIZE];

ARCH_WORD *ciphbin;

void run_bank(int banknum) {
  DES_bs_clear_keys();
  DES_bs_set_salt(saltbank[banknum]);
  
  for (int i = 0; i < banklen[banknum]; i++)
    DES_bs_set_key(keybank[banknum][i], i);

  DES_bs_expand_keys();  
  DES_bs_crypt_25();

  if (DES_bs_cmp_all(ciphbin))
    for (int i = 0; i < KEYS; i++)
      if (DES_bs_cmp_one(ciphbin, 32, i))
	printf("Hit: %s\n", keybank[banknum][i]);

  banklen[banknum] = 0;

  return;
}

int main(int argc, char **argv) {
  FILE *infile;
  int hash, index;
  char * restrict iobuf;
  char * restrict saltbuf;

  if (--argc) {
    char ciphertext[14];

    memset(ciphertext, 0, 14);
    strncpy(ciphertext + 3, *++argv, 10);

    ciphbin = DES_bs_get_binary(ciphertext);
  } else {
    exit(EXIT_FAILURE);
  }

  DES_bs_init(0);

  iobuf   = calloc(sizeof(char), IOBUF_SIZE);
  saltbuf = calloc(sizeof(char),  SALT_SIZE);

  if (--argc)
    infile = fopen(*++argv, "r");
  else
    exit(EXIT_FAILURE);

  if (infile == NULL) {
    fprintf(stderr, "Unable to open file.\n");
    exit(EXIT_FAILURE);
  }

  while (fgets(iobuf, IOBUF_SIZE, infile)) {
    size_t iolen;

    if (iobuf[0] == '#')
      continue;

    memset(saltbuf, 'H', 2);

    iolen = strlen(iobuf);

    if (iobuf[iolen - 1] == '\n')
      iobuf[--iolen] = '\0';

    switch (iolen) {
    case 1:
      saltbuf[1] = '.';
      break;
    default:
      saltbuf[1] = salt[(unsigned char) iobuf[2]];
    case 2:
      saltbuf[0] = salt[(unsigned char) iobuf[1]];
      break;
    }

    hash  = (saltbuf[0] & 0x3f);
    hash |= (saltbuf[1] & 0x3f) << 6;

    if (!saltbank[hash])
      saltbank[hash] = DES_raw_get_salt(saltbuf);

    index = banklen[hash];
    for (int i = 0; i < 8; i++)
      keybank[hash][index][i] = iobuf[i] ? iobuf[i] : 0;

    banklen[hash] += 1;

    if (banklen[hash] == KEYS) {
      run_bank(hash);
    }
  }

  for (int i = 0; i < BANK_SIZE; i++)
    if (banklen[i])
      run_bank(i);

  exit(EXIT_SUCCESS);
}
