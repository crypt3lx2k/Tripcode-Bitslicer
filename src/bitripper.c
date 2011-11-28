/*
 * This file is part of BitRipper imageboard tripcode cracker,
 * Copyright (C) 2011 Truls Edvard Stokke
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arch.h"
#include "common.h"  /* MAYBE_INLINE, CC_CACHE_ALIGN */
#include "DES_std.h" /* DES_raw_get_salt */
#include "DES_bs.h"
#include "bitripper.h"

#define IO_BUFFER_SIZE 128

/*
 * With bitslicing DES we want to run as many
 * keys as possible at the same time, but we
 * may only have one salt per run, therefore
 * we divide the work into a number of boxes
 * uniquely identified by the salt.
 */
static struct {
  /* keys currently in box */
  int number_of_keys;

  ARCH_WORD salt_binary;
  char keys[KEYS_PER_BOX][8];
} CC_CACHE_ALIGN boxes[NUMBER_OF_BOXES];

static struct cipher {
  /*
   * The magic number 2 here comes from
   * line 1077, 1088 in DES_std.c:
   *   static ARCH_WORD out[2];
   *   ...
   *   return out;
   */
  ARCH_WORD binaries[HIDDEN_POSSIBILITIES][2];
  char text[11];
} CC_CACHE_ALIGN * ciphers;

static MAYBE_INLINE int handle_hit (char * key, int cipher) {
  char output [9];

  printf("#%s => !%s\n",
	 strncat(output, key, 8),
	 ciphers[cipher].text);

  return 1;
}

static MAYBE_INLINE int run_box(int box_number) {
  int i, j;
  int keys = boxes[box_number].number_of_keys;

  boxes[box_number].number_of_keys = 0;

  DES_bs_set_salt(boxes[box_number].salt_binary);

  for (i = 0; i < keys; i++)
    DES_bs_set_key(boxes[box_number].keys[i], i);

  DES_bs_crypt_25(keys);

  for (i = 0; i < HIDDEN_POSSIBILITIES; i++)
    if (DES_bs_cmp_all(ciphers[0].binaries[i], 32))
      for (j = 0; j < keys; j++)
	if (DES_bs_cmp_one(ciphers[0].binaries[i], 2*ARCH_BITS, j))
	  return handle_hit (boxes[box_number].keys[j], 0);

  return 0;
}

int main (int argc, char **argv) {
  char io_buffer[IO_BUFFER_SIZE];
  char salt[14];
  FILE * infile;

  if (argc < 2) {
    fprintf(stderr,
	    "usage: %s tripcode wordfile\n",
	    argv[0]);
    exit(EXIT_FAILURE);
  }

  /* Initialize DES_bs here in case some
     of the other functions use it. */
  DES_bs_init(0, DES_bs_cpt);

  {
    int i;
    char ciphertext [14];
    ARCH_WORD * binary;

    ciphers = malloc(1 * sizeof(struct cipher));
    strncat(&ciphers[0].text[0], argv[1], 10);

    memset(ciphertext, 0, 14);
    strncpy(ciphertext + 3, argv[1], 10);

    for (i = 0; i < HIDDEN_POSSIBILITIES; i++) {
      ciphertext[2] = hidden[i];
      binary = DES_bs_get_binary(ciphertext);
      ciphers[0].binaries[i][0] = binary[0];
      ciphers[0].binaries[i][1] = binary[1];
    }
  }

  {
    infile = fopen(argv[2], "r");

    if (infile == NULL) {
      fprintf(stderr,
	      "unable to open file %s\n",
	      argv[2]);
      exit(EXIT_FAILURE);
    }
  }

  memset(io_buffer, '\0', IO_BUFFER_SIZE);
  memset(salt,      '\0', 14);

  while (fgets(io_buffer, IO_BUFFER_SIZE, infile)) {
    int hash;
    int index;
    size_t input_length;

    memset(salt, 'H', 2);

    input_length = strlen(io_buffer);

    if (io_buffer[input_length - 1] == '\n')
      io_buffer[--input_length] = '\0';

    switch (input_length) {
    case 1:
      salt[1] = '.';
      break;
    default:
      salt[1] = salt_table[(unsigned char) io_buffer[2]];
    case 2:
      salt[0] = salt_table[(unsigned char) io_buffer[1]];
      break;
    }

    SALT_HASH(hash, salt);

    if (!boxes[hash].salt_binary)
      boxes[hash].salt_binary = DES_raw_get_salt(salt);

    index = boxes[hash].number_of_keys;
    memcpy(&boxes[hash].keys[index][0], io_buffer, 8);

    boxes[hash].number_of_keys += 1;

    if (boxes[hash].number_of_keys == KEYS_PER_BOX)
      run_box(hash);

    memset(io_buffer, '\0', IO_BUFFER_SIZE);
  }

  {
    int i;

    for (i = 0; i < NUMBER_OF_BOXES; i++)
      if (boxes[i].number_of_keys)
	run_box(i);
  }

  exit(EXIT_SUCCESS);
}
