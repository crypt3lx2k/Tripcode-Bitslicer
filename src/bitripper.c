/*
 * This file is part of BitRipper imageboard tripcode cracker,
 * Copyright (C) 2011 Truls Edvard Stokke
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bitripper.h"

#define IO_BUFFER_SIZE 128

Box boxes[NUMBER_OF_BOXES];
ARCH_WORD cipher_binaries[sizeof(hidden)][2];

static inline void run_box(int hash) {
  int i, j;
  int keys = boxes[hash].number_of_keys;

  boxes[hash].number_of_keys = 0;

  DES_bs_set_salt(boxes[hash].salt_binary);

  for (i = 0; i < keys; i++)
    DES_bs_set_key(boxes[hash].keys[i], i);

  DES_bs_crypt_25(keys);

  for (i = 0; i < sizeof(hidden); i++)
    if (DES_bs_cmp_all(cipher_binaries[i], 32))
      for (j = 0; j < keys; j++)
	if (DES_bs_cmp_one(cipher_binaries[i],
			   2*ARCH_BITS,
			   j)) {
	  printf("Hit: %s\n", boxes[hash].keys[j]);
	  goto end;
	}

 end:
  ;
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

  DES_bs_init(0, DES_bs_cpt);

  {
    int i;
    char ciphertext [14];
    ARCH_WORD * binary;

    memset(ciphertext, 0, 14);
    strncpy(ciphertext + 3, argv[1], 11);

    for (i = 0; i < sizeof(hidden); i++) {
      ciphertext[2] = hidden[i];
      binary = DES_bs_get_binary(ciphertext);
      cipher_binaries[i][0] = binary[0];
      cipher_binaries[i][1] = binary[1];
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
    int i;
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
    for (i = 0; i < 8; i++)
      boxes[hash].keys[index][i] = io_buffer[i];

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
