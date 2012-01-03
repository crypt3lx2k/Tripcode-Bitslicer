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
#define MAX_CIPHERS 256

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

static struct {
  struct {
    /*
     * The magic number 2 here comes from
     * line 1077, 1088 in DES_std.c:
     *   static ARCH_WORD out[2];
     *   ...
     *   return out;
     */
    ARCH_WORD binaries[HIDDEN_POSSIBILITIES][2];
    char text[11];
  } CC_CACHE_ALIGN array[MAX_CIPHERS];

  int length;
} ciphers;

static int read_targets (char * filename) {
  char io_buffer[IO_BUFFER_SIZE];
  FILE * targets = fopen(filename, "r");

  if (targets == NULL) {
    fprintf(stderr,
	    "unable to open targetlist %s\n",
	    filename);
    exit(EXIT_FAILURE);
  }

  memset(io_buffer, '\0', IO_BUFFER_SIZE);

  while (fgets(io_buffer, IO_BUFFER_SIZE, targets)) {
    int i;
    size_t input_length;
    char ciphertext[14];
    ARCH_WORD * binary;

    if (ciphers.length == MAX_CIPHERS) {
      fprintf(stderr,
	      "too many targets, can only handle %d\n",
	      MAX_CIPHERS);
      exit(EXIT_FAILURE);
    }

    if (io_buffer[0] == '\0')
      continue;

    input_length = strlen(io_buffer);

    while (io_buffer[input_length - 1] == '\n' ||
	   io_buffer[input_length - 1] == '\r')
      io_buffer[--input_length] = '\0';

    /* does not clearing the buffer
       here have any effect? */
    if (input_length < 10) {
      fprintf(stderr,
	      "illegal line: %s in target file %s\n",
	      io_buffer, filename);
      continue;
    }

    strncat(&ciphers.array[ciphers.length].text[0],
	    io_buffer, 10);

    memset(ciphertext, 0, 14);
    strncpy(ciphertext + 3, io_buffer, 10);

    for (i = 0; i < HIDDEN_POSSIBILITIES; i++) {
      ciphertext[2] = hidden[i];
      binary = DES_bs_get_binary(ciphertext);
      ciphers.array[ciphers.length].binaries[i][0] = binary[0];
      ciphers.array[ciphers.length].binaries[i][1] = binary[1];
    }

    ciphers.length += 1;

    memset(io_buffer, '\0', input_length);
  }

  if (ciphers.length == 0) {
    fprintf(stderr,
	    "no tripcodes to crack\n");
    exit(EXIT_FAILURE);
  }

  return ciphers.length;
}

static MAYBE_INLINE int handle_hit (char * key, int cipher) {
  int i;

  printf("%02x %02x %02x %02x "
	 "%02x %02x %02x %02x => %s\n",
	 key[0], key[1], key[2], key[3],
	 key[4], key[5], key[6], key[7],
	 ciphers.array[cipher].text);

  /* rearrange array */
  ciphers.length -= 1;
  for (i = cipher; i < ciphers.length; i++)
    ciphers.array[i] = ciphers.array[i+1];

  /* done? */
  if (ciphers.length == 0) {
    printf("every tripcode cracked!\n");
    exit(EXIT_SUCCESS);
  }

  return 0;
}

static MAYBE_INLINE int run_box(int box_number) {
  int i, j, k;
  int keys = boxes[box_number].number_of_keys;

  boxes[box_number].number_of_keys = 0;

  DES_bs_set_salt(boxes[box_number].salt_binary);

  for (i = 0; i < keys; i++)
    DES_bs_set_key(boxes[box_number].keys[i], i);

  /* just try to guess where
     most of the time is spent */
  DES_bs_crypt_25(keys);

 next:
  for (i = 0; i < ciphers.length; i++)
    for (j = 0; j < HIDDEN_POSSIBILITIES; j++)
      if (DES_bs_cmp_all(ciphers.array[i].binaries[j], 32))
	for (k = 0; k < keys; k++)
	  if (DES_bs_cmp_one(ciphers.array[i].binaries[j], 64, k)) {
	    handle_hit(boxes[box_number].keys[k], i);
	    goto next;
	  }

  return 0;
}

static MAYBE_INLINE int run_key (const char key[9], char salt[14], size_t keylen) {
  int hash;
  int index;

  memset(salt, 'H', 2);

  switch (keylen) {
  case 1:
    salt[1] = '.';
    break;
  default:
    salt[1] = salt_table[(unsigned char) key[2]];
  case 2:
    salt[0] = salt_table[(unsigned char) key[1]];
    break;
  }

  hash = SALT_HASH(salt);

  if (!boxes[hash].salt_binary)
    boxes[hash].salt_binary = DES_raw_get_salt(salt);

  index = boxes[hash].number_of_keys;
  memcpy(&boxes[hash].keys[index][0], key, 8);

  boxes[hash].number_of_keys += 1;

  if (boxes[hash].number_of_keys == KEYS_PER_BOX)
    run_box(hash);

  return hash;
}

static int loop_key (char key[9]) {
  char salt[14];
  memset(salt, '\0', 14);

  do {
    int i;

    key[0] += 1;

    for (i = 0; key[i] && i < 7; i++) {
      if (key[i] == (char) 0x80) {
	key[i]    = 1;
	key[i+1] += 1;
      }
    }

    run_key(key, salt, i);
  } while (key[8] != 0x7f);

  return 1;
}

static int loop_file (const char * filename) {
  char salt[14];
  char io_buffer[IO_BUFFER_SIZE];
  FILE * infile;

  infile = fopen(filename, "r");

  if (infile == NULL) {
    fprintf(stderr,
	    "unable to open file %s\n",
	    filename);
    return 0;
  }

  memset(salt, '\0', 14);
  memset(io_buffer, '\0', IO_BUFFER_SIZE);

  while (fgets(io_buffer, IO_BUFFER_SIZE, infile)) {
    size_t input_length;

    if (io_buffer[0] == '\0')
      continue;

    input_length = strlen(io_buffer);

    while (io_buffer[input_length - 1] == '\n' ||
	   io_buffer[input_length - 1] == '\r')
      io_buffer[--input_length] = '\0';

    if (!input_length)
      continue;

    run_key(io_buffer, salt, input_length);
    memset(io_buffer, '\0', input_length);
  }

  fclose(infile);

  return 1;
}

static void finalize (void) {
  int i;

  for (i = 0; i < NUMBER_OF_BOXES; i++)
    if (boxes[i].number_of_keys)
      run_box(i);
}

int main (int argc, char **argv) {
  int i;
  char key[9];

  if (argc < 2) {
    fprintf(stderr,
	    "usage: %s targetlist [wordlists...]\n",
	    argv[0]);
    exit(EXIT_FAILURE);
  }

  /* Initialize DES_bs here in case some
     of the other functions use it. */
  DES_bs_init(0, DES_bs_cpt);

  read_targets(argv[1]);

  for (i = 2; i < argc; i++)
    loop_file(argv[i]);

  memset(key, '\0',  9);
  loop_key(key);

  finalize();

  exit(EXIT_SUCCESS);
}
