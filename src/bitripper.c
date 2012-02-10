/*
 * This file is part of BitRipper imageboard tripcode cracker,
 * Copyright (C) 2011 Truls Edvard Stokke
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mpi.h>

#include "arch.h"
#include "common.h"  /* MAYBE_INLINE, CC_CACHE_ALIGN */
#include "DES_std.h" /* DES_raw_get_salt */
#include "DES_bs.h"

#include "bitripper.h"
#include "bitripper-mpi.h"

#define IO_BUFFER_SIZE 128
#define MAX_CIPHERS 256

/*
 * This number defines the number of possible
 * divisions of the keyspace.
 *
 * The number in this instance is 1 + 7f + 7f^2
 * (in mathematical notation) and defines the
 * number of possible key combinations for the
 * last two characters in a null terminated
 * string.
 *
 * The choice of dividing the keyspace with
 * only the last two blocks is an arbitrary
 * decision to ease the division of work.
 * If you need to run more than 16256
 * processes at the same time you may
 * increase the number of blocks used to
 * divide the keyspace, but keep in mind that
 * the complexity of the divide_keyspace
 * function increases.
 */
#define KEY_BLOCKS 16257

/* rank of this process
   within MPI_COMM_WORLD */
static int mpi_rank;

/* total number of processes
   in MPI_COMM_WORLD */
static int mpi_size;

/* request handler connected
   to cracked tripcodes */
static MPI_Request mpi_cracked_handler;

/* index of last cracked
   tripcode in ciphers.array */
static int mpi_last_cracked;

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
    root_eprintf(mpi_rank,
		 "unable to open targetlist %s\n",
		 filename);
    FINALIZE_AND_FAIL;
  }

  memset(io_buffer, '\0', IO_BUFFER_SIZE);

  while (fgets(io_buffer, IO_BUFFER_SIZE, targets)) {
    int i;
    size_t input_length;
    char ciphertext[14];
    ARCH_WORD * binary;

    if (ciphers.length == MAX_CIPHERS) {
      root_eprintf(mpi_rank,
		   "too many targets, can only handle %d\n",
		   MAX_CIPHERS);
      FINALIZE_AND_FAIL;
    }

    if (io_buffer[0] == '\0')
      continue;

    input_length = strlen(io_buffer);

    while (input_length &&
	   (io_buffer[input_length - 1] == '\n' ||
	    io_buffer[input_length - 1] == '\r'))
      io_buffer[--input_length] = '\0';

    /* does not clearing the buffer
       here have any effect? */
    if (input_length < 10) {
      root_eprintf(mpi_rank,
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
    root_eprintf(mpi_rank,
		 "no tripcodes to crack\n");
    FINALIZE_AND_FAIL;
  }

  return ciphers.length;
}

static void set_cracked_handler (void) {
  MPI_Irecv(&mpi_last_cracked, 1, MPI_INT,
	    MPI_ANY_SOURCE, CRACKED_TAG,
	    MPI_COMM_WORLD, &mpi_cracked_handler);
}

static void check_for_hits (void) {
  int cracked;

  MPI_Test(&mpi_cracked_handler, &cracked,
	   MPI_STATUS_IGNORE);

  while (cracked) {
    int i;

    /* rearrange array */
    ciphers.length -= 1;
    for (i = mpi_last_cracked; i < ciphers.length; i++)
      ciphers.array[i] = ciphers.array[i+1];

    /* done? */
    if (ciphers.length == 0) {
      root_printf(mpi_rank, "every tripcode cracked!\n");
      FINALIZE_AND_SUCCEED;
    }

    set_cracked_handler();

    MPI_Test(&mpi_cracked_handler, &cracked,
	     MPI_STATUS_IGNORE);
  }
}

static MAYBE_INLINE void handle_hit (char * key, int cipher) {
  int rank;

  for (rank = 0; rank < mpi_size; rank++)
    MPI_Send(&cipher, 1, MPI_INT,
	     rank, CRACKED_TAG,
	     MPI_COMM_WORLD);

  printf("%02x %02x %02x %02x "
	 "%02x %02x %02x %02x => %s\n",
	 key[0], key[1], key[2], key[3],
	 key[4], key[5], key[6], key[7],
	 ciphers.array[mpi_last_cracked].text);
  fflush(stdout);
}

static MAYBE_INLINE int run_box (int box_number) {
  int i, j, k;
  int keys;

  check_for_hits();

  keys = boxes[box_number].number_of_keys;
  boxes[box_number].number_of_keys = 0;

  DES_bs_set_salt(boxes[box_number].salt_binary);

  for (i = 0; i < keys; i++)
    DES_bs_set_key(boxes[box_number].keys[i], i);

  /* just try to guess where
     most of the time is spent */
  DES_bs_crypt_25(keys);

  i = 0;
 next:
  for (/* i = 0 */; i < ciphers.length; i++)
    for (j = 0; j < HIDDEN_POSSIBILITIES; j++)
      if (DES_bs_cmp_all(ciphers.array[i].binaries[j], 32))
	for (k = 0; k < keys; k++)
	  if (DES_bs_cmp_one(ciphers.array[i].binaries[j], 64, k)) {
	    handle_hit(boxes[box_number].keys[k], i);
	    i++; goto next;
	  }
  /* good guess */

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

static int loop_file (const char * filename) {
  char salt[14];
  char io_buffer[IO_BUFFER_SIZE];
  FILE * infile;

  infile = fopen(filename, "r");

  if (infile == NULL) {
    fprintf(stderr,
	    "process %d: unable to open file %s\n",
	    mpi_rank,
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

    while (input_length &&
	   (io_buffer[input_length - 1] == '\n' ||
	    io_buffer[input_length - 1] == '\r'))
      io_buffer[--input_length] = '\0';

    if (!input_length)
      continue;

    run_key(io_buffer, salt, input_length);
    memset(io_buffer, '\0', input_length);
  }

  fclose(infile);

  return 1;
}

static void divide_keyspace (int rank, int size, int indices[2]) {
  int lower_index = BLOCK_LOW(rank, size, KEY_BLOCKS);

  indices[1] = BLOCK_LOW(rank, size, 0x80);
  indices[0] = lower_index - 0x7f * indices[1];
}

static void loop_key (char key[9]) {
  char salt[14];
  int indices[2];

  memset(salt, '\0', 14);

  divide_keyspace(mpi_rank + 1, mpi_size, indices);

  while (key[6] != (char) indices[0] ||
	 key[7] != (char) indices[1]) {
    int i;

    run_key(key, salt, strlen(key));

    key[0] += 1;

    for (i = 0; (key[i] == (char) 0x80) && i < 6; i++) {
      key[i+0]  = 1;
      key[i+1] += 1;
    }
  }
}

static void finalize (void) {
  int i;

  for (i = 0; i < NUMBER_OF_BOXES; i++)
    if (boxes[i].number_of_keys)
      run_box(i);

  check_for_hits();
}

int main (int argc, char * argv[]) {
  int i;
  int indices[2];
  char key[9];

  MPI_Init(&argc, &argv);

  MPI_Comm_rank(MPI_COMM_WORLD, &mpi_rank);
  MPI_Comm_size(MPI_COMM_WORLD, &mpi_size);

  if (mpi_size > KEY_BLOCKS) {
    root_eprintf(mpi_rank,
		 "Too many processes spawned.\n"
		 "This program may only handle %d processes, see the KEY_BLOCKS macro for details.\n",
		 KEY_BLOCKS);
    FINALIZE_AND_FAIL;
  }

  if (argc < 2) {
    root_eprintf(mpi_rank,
		 "usage: %s targetlist [wordlists...]\n",
		 argv[0]);
    FINALIZE_AND_FAIL;
  }

  /* Initialize DES_bs here in case some
     of the other functions use it. */
  DES_bs_init(0, DES_bs_cpt);

  read_targets(argv[1]);
  set_cracked_handler();

  if (argc > 2)
    for (i = BLOCK_LOW (mpi_rank, mpi_size, argc-2);
	 i < BLOCK_HIGH(mpi_rank, mpi_size, argc-2); i++)
      loop_file(argv[i+2]);

  divide_keyspace(mpi_rank, mpi_size, indices);

  memset(key, '\0', 9);
  key[6] = (char) indices[0];
  key[7] = (char) indices[1];

  /* we assume that any valid key is zero terminated, which is
     true for tripcodes but not for any DES key. So here we pad
     keys so that no key has a zero before a non-zero value.

     typically for process that don't have rank zero the key
     will be transformed from something like

     0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x2f 0x55 0x0
     to
     0x1 0x1 0x1 0x1 0x1 0x1 0x1 0x2f 0x55 0x0
  */
  if (key[6] || key[7])
    memset(key, 1, 6);

  loop_key(key);

  finalize();
  FINALIZE_AND_SUCCEED;
}
