/*
 * This file is part of TripSlicer imageboard tripcode cracker,
 * Copyright (C) 2011-2013 Truls Edvard Stokke
 */

#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mpi.h>

#include "arch.h"
#include "common.h"  /* MAYBE_INLINE, CC_CACHE_ALIGN */
#include "DES_std.h" /* DES_raw_get_salt */
#include "DES_bs.h"

#include "tripslicer.h"
#include "tripslicer-mpi.h"

static const char alnum[] =
  "abcdefghijklmnopqrstuvwxyz"
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  "0123456789";

#define CHARSET alnum
#define CHARSET_SIZE (sizeof(CHARSET)-1)

#define IO_BUFFER_SIZE 128
#define MAX_CIPHERS 4096

/* rank of this process
   within MPI_COMM_WORLD */
static int mpi_rank;

/* total number of processes
   in MPI_COMM_WORLD */
static int mpi_size;

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

  char keys[KEYS_PER_BOX][8];
} CC_CACHE_ALIGN boxes[NUMBER_OF_BOXES];

static struct {
  struct cipher {
    /*
     * The magic number 2 here comes from
     * line 1077, 1088 in DES_std.c:
     *   static ARCH_WORD out[2];
     *   ...
     *   return out;
     */
    ARCH_WORD binary[2];
    char text[10];
  } array[MAX_CIPHERS];

  int length;
} ciphers;

static int read_targets (char * filename) {
  MPI_Datatype cipher_type;

  int block_lengths[2];
  MPI_Aint displacements[2];
  MPI_Datatype types[2];

  /* ARCH_WORD binary[2] */
  block_lengths[0] = 2;
  /* char text[10] */
  block_lengths[1] = 10;

  displacements[0] = offsetof(struct cipher, binary);
  displacements[1] = offsetof(struct cipher, text);

  types[0] = ARCH_WORD_MPI;
  types[1] = MPI_CHAR;

  MPI_Type_create_struct(2, block_lengths, displacements,
			 types, &cipher_type);
  MPI_Type_commit(&cipher_type);

  /* root process reads file. */
  if (PROCESS_IS_ROOT(mpi_rank)) {
    char io_buffer[IO_BUFFER_SIZE];
    FILE * targets;

    targets = fopen(filename, "r");

    if (targets == NULL) {
      fprintf(stderr, "unable to open targetlist %s\n",
	      filename);
      MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
    }

    memset(io_buffer, '\0', IO_BUFFER_SIZE);

    while (fgets(io_buffer, IO_BUFFER_SIZE, targets)) {
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
      memset(ciphertext, '.', 3);
      memcpy(ciphertext + 3, io_buffer, 10);

      binary = DES_bs_get_binary(ciphertext);
      ciphers.array[ciphers.length].binary[0] = binary[0];
      ciphers.array[ciphers.length].binary[1] = binary[1];

      ciphers.length += 1;

      memset(io_buffer, '\0', input_length);
    }
  }

  /* root process broadcasts ciphers to children. */
  MPI_Bcast(&ciphers.length, 1, MPI_INT,
	    ROOT_PROCESS, MPI_COMM_WORLD);
  MPI_Bcast(&ciphers.array, ciphers.length, cipher_type,
	    ROOT_PROCESS, MPI_COMM_WORLD);

  if (ciphers.length == 0) {
    root_eprintf(mpi_rank,
		 "no tripcodes to crack\n");
    FINALIZE_AND_FAIL;
  }

  MPI_Type_free(&cipher_type);

  return ciphers.length;
}

static MAYBE_INLINE void handle_hit (char * key, int cipher) {
  printf("%02x %02x %02x %02x "
  	 "%02x %02x %02x %02x => %.10s (%.8s)\n",
  	 (unsigned) key[0], (unsigned) key[1],
  	 (unsigned) key[2], (unsigned) key[3],
  	 (unsigned) key[4], (unsigned) key[5],
  	 (unsigned) key[6], (unsigned) key[7],
  	 ciphers.array[cipher].text, key);

  fflush(stdout);
}

static MAYBE_INLINE int run_box (ARCH_WORD box_number) {
  int i, k;
  int keys;

  keys = boxes[box_number].number_of_keys;
  boxes[box_number].number_of_keys = 0;

  DES_bs_set_salt(box_number);

  for (i = 0; i < keys; i++)
    DES_bs_set_key(boxes[box_number].keys[i], i);

  /* just try to guess where
     most of the time is spent */
  DES_bs_crypt_25(keys);

  /* set the first character of the DEScrypt output
     to '.', this character is not part of the tripcode. */
  memset(DES_bs_all.B[ 7], 0, sizeof(DES_bs_vector));
  memset(DES_bs_all.B[15], 0, sizeof(DES_bs_vector));
  memset(DES_bs_all.B[23], 0, sizeof(DES_bs_vector));
  memset(DES_bs_all.B[39], 0, sizeof(DES_bs_vector));
  memset(DES_bs_all.B[47], 0, sizeof(DES_bs_vector));
  memset(DES_bs_all.B[55], 0, sizeof(DES_bs_vector));

  for (i = 0; i < ciphers.length; i++)
    if (DES_bs_cmp_all(ciphers.array[i].binary, keys))
      for (k = 0; k < keys; k++)
	if (DES_bs_cmp_one(ciphers.array[i].binary, 64, k)) {
	  handle_hit(boxes[box_number].keys[k], i);
	  break;
	}
  /* good guess */

  return 0;
}

static MAYBE_INLINE int run_key (const char key[9], char salt[14], size_t keylen) {
  ARCH_WORD hash;
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

  hash = DES_raw_get_salt(salt);

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

static void finalize (void) {
  int i;

  for (i = 0; i < NUMBER_OF_BOXES; i++)
    if (boxes[i].number_of_keys)
      run_box(i);
}

static void signal_handler (int signal) {
  finalize();
  FINALIZE_AND_EXIT(signal);
}

static void advance_once (unsigned char counters[9], size_t p) {
  size_t i;

  counters[p] += 1;
  for (i = p; i < 8 && counters[i] == CHARSET_SIZE+1; i++) {
    counters[i+0]  = 1;
    counters[i+1] += 1;
  }
}

static void advance_key (unsigned char counters[9], size_t times) {
  while (times > 0) {
    const size_t cs2 = CHARSET_SIZE*CHARSET_SIZE;
    const size_t cs1 = CHARSET_SIZE;

    if (times > cs2 + cs1) {
      advance_once(counters, 2);
      times -= cs2;
    }

    if (times > cs1) {
      advance_once(counters, 1);
      times -= cs1;
    }

    advance_once(counters, 0);
    times -= 1;
  }
}

static void loop_key (unsigned char counters[9]) {
  char salt[14] = {0};
  char key [9]  = {0};
  size_t keylen =  0;
  size_t i;

  advance_key(counters, mpi_rank+1);

  while (counters[8] == 0) {
    for (i = 0; counters[i]; i++) {
      key[i] = CHARSET[counters[i]-1];
      keylen = i+1;
    }

    run_key(key, salt, keylen);
    advance_key(counters, mpi_size);
  }
}

int main (int argc, char * argv[]) {
  int i;
  unsigned char counters[9];

  MPI_Init(&argc, &argv);

  signal(SIGINT,  signal_handler);
  signal(SIGTERM, signal_handler);

  MPI_Comm_rank(MPI_COMM_WORLD, &mpi_rank);
  MPI_Comm_size(MPI_COMM_WORLD, &mpi_size);

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

  if (argc > 2)
    for (i = BLOCK_LOW (mpi_rank, mpi_size, argc-2);
	 i < BLOCK_HIGH(mpi_rank, mpi_size, argc-2); i++)
      loop_file(argv[i+2]);

  MPI_Barrier(MPI_COMM_WORLD);

  memset(counters, 0, 9);
  loop_key(counters);

  finalize();
  FINALIZE_AND_SUCCEED;
}
