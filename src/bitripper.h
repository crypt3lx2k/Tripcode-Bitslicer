/*
 * This file is part of BitRipper imageboard tripcode cracker,
 * Copyright (C) 2011 Truls Edvard Stokke
 */

#ifndef __BITRIPPER_H
#define __BITRIPPER_H

#include "arch.h"
#include "DES_bs.h"
#include "DES_std.h"

/* The number of boxes is the number
   of possible hashes for salt */
#define NUMBER_OF_BOXES (1 << 12)
#define KEYS_PER_BOX DES_BS_DEPTH

/*
 * With bitslicing DES we run several keys
 * at the same time with a single salt, we
 * therefore divide the keys into several
 * boxes hashed by the corresponding salt.
 */
typedef struct {
  ARCH_WORD salt_binary;
  int number_of_keys;
  char keys [KEYS_PER_BOX][9];
} Box;

/* salt hash */
#define SALT_HASH(hash, salt)			\
  do {						\
    hash  = (salt[0] & 0x3f);			\
    hash |= (salt[1] & 0x3f) << 6;		\
  } while (0)

/*
 * Salt table for plaintexts.
 */
const char salt_table[] =
  "................................"
  ".............../0123456789ABCDEF"
  "GABCDEFGHIJKLMNOPQRSTUVWXYZabcde"
  "fabcdefghijklmnopqrstuvwxyz....."
  "................................"
  "................................"
  "................................"
  "................................";

/*
 * Minus the salt we are missing the
 * third character compared to a
 * regular DES crypt hash.
 *
 * This means we have to test for
 * every possible completion of the
 * tripcode as a DES crypt hash.
 *
 * This table provides every possible
 * completion for the third character.
 */
const char hidden[] =
  "./0123456789"
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  "abcdefghijklmnopqrstuvwxyz";

#endif /* __BITRIPPER_H */
