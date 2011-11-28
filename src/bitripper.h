/*
 * This file is part of BitRipper imageboard tripcode cracker,
 * Copyright (C) 2011 Truls Edvard Stokke
 */

#ifndef __BITRIPPER_H
#define __BITRIPPER_H

#include "DES_bs.h"

/* The number of boxes is the number
   of possible hashes for salt */
#define NUMBER_OF_BOXES (1 << 12)
#define KEYS_PER_BOX DES_BS_DEPTH

/* 12 bit hash based on salt */
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

#define HIDDEN_POSSIBILITIES (sizeof(hidden))

#endif /* __BITRIPPER_H */
