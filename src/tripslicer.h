/*
 * This file is part of TripSlicer imageboard tripcode cracker,
 * Copyright (C) 2011-2013 Truls Edvard Stokke
 */

#ifndef TRIPSLICER_H__
#define TRIPSLICER_H__

#include "DES_bs.h"

/* The number of boxes is the number
   of possible hashes for salt */
#define NUMBER_OF_BOXES (1 << 12)
#define KEYS_PER_BOX (DES_BS_DEPTH)

/* 12 bit hash based on salt */
#define SALT_HASH(salt)				\
  ((salt[0] & 0x3f) |				\
   ((salt[1] & 0x3f) << 6))

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

#endif /* TRIPSLICER_H__ */
