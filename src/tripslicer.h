/*
 * This file is part of TripSlicer imageboard tripcode cracker,
 * Copyright (C) 2011-2013 Truls Edvard Stokke
 */

#ifndef TRIPSLICER_H__
#define TRIPSLICER_H__

#include "DES_bs.h"

/* Number of BS runs per salt */
#define LEVELS_PER_SALT 4

/* The number of boxes is the number
   of possible hashes for salt */
#define NUMBER_OF_BOXES (1 << 12)
#define KEYS_PER_BOX (LEVELS_PER_SALT*DES_BS_DEPTH)

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
