/*
 * This file is part of TripSlicer imageboard tripcode cracker,
 * Copyright (C) 2011-2013 Truls Edvard Stokke
 */

#ifndef TRIPSLICER_MPI_H__
#define TRIPSLICER_MPI_H__

#include <stdio.h>
#include <stdlib.h>

/* common */

#define ROOT_PROCESS 0

#define PROCESS_IS_ROOT(id) \
  ((id) == ROOT_PROCESS)

/* tags */

#define CRACKED_TAG 1

/* utility */

#define BLOCK_LOW(id, p, n) \
  ((id)*(n)/(p))

#define BLOCK_HIGH(id, p, n) \
  (BLOCK_LOW((id)+1, p, n))

#define BLOCK_SIZE(id, p, n) \
  ((BLOCK_HIGH(id, p, n)) - (BLOCK_LOW(id, p, n)))

#define FINALIZE_AND_EXIT(status) \
  do { MPI_Finalize(); exit(status); } while (0)

#define FINALIZE_AND_FAIL \
  FINALIZE_AND_EXIT(EXIT_FAILURE)

#define FINALIZE_AND_SUCCEED \
  FINALIZE_AND_EXIT(EXIT_SUCCESS)

#define root_fprintf(id, ...) \
  if (PROCESS_IS_ROOT(id)) fprintf(__VA_ARGS__)

#define root_printf(id, ...) \
  root_fprintf((id), stdout, __VA_ARGS__)

#define root_eprintf(id, ...) \
  root_fprintf((id), stderr, __VA_ARGS__)

#endif /* TRIPSLICER_MPI_H__ */
