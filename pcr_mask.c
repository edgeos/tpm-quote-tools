/*
 * Extract a PCR mask from command line arguments.
 * Copyright (C) 2010 The MITRE Corporation
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the BSD License as published by the
 * University of California.
 */

#if defined HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <tss/tspi.h>
#include "tpm_quote.h"

int pcr_mask(UINT32 *pcrs, UINT32 npcrs, char **mask)
{
  UINT32 i;
  for (i = 0; i < npcrs; i++) {
    char *endptr;
    long pcr = strtol(mask[i], &endptr, 10);
    if (pcr < 0 || *mask[i] == 0 || *endptr != 0) {
      fprintf(stderr, "Illegal PCR value %s\n", mask[i]);
      return 1;
    }
    pcrs[i] = pcr;
  }
  return 0;
}
