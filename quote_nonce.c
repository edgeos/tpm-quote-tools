/*
 * Extract a nonce from a quote.
 * Copyright (C) 2010 The MITRE Corporation
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the BSD License as published by the
 * University of California.
 */

#if defined HAVE_CONFIG_H
#include "config.h"
#endif
#include <stddef.h>
#include <stdlib.h>
#include <tss/tspi.h>
#include "tpm_quote.h"

/* This function works when the quote info is in blob format due to
   the way compilers layout the structs. */
TPM_NONCE *quote_nonce(BYTE *info)
{
  if (!info)
    return NULL;
  TPM_QUOTE_INFO2 *qi2 = (TPM_QUOTE_INFO2 *)info;
  if (qi2->fixed[0] == 'Q' && qi2->fixed[1] == 'U' &&
      qi2->fixed[2] == 'T' && qi2->fixed[3] == '2')
    return &qi2->externalData;
  TPM_QUOTE_INFO *qi = (TPM_QUOTE_INFO *)info;
  if (qi->fixed[0] == 'Q' && qi->fixed[1] == 'U' &&
      qi->fixed[2] == 'O' && qi->fixed[3] == 'T')
    return &qi->externalData;
  return NULL;
}
