/*
 * Free memory associated with a context and close it
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
#include <tss/tspi.h>
#include "tpm_quote.h"
/* Returns the code after freeing resources associated with a context */
int tidy(TSS_HCONTEXT hContext, int code)
{
  if (Tspi_Context_FreeMemory(hContext, NULL) != TSS_E_INVALID_HANDLE)
    Tspi_Context_Close(hContext);
  return code;
}
