/*
 * Create a UUID.
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
#include <stdio.h>
#include <unistd.h>
#include <tss/tspi.h>
#include "tpm_quote.h"

static int usage(const char *prog)
{
  const char text[] =
    "Usage: %s [options] uuid\n"
    "Options:\n"
    "\t-h   Display command usage info\n"
    "\t-v   Display command version info\n"
    "\n"
    "On success, creates a UUID in file uuid.\n";
  fprintf(stderr, text, prog);
  return 1;
}

int main (int argc, char **argv)
{
  int opt;
  while ((opt = getopt(argc, argv, "hv")) != -1) {
    switch (opt) {
    case 'h':
      usage(argv[0]);
      return 0;
    case 'v':
      fprintf(stderr, "%s\n", PACKAGE_STRING);
      return 0;
    default:
      return usage(argv[0]);
    }
  }
  if (argc != optind + 1)
    return usage(argv[0]);

  const char *uuidname = argv[optind];

  /* Create context */
  TSS_HCONTEXT hContext;
  int rc = Tspi_Context_Create(&hContext);
  if (rc != TSS_SUCCESS)
    return tss_err(rc, "creating context");

  rc = Tspi_Context_Connect(hContext, NULL);
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "connecting"));

  /* Get TPM handle */
  TSS_HTPM hTPM;		/* TPM handle */
  rc = Tspi_Context_GetTpmObject(hContext, &hTPM);
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "getting TPM object"));

  TSS_UUID *uuid;
  /* Generate a UUID for the key */
  rc = Tspi_TPM_GetRandom(hTPM, sizeof(TSS_UUID), (BYTE **)&uuid);
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "generating a key UUID"));

  // Put in the variant and version bits
  uuid->usTimeHigh &= 0x0FFF;
  uuid->usTimeHigh |= (4 << 12);
  uuid->bClockSeqHigh &= 0x3F;
  uuid->bClockSeqHigh |= 0x80;

  /* Write uuid */
  FILE *out = fopen(uuidname, "wb");
  if (out == NULL) {
    fprintf(stderr, "Cannot open %s\n", uuidname);
    return tidy(hContext, 1);
  }
  fwrite(uuid, 1, sizeof *uuid, out);
  fclose(out);
  Tspi_Context_FreeMemory(hContext, (BYTE *)uuid);

  return tidy(hContext, 0);
}
