/*
 * Create a composite PCR hash.
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
#include <stdlib.h>
#include <unistd.h>
#include <tss/tspi.h>
#include "tpm_quote.h"

static int uint32_compar(const void *a, const void *b)
{
  UINT32 x = *(UINT32 *) a;
  UINT32 y = *(UINT32 *) b;
  return x - y;
}

static int usage(const char *prog)
{
  const char text[] =
    "Usage: %s [-r host] [-hv] uuid hash pcrvals PCRS...\n"
    "\tuuid\tFile containing uuid of AIK\n"
    "\thash\tOutput file containing PCR hash\n"
    "\tpcrvals\tOutput file containing list of PCR values\n"
    "\tPCRS...\tList of PCR numbers to use in the quote\n"
    "Options:\n"
    "\t-r host\n"
    "\t     Perform operation on remote host\n"
    "\t-h   Display command usage info\n"
    "\t-v   Display command version info\n"
    "\n"
    "On success, returns the signed data produced by a TPM quote\n"
    "in file hash.  The nonce used in the quote is unpredictable.\n";
  fprintf(stderr, text, prog);
  return 1;
}

int main(int argc, char **argv)
{
  UINT32 pcrs[argc];

  TSS_UNICODE *host = NULL; /* Non-null when connecting to a remote host */
  int opt;
  while ((opt = getopt(argc, argv, "r:hv")) != -1) {
    switch (opt) {
    case 'r':
#if defined HAVE_ICONV_H
      host = (TSS_UNICODE *)toutf16le(optarg);
      if (!host) {
	fprintf(stderr, "Cannot convert %s to UTF-16LE\n", optarg);
	return 1;
      }
      break;
#else
      fprintf(stderr, "Remote requests not supported on this platform.\n");
      return 1;
#endif
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

  if (argc < optind + 4)
    return usage(argv[0]);

  const char *uuidname = argv[optind];
  const char *hashname = argv[optind + 1];
  const char *pcrvals = argv[optind + 2];
  UINT32 npcrs = argc - optind - 3;

  if (pcr_mask(pcrs, npcrs, argv + optind +  3))
    return 1;

  FILE *in = fopen(uuidname, "rb");
  if (!in) {
    fprintf(stderr, "Cannot open %s\n", uuidname);
    return 1;
  }

  TSS_UUID uuid;
  if (sizeof uuid != fread((void *)&uuid, 1, sizeof uuid, in)) {
    fprintf(stderr, "Expecting a uuid of %zd bytes in %s\n",
	    sizeof uuid, uuidname);
    return 1;
  }
  fclose(in);

  /* Create context */
  TSS_HCONTEXT hContext;	/* Context handle */
  TSS_RESULT rc = Tspi_Context_Create(&hContext);
  if (rc != TSS_SUCCESS)
    return tss_err(rc, "creating context");

  rc = Tspi_Context_Connect(hContext, host);
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "connecting"));

  BYTE nonce[20];		/* Value of nonce does not matter */
  TSS_VALIDATION valid;
  valid.ulExternalDataLength = sizeof nonce;
  valid.rgbExternalData = nonce;

  if (quote(hContext, uuid, pcrs, npcrs, &valid))
    return tidy(hContext, 1);

  FILE *out = fopen(hashname, "wb");
  if (!out) {
    fprintf(stderr, "Cannot open %s\n", hashname);
    return tidy(hContext, 1);
  }
  fwrite(valid.rgbData, 1, valid.ulDataLength, out);
  fclose(out);

  Tspi_Context_FreeMemory(hContext, valid.rgbData);
  Tspi_Context_FreeMemory(hContext, valid.rgbValidationData);

  /* Save the selected PCR values in a file. */

  /* Get TPM handle */
  TSS_HTPM hTPM;		/* TPM handle */
  rc = Tspi_Context_GetTpmObject(hContext, &hTPM);
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "getting TPM object"));

  out = fopen(pcrvals, "wb");
  if (!out) {
    fprintf(stderr, "Cannot open %s\n", pcrvals);
    return tidy(hContext, 1);
  }

  qsort(pcrs, npcrs, sizeof pcrs[0], uint32_compar);

  UINT32 i;
  for (i = 0; i < npcrs; i++) {
    UINT32 len;
    BYTE *value;
    rc = Tspi_TPM_PcrRead(hTPM, pcrs[i], &len, &value);
    if (rc != TSS_SUCCESS)
      return tidy(hContext, tss_err(rc, "reading PCR"));
    fprintf(out, "%u=", pcrs[i]);
    UINT32 j;
    for (j = 0; j < len; j++)
      fprintf(out, "%02X", value[j]);
    fprintf(out, "\n");
  }
  fclose(out);

  return tidy(hContext, 0);
}
