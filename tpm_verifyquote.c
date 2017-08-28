/*
 * Verify a quote.
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
#include <string.h>
#include <unistd.h>
#include <tss/tspi.h>
#include "tpm_quote.h"

#define BUFSIZE (1 << 10)

static int read_data(BYTE *buf, const char *name, UINT32 *len)
{
  FILE *in = fopen(name, "rb");
  if (!in) {
    fprintf(stderr, "Cannot open %s\n", name);
    return 1;
  }
  *len = fread(buf, 1, BUFSIZE, in);
  if (ferror(in))
    return 1;
  fclose(in);
  return 0;
}

static int usage(const char *prog)
{
  const char text[] =
    "Usage: %s [-hv] pubkey hash nonce [quote]\n"
    "\tpubkey\tFile containing public part of the AIK\n"
    "\thash\tFile containing the expected PCR composite hash\n"
    "\tnonce\tFile containing nonce in quote request\n"
    "\tquote\tFile with signature to verify\n"
    "Options:\n"
    "\t-h   Display command usage info\n"
    "\t-v   Display command version info\n"
    "\n"
    "On success, verifies quote.\n";
    fprintf(stderr, text, prog);
    return 1;
}

int main(int argc, char **argv)
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

  switch (argc - optind) {
  case 3:			/* Take quote from standard input */
    break;
  case 4:			/* Take quote from file */
    if (!freopen(argv[optind + 3], "rb", stdin)) {
      fprintf(stderr, "Cannot open %s\n", argv[optind + 3]);
      return 1;
    }
    break;
  default:
    return usage(argv[0]);
  }

  const char *pubkeyname = argv[optind];
  const char *hashname = argv[optind + 1];
  const char *noncename = argv[optind + 2];

  BYTE pubkey[BUFSIZE];
  UINT32 pubkeyLen;
  if (read_data(pubkey, pubkeyname, &pubkeyLen))
    return 1;

  BYTE hash[BUFSIZE];
  UINT32 hashLen;
  if (read_data(hash, hashname, &hashLen))
    return 1;
  if (hashLen < sizeof(TPM_NONCE)) {
    fprintf(stderr, "Hash wrong size\n");
    return 1;
  }
  TPM_NONCE *hashNonce = quote_nonce(hash);
  if (!hashNonce) {
    fprintf(stderr, "Hash format error\n");
    return 1;
  }

  BYTE nonce[BUFSIZE];
  UINT32 nonceLen;
  if (read_data(nonce, noncename, &nonceLen))
    return 1;
  if (nonceLen != sizeof(TPM_NONCE)) {
    fprintf(stderr, "Nonce wrong size\n");
    return 1;
  }
  /* Insert nonce into provisioned signed data */
  memcpy(hashNonce, nonce, sizeof(TPM_NONCE));

  BYTE quote[BUFSIZE];
  UINT32 quoteLen;
  quoteLen = fread(quote, 1, BUFSIZE, stdin);
  fclose(stdin);

  /* Decode public key */
  UINT32 blobType;
  BYTE blob[BUFSIZE];
  UINT32 blobLen = BUFSIZE;
  TSS_RESULT rc =
    Tspi_DecodeBER_TssBlob(pubkeyLen, pubkey, &blobType, &blobLen, blob);
  if (rc != TSS_SUCCESS)
    return tss_err(rc, "decoding public key");
  if (blobType !=  TSS_BLOB_TYPE_PUBKEY) {
    fprintf(stderr, "Error while decoding public key, got wrong blob type");
    return 1;
  }

  /* Create context */
  TSS_HCONTEXT hContext;	/* Context handle */
  rc = Tspi_Context_Create(&hContext);
  if (rc != TSS_SUCCESS)
    return tss_err(rc, "creating context");

  /* Create Public AIK object */
  TSS_HKEY hPubAIK;
  int initFlags = TSS_KEY_TYPE_IDENTITY | TSS_KEY_SIZE_2048;
  rc = Tspi_Context_CreateObject(hContext,
				 TSS_OBJECT_TYPE_RSAKEY,
				 initFlags, &hPubAIK);
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "creating public AIK object"));

  /* Install public key */
  rc = Tspi_SetAttribData(hPubAIK, TSS_TSPATTRIB_KEY_BLOB,
			  TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
			  blobLen, blob);
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "installing public key"));

  /* Hash quote for signature checking */
  TSS_HHASH hHash;
  rc = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_HASH,
				 TSS_HASH_SHA1, &hHash);
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "creating hash object"));

  rc = Tspi_Hash_UpdateHashValue(hHash, hashLen, hash);
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "setting hash to quote"));

  /* Verify the signature on the quote */
  rc = Tspi_Hash_VerifySignature(hHash, hPubAIK, quoteLen, quote);
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "verifying signature"));

  return tidy(hContext, 0);
}
