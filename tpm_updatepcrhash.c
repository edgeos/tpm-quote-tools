/*
 * Update a PCR hash to reflect new PCR values
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

#if defined HAVE_TROUSERS_TROUSERS_H
#include <stddef.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>
#include "tpm_quote.h"

#define PCRSELSIZE 3
#define NPCRVALS (8 * PCRSELSIZE)
#define PCRVALSIZE 20
#define BUFSIZE (1 << 10)

static int trousers_err(TSS_RESULT rc, const char *msg)
{
  const char *result = Trspi_Error_String(rc);
  if (result)
    fprintf(stderr, "Error while %s. Error code: %s\n", msg, result);
  else
    fprintf(stderr, "Error while %s. Error code: 0x%x\n", msg, rc);
  return 1;
}

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
    "Usage: %s [-hv] oldhash newpcrvals newhash\n"
    "\toldhash:      file containing old PCR hash\n"
    "\tnewpcrvals:   file containing list of PCR index=value pairs\n"
    "\t              to use in creating new hash\n"
    "\tnewhash:      output file\n"
    "On success, writes the new PCR hash to newhash\n";
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
  if (argc != optind + 3)
    return usage(argv[0]);

  const char *oldhashname = argv[optind];
  const char *newpcrvalsname = argv[optind + 1];
  const char *newhashname = argv[optind + 2];

  FILE *in = fopen(newpcrvalsname, "r");
  if (!in) {
    fprintf(stderr, "Cannot open %s\n", newpcrvalsname);
    return 1;
  }

  BYTE pcrSelect[PCRSELSIZE];
  BYTE pcrValue[NPCRVALS][PCRVALSIZE];
  memset(pcrSelect, 0, sizeof pcrSelect);
  memset(pcrValue, 0, sizeof pcrValue);
  UINT32 npcrs = 0;	      /* Number of bits set in pcrSelect */
  unsigned int pcrind;	      /* Type matches "%u" format specifier */
  UINT32 i, j;

  while (1) {
    char line[BUFSIZE];		/* Read a line of input */
    if (!fgets(line, BUFSIZE, in)) {
      if (ferror(in)) {
	fprintf(stderr, "Error on file read\n");
	exit(1);
      }
      else
	break;			/* EOF found, exit loop */
    }

    npcrs++;			/* Found a line of input */

    char *endp;			/* Parse PCR index */
    pcrind = (unsigned int)strtoul(line, &endp, 10);
    if (endp == line) {
      fprintf(stderr, "(%s:  cannot read PCR index\n", newpcrvalsname);
      exit(1);
    }

    if (pcrind >= NPCRVALS) {
      fprintf(stderr, "%s:  out of range PCR %u\n",
	      newpcrvalsname, pcrind);
      exit(1);
    }

    /* Ensure there are no duplicate PCR specifications, as it would
       cause npcrs to be too large, and corrupt the hash
       computation. */
    if (pcrSelect[pcrind / 8] & 1 << (pcrind % 8)) {
      fprintf(stderr, "%s:  PCR %u already specified\n",
	      newpcrvalsname, pcrind);
      exit(1);
    }

    /* Set bit associated with pcrind */
    pcrSelect[pcrind / 8] |= 1 << (pcrind % 8);

    char *val = strchr(endp, '='); /* Find equal sign */
    if (!val) {
      fprintf(stderr, "%s:  ill-formed entry for PCR %u\n",
	      newpcrvalsname, pcrind);
      exit(1);
    }

    for (val++; isspace(*val); val++); /* Skip leading white space */

    for (endp = val; isxdigit(*endp); endp++); /* Find end of value */

    if (endp - val != 2 * PCRVALSIZE) {
      fprintf(stderr, "%s:  ill-formed entry for PCR %u\n",
	      newpcrvalsname, pcrind);
      exit(1);
    }

    for(j = 0; val < endp; val += 2, j++) { /* Parse PCR value */
      unsigned int byte;
      if (sscanf(val, "%2x", &byte) != 1) {
	fprintf(stderr, "%s:  error reading PCR value byte for PCR %u\n",
		newpcrvalsname, pcrind);
	exit(1);
      }
      pcrValue[pcrind][j] = (BYTE)byte;
    }
  }

  /* Read the old hash */
  BYTE hash[BUFSIZE];
  UINT32 hashLen;
  if (read_data(hash, oldhashname, &hashLen))
    return 1;
  if (hashLen < sizeof(TPM_QUOTE_INFO)) {
    fprintf(stderr, "Hash too small\n");
    return 1;
  }

  TPM_QUOTE_INFO2 *qi2 = (TPM_QUOTE_INFO2 *)hash;
  TPM_QUOTE_INFO *qi = (TPM_QUOTE_INFO *)hash;
  TPM_PCR_INFO_SHORT info;	/* This is set only for quote 2 */
  UINT16 selectSize;
  TSS_RESULT rc;
  if (qi2->fixed[0] == 'Q' && qi2->fixed[1] == 'U' &&
      qi2->fixed[2] == 'T' && qi2->fixed[3] == '2') {
    qi = NULL;			/* Get select size and info */
    UINT64 offset = (UINT64)offsetof(TPM_QUOTE_INFO2, externalData);
    Trspi_UnloadBlob_NONCE(&offset, hash, 0);
    rc = Trspi_UnloadBlob_PCR_INFO_SHORT(&offset, hash, &info);
    if (rc != TSS_SUCCESS)
      return trousers_err(rc, "extracting PCR info from hash");
    selectSize = info.pcrSelection.sizeOfSelect;
  } else if (qi->fixed[0] == 'Q' && qi->fixed[1] == 'U' &&
	     qi->fixed[2] == 'O' && qi->fixed[3] == 'T') {
    qi2 = NULL;			/* Set only select size */
    selectSize = 2;
  } else {
    fprintf(stderr, "%s is not a valid quote!\n", oldhashname);
    return 1;
  }

  if (selectSize > PCRSELSIZE) {
    fprintf(stderr, "Cannot handle the selection size of %u in %s\n",
	    selectSize, oldhashname);
    return 1;
  }

  for (i = selectSize; i < PCRSELSIZE; i++)
    if (pcrSelect[i]) {
      fprintf(stderr, "Specified PCRs exceed supported PCRs in hash\n");
      return 1;
    }

  /* Construct a hash of a PCR composite */

  /* The TSS data structure that holds a PCR composite hash is
     TPM_PCR_COMPOSITE.  It contains a TPM_PCR_SELECTION, and a list
     of PCR values.  There is no direct support for updating a hash
     with a TPM_PCR_COMPOSITE.  To compute a hash, one must hash the
     selection, and then hash the values in pieces. */

  Trspi_HashCtx hctx;
  rc = Trspi_HashInit(&hctx, TSS_HASH_SHA1);
  if (rc != TSS_SUCCESS)
    return trousers_err(rc, "initing hash");

  /* Selection */
  /* free(info.pcrSelection.pcrSelect); for pedantics */
  info.pcrSelection.pcrSelect = pcrSelect;
  rc = Trspi_Hash_PCR_SELECTION(&hctx, &info.pcrSelection);
  if (rc != TSS_SUCCESS)
    return trousers_err(rc, "updating hash with PCR selection");

  /* Size of values */
  rc = Trspi_Hash_UINT32(&hctx, npcrs * PCRVALSIZE);
  if (rc != TSS_SUCCESS)
    return trousers_err(rc, "updating hash with value size");

  /* Values */
  for (i = 0, pcrind = 0; i < selectSize; i++) {
    for (j = 1; j != (1 << 8); j <<= 1, pcrind++) {
      if (pcrSelect[i] & j) {
	rc = Trspi_HashUpdate(&hctx, PCRVALSIZE, pcrValue[pcrind]);
	if (rc != TSS_SUCCESS)
	  return trousers_err(rc, "updating hash with a value");
      }
    }
  }

  /* Put composite hash into info even when using old quotes */
  BYTE *digest = (BYTE *)&info.digestAtRelease;
  rc = Trspi_HashFinal(&hctx, digest);
  if (rc != TSS_SUCCESS)
    return trousers_err(rc, "finalizing hash");

  /* Update the hash */
  if (qi2) {
    UINT64 offset = (UINT64)offsetof(TPM_QUOTE_INFO2, externalData);
    Trspi_UnloadBlob_NONCE(&offset, hash, 0);
    Trspi_LoadBlob_PCR_INFO_SHORT(&offset, hash, &info);
  } else {
    size_t digestLen = sizeof info.digestAtRelease;
    memcpy(hash+hashLen-digestLen-sizeof(TPM_NONCE), digest, digestLen);
  }

  /* Write the new hash */
  FILE *out = fopen(newhashname, "wb");
  if (!out) {
    fprintf(stderr, "Cannot open %s\n", newhashname);
    return 1;
  }
  fwrite(hash, 1, hashLen, out);
  fclose(out);

  return 0;
}
#else
int main(void)
{
  fprintf(stderr, "Update PCR hash not available on this platform.\n");
  return 1;
}
#endif
