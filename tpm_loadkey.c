/*
 * Load a key.
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

#define BLOBSIZE (1 << 10)
#define NONCESIZE (1 << 10)

static int usage(const char *prog)
{
  const char text[] =
    "Usage: %s [-r host] [-hv] blob uuid\n"
    "Options:\n"
    "\t-r host\n"
    "\t     Perform operation on remote host\n"
    "\t-h   Display command usage info\n"
    "\t-v   Display command version info\n"
    "\n"
    "On success, load and registers key in blob as uuid.\n";
  fprintf(stderr, text, prog);
  return 1;
}

int main(int argc, char **argv)
{
  TSS_UNICODE *host = NULL;
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

  if (argc != optind + 2)
    return usage(argv[0]);

  const char *blobname = argv[optind];
  const char *uuidname = argv[optind + 1];

  FILE *in = fopen(blobname, "rb");
  if (!in) {
    fprintf(stderr, "Cannot open %s\n", blobname);
    return 1;
  }
  BYTE blob[BLOBSIZE];
  UINT32 blobLen;
  blobLen = fread(blob, 1, BLOBSIZE, in);
  fclose(in);

  in = fopen(uuidname, "rb");
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
  free(host);
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "connecting"));

  if (loadkey(hContext, blob, blobLen, uuid))
    return tidy(hContext, 1);

  return tidy(hContext, 0);
}
