/*
 * Create a legecy endorsement key.
 * Copyright (C) 2010 The MITRE Corporation
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the BSD License as published by the
 * University of California.
 */

/* For use on systems on which IBM's tpm-tools are not available. */

#if defined HAVE_CONFIG_H
#include "config.h"
#endif
#include <stddef.h>
#include <stdio.h>
#include <tss/tspi.h>
#include "tpm_quote.h"

const static char usage[] =
  "Usage: %s\n"
  "On success, creates an endorsment key using\n"
  "Tspi_TPM_CreateEndorsementKey.\n";

int main(int argc, char **argv)
{
  if (argc != 1) {
    fprintf(stderr, usage, argv[0]);
    return 1;
  }

  /* Create context */
  TSS_HCONTEXT hContext;
  int rc = Tspi_Context_Create(&hContext);
  if (rc != TSS_SUCCESS)
    return tss_err(rc, "creating context");

  rc = Tspi_Context_Connect(hContext, NULL);
  if (rc != TSS_SUCCESS)
    return tss_err(rc, "connecting");

  TSS_HKEY hKEY;
  rc = Tspi_Context_CreateObject(hContext,
				 TSS_OBJECT_TYPE_RSAKEY,
				 TSS_KEY_TYPE_LEGACY|TSS_KEY_SIZE_2048,
				 &hKEY);
  if (rc != TSS_SUCCESS)
    return tss_err(rc, "creating KEY object");

  /* Get TPM handle */
  TSS_HTPM hTPM;
  rc = Tspi_Context_GetTpmObject(hContext, &hTPM);
  if (rc != TSS_SUCCESS)
    return tss_err(rc, "getting TPM object");

  BYTE nonce[20];		/* Value of nonce does not matter */
  TSS_VALIDATION valid;
  valid.ulExternalDataLength = sizeof nonce;
  valid.rgbExternalData = nonce;

  rc = Tspi_TPM_CreateEndorsementKey(hTPM, hKEY, &valid);
  if (rc != TSS_SUCCESS)
    return tss_err(rc, "creating endorsment key");

  return 0;
}
