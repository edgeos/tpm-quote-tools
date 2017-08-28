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
#include <stdlib.h>
#include <tss/tspi.h>
#include "tpm_quote.h"

/* Load a key and register it under the given UUID. */
int loadkey(TSS_HCONTEXT hContext,
	    BYTE *blob, UINT32 blobLen,
	    TSS_UUID uuid)
{
  /* Get SRK */
  TSS_UUID SRK_UUID = TSS_UUID_SRK;
  TSS_HKEY hSRK;
  TSS_RESULT rc;
  rc = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM,
				  SRK_UUID, &hSRK);
  if (rc != TSS_SUCCESS)
    return tss_err(rc, "loading SRK");

  TSS_HPOLICY hSrkPolicy;
  rc = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSrkPolicy);
  if (rc != TSS_SUCCESS)
    return tss_err(rc, "getting SRK policy");

  BYTE srkSecret[] = TSS_WELL_KNOWN_SECRET;
  rc = Tspi_Policy_SetSecret(hSrkPolicy, TSS_SECRET_MODE_SHA1,
			     sizeof srkSecret, srkSecret);
  if (rc != TSS_SUCCESS)
    return tss_err(rc, "setting SRK secret");

  TSS_HKEY hAIK;		/* AIK handle */
  rc = Tspi_Context_LoadKeyByBlob(hContext, hSRK, blobLen, blob, &hAIK);
  if (rc != TSS_SUCCESS)
    return tss_err(rc, "loading key blob");

  /* Register the key in persistant storage */
  rc = Tspi_Context_RegisterKey(hContext, hAIK, TSS_PS_TYPE_SYSTEM,
				uuid, TSS_PS_TYPE_SYSTEM, SRK_UUID);
  if (rc != TSS_SUCCESS)
    return tss_err(rc, "registering a key");

  return 0;
}
