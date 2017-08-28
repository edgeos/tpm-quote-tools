/*
 * Create a quote.
 * Copyright (C) 2010 The MITRE Corporation
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the BSD License as published by the
 * University of California.
 */

#if defined HAVE_CONFIG_H
#include "config.h"
#endif
#include <tss/tspi.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "tpm_quote.h"

#if defined HAVE_TSS_12_LIB

    /* This function shows the hash offset when one is handling quotes in
       blob format. */
    // #define SHOW_HASH_OFFSET
    #if defined SHOW_HASH_OFFSET && defined HAVE_TROUSERS_TROUSERS_H
    #include <trousers/trousers.h>
    static void show_hash_offset(TSS_VALIDATION *valid)
    {
      if (!valid)
        return;
      TPM_QUOTE_INFO2 *qi2 = (TPM_QUOTE_INFO2 *)(valid->rgbData);
      fprintf(stderr, "TAG: %c%c%c%c\n", qi2->fixed[0],
	      qi2->fixed[1],qi2->fixed[2],qi2->fixed[3]);
      if (qi2->fixed[0] != 'Q' || qi2->fixed[1] != 'U' ||
          qi2->fixed[2] != 'T' || qi2->fixed[3] != '2')
        return;
      fprintf(stderr, "Data size %d\n", valid->ulDataLength);
      UINT64 offset = (UINT64)offsetof(TPM_QUOTE_INFO2, externalData);
      fprintf(stderr, "Nonce start %lu\n", offset);
      Trspi_UnloadBlob_NONCE(&offset, valid->rgbData, 0);
      fprintf(stderr, "Unload PCR_INFO_SHORT start %lu\n", offset);
      TPM_PCR_INFO_SHORT info;
      TSS_RESULT rc =
        Trspi_UnloadBlob_PCR_INFO_SHORT(&offset, valid->rgbData, &info);
      fprintf(stderr, "Unload PCR_INFO_SHORT return code %d offset %lu\n",
	      rc, offset);
      fprintf(stderr, "Locality at release %d\n", info.localityAtRelease);
    }
    #else

        #define show_hash_offset( dummy ) ((void)0)

    #endif

    static int  _quote2(TSS_HCONTEXT hContext,
                        TSS_HKEY hAIK,
                        TSS_HTPM hTPM,
                        UINT32 *pcrs, UINT32 npcrs,
                        TSS_VALIDATION *valid)
    {
        TSS_RESULT  rc;
        TSS_HPCRS   hPCRs;
        UINT32 i;
        BYTE *versionInfo;
        UINT32 versionInfoLen;
        
        rc = Tspi_Context_CreateObject( hContext, 
                                        TSS_OBJECT_TYPE_PCRS, TSS_PCRS_STRUCT_INFO_SHORT, 
                                        &hPCRs );
        if (rc != TSS_SUCCESS)
            return tss_err(rc, "creating PCR mask object");

        for (i = 0; i < npcrs; i++) {    
            rc = Tspi_PcrComposite_SelectPcrIndexEx(hPCRs, pcrs[i],
					                                TSS_PCRS_DIRECTION_RELEASE);
            if (rc != TSS_SUCCESS)
                return tss_err(rc, "creating PCR mask");
        }

        rc = Tspi_TPM_Quote2(hTPM, hAIK, FALSE, hPCRs, valid,
		                     &versionInfoLen, &versionInfo);
        show_hash_offset(valid);
        if (rc != TSS_SUCCESS)
            return tss_err(rc, "performing quote");

        return 0;
    }
    
#else
    
    static int _quote2( TSS_HCONTEXT hContext,
                        TSS_HKEY hAIK,
                        TSS_HTPM hTPM,
                        UINT32 *pcrs, UINT32 npcrs,
                        TSS_VALIDATION *valid)
    {
        (void)hContext;
        (void)hAIK;
        (void)hTPM;
        (void)pcrs;
        (void)npcrs;
        (void)valid;

        fprintf(stderr, "Error quote2 not supported (!defined HAVE_TSS_12_LIB).\n");
        return 1;
    }
    
#endif

static int  _quote_legacy(  TSS_HCONTEXT hContext,
                            TSS_HKEY hAIK,
                            TSS_HTPM hTPM,
                            UINT32 *pcrs, UINT32 npcrs,
                            TSS_VALIDATION *valid)
{
    TSS_RESULT  rc;
    TSS_HPCRS   hPCRs;
    UINT32 i;

    rc = Tspi_Context_CreateObject( hContext, 
                                    TSS_OBJECT_TYPE_PCRS, TSS_PCRS_STRUCT_INFO,
                                    &hPCRs );
    if (rc != TSS_SUCCESS)
        return tss_err(rc, "creating PCR mask object");

    for (i = 0; i < npcrs; i++) {
        rc = Tspi_PcrComposite_SelectPcrIndex(hPCRs, pcrs[i]);
        if (rc != TSS_SUCCESS)
            return tss_err(rc, "creating PCR mask");
    }

    rc = Tspi_TPM_Quote(hTPM, hAIK, hPCRs, valid);
    if (rc != TSS_SUCCESS)
        return tss_err(rc, "performing quote");
    
    return 0;
}

/* Returns a TPM quote in the TSS validation struct.  The nonce used
   by the quote is passed in via the struct. */
int quote(TSS_HCONTEXT hContext, TSS_UUID uuid,
	      UINT32 *pcrs, UINT32 npcrs,
	      TSS_VALIDATION *valid)
{
    TSS_RESULT rc;
    
    /* Get TPM handle */
    TSS_HTPM hTPM;		/* TPM handle */
    rc = Tspi_Context_GetTpmObject(hContext, &hTPM);
    if (rc != TSS_SUCCESS)
        return tss_err(rc, "getting TPM object");

    /* Get SRK */
    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    TSS_HKEY hSRK;

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

    /* Get AIK */
    TSS_HKEY hAIK;		/* AIK handle */
    rc = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM,
		          uuid, &hAIK);
    if (rc != TSS_SUCCESS)
        return tss_err(rc, "loading AIK");

    /* Get quote */
    if( 0!= _quote2(  hContext, hAIK, hTPM, pcrs, npcrs, valid) ){
        fprintf(stderr, "\t... failling back to legacy quote command\n");
        return _quote_legacy(   hContext, hAIK, hTPM, pcrs, npcrs, valid);
    }

    return 0;
}

