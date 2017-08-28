/*
 * Create an identity key.
 * Copyright (C) 2010 The MITRE Corporation
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the BSD License as published by the
 * University of California.
 */

/*
 * This program generates a TPM identity key and puts the key blob in
 * the file aik.blob, and its DER-encoded public key in aik.der.
 *
 * Inspired by Hal Finney's code on http://privacyca.com.
 */

#if defined HAVE_CONFIG_H
#include "config.h"
#endif
#define BLOBLEN (1 << 10)
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <tss/tspi.h>
#include "tpm_quote.h"

#if defined HAVE_OPENSSL_UI_H && defined HAVE_OPENSSL_UI_LIB
#define USE_OPENSSL_UI
#endif

#if defined USE_OPENSSL_UI
#include <openssl/ui.h>

#define UI_MAX_SECRET_STRING_LENGTH 256

/* Prompt for a password using OpenSSL's UI library */
static int getpasswd(const char *prompt, char *buf, int len)
{
  UI *ui = UI_new();		/* Create UI with default method */
  if (!ui)
    return -1;

  /* Add input buffer leaving room for a null byte */
  if (!UI_add_input_string(ui, prompt, 0, buf, 1, len - 1)) {
    UI_free(ui);
    return -1;
  }

  int rc = UI_process(ui);	/* Print prompt and read password */
  UI_free(ui);
  return rc ? -1 : 0;
}
#endif

static int usage(const char *prog)
{
  const char text[] =
    "Usage: %s [options] blob pubkey\n"
    "Options:\n"
    "\t-z   Use well known secret used as owner secret\n"
    "\t-u   Use TSS UNICODE encoding for passwords\n"
    "\t-h   Display command usage info\n"
    "\t-v   Display command version info\n"
    "\n"
    "On success, creates an attestation identity key in blob\n"
    "and a DER-encoded public key in pubkey.\n";
  fprintf(stderr, text, prog);
  return 1;
}

int main (int argc, char **argv)
{
  int well_known = 0;
  int utf16le = 0;
  int opt;
  while ((opt = getopt(argc, argv, "zuhv")) != -1) {
    switch (opt) {
    case 'z':
      well_known = 1;
      break;
    case 'u':
      utf16le = 1;
      break;
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

#if !defined HAVE_ICONV_H
  if (utf16le) {
    fprintf(stderr, "TSS UNICODE passwords not supported on this platform.\n");
    return 1;
  }
#endif

  const char *blobname = argv[optind];
  const char *pubkeyname = argv[optind + 1];

  /* Create context */
  TSS_HCONTEXT hContext;
  int rc = Tspi_Context_Create(&hContext);
  if (rc != TSS_SUCCESS)
    return tss_err(rc, "creating context");

  rc = Tspi_Context_Connect(hContext, NULL);
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "connecting"));

  /* Get SRK */
  TSS_UUID SRK_UUID = TSS_UUID_SRK;
  TSS_HKEY hSRK;
  rc = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM,
				  SRK_UUID, &hSRK);
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "loading SRK"));

  TSS_HPOLICY hSrkPolicy;
  rc = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSrkPolicy);
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "getting SRK policy"));

  BYTE srkSecret[] = TSS_WELL_KNOWN_SECRET;
  rc = Tspi_Policy_SetSecret(hSrkPolicy, TSS_SECRET_MODE_SHA1,
			     sizeof srkSecret, srkSecret);
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "setting SRK secret"));

  /* Get TPM handle */
  TSS_HTPM hTPM;
  rc = Tspi_Context_GetTpmObject(hContext, &hTPM);
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "getting TPM object"));

  TSS_HPOLICY hTPMPolicy;
  rc = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
				 TSS_POLICY_USAGE, &hTPMPolicy);
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "getting TPM policy"));

  rc = Tspi_Policy_AssignToObject(hTPMPolicy, hTPM);
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "assigning TPM policy"));

  if (well_known)
    rc = Tspi_Policy_SetSecret(hTPMPolicy, TSS_SECRET_MODE_SHA1,
			       sizeof srkSecret, srkSecret);
  else
#if defined USE_OPENSSL_UI
    {
      int bufSize = UI_MAX_SECRET_STRING_LENGTH;
      char buf[bufSize];
      if (getpasswd("Enter owner password: ", buf, bufSize) < 0)
	return tidy(hContext, tss_err(TSS_E_FAIL, "getting owner password"));
#if defined HAVE_ICONV_H
      if (utf16le) {
	char *passwd = toutf16le(buf);
	if (!passwd)
	  return tidy(hContext, 
		      tss_err(TSS_E_FAIL, "converting password to UTF16LE"));
	size_t passwdLen = utf16lelen(passwd);
	rc = Tspi_Policy_SetSecret(hTPMPolicy, TSS_SECRET_MODE_PLAIN,
				   passwdLen, (BYTE *)passwd);
	free(passwd);
      }
      else
	rc = Tspi_Policy_SetSecret(hTPMPolicy, TSS_SECRET_MODE_PLAIN,
				   strlen(buf), (BYTE *)buf);
#else
      rc = Tspi_Policy_SetSecret(hTPMPolicy, TSS_SECRET_MODE_PLAIN,
				 strlen(buf), (BYTE *)buf);
#endif
      memset(buf, 0, bufSize);
    }
#else
    rc = Tspi_Policy_SetSecret(hTPMPolicy, TSS_SECRET_MODE_POPUP, 0, NULL);
#endif
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "setting TPM policy secret"));

  /* Create dummy PCA key */
  TSS_HKEY hPCA;
  rc = Tspi_Context_CreateObject(hContext,
				 TSS_OBJECT_TYPE_RSAKEY,
				 TSS_KEY_TYPE_LEGACY|TSS_KEY_SIZE_2048,
				 &hPCA);
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "creating PCA object"));

  /* Create the PCA key in the TPM, it is not user supplied */
  rc = Tspi_Key_CreateKey(hPCA, hSRK, 0);
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "creating PCA key in TPM"));

  /* Create AIK object */
  int initFlags = TSS_KEY_TYPE_IDENTITY | TSS_KEY_SIZE_2048;
  TSS_HKEY hAIK;
  rc = Tspi_Context_CreateObject(hContext,
				 TSS_OBJECT_TYPE_RSAKEY,
				 initFlags, &hAIK);
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "creating AIK object"));

  /* Generate new AIK */
  BYTE lab[] = {};
  BYTE *blob;
  UINT32 blobLen;
  rc = Tspi_TPM_CollateIdentityRequest(hTPM, hSRK, hPCA, 0, lab,
				       hAIK, TSS_ALG_AES,
				       &blobLen, &blob);
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "generating new key"));
  Tspi_Context_FreeMemory(hContext, blob);

  /* Get key blob */
  rc = Tspi_GetAttribData(hAIK, TSS_TSPATTRIB_KEY_BLOB,
			  TSS_TSPATTRIB_KEYBLOB_BLOB,
			  &blobLen, &blob);
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "getting key blob"));

  /* Write key blob */
  FILE *out = fopen(blobname, "wb");
  if (out == NULL) {
    fprintf(stderr, "Cannot open %s\n", blobname);
    return tidy(hContext, 1);
  }
  fwrite(blob, 1, blobLen, out);
  fclose(out);
  Tspi_Context_FreeMemory(hContext, blob);

  /* Get public key blob */
  rc = Tspi_GetAttribData(hAIK, TSS_TSPATTRIB_KEY_BLOB,
			  TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
			  &blobLen, &blob);
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "getting public key blob"));

  BYTE derBlob[BLOBLEN];
#if defined WIN32
  // Handle NTRU tsp1.dll bug.  One must compute the size first.
  UINT32 derBlobLen = 0;
  rc = Tspi_EncodeDER_TssBlob(blobLen, blob, TSS_BLOB_TYPE_PUBKEY,
			      &derBlobLen, derBlob);
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "getting DER encoding public key size"));
  if (derBlobLen > sizeof derBlob) {
    fprintf(stderr, "Size of key %u is greater than %u\n",
	    derBlobLen, sizeof derBlob);
    return tidy(hContext, 1);
  }
#else
  UINT32 derBlobLen = sizeof derBlob;
#endif
  rc = Tspi_EncodeDER_TssBlob(blobLen, blob, TSS_BLOB_TYPE_PUBKEY,
			      &derBlobLen, derBlob);
  if (rc != TSS_SUCCESS)
    return tidy(hContext, tss_err(rc, "DER encoding public key blob"));
  Tspi_Context_FreeMemory(hContext, blob);

  /* Write DER-encoded public key */
  out = fopen(pubkeyname, "wb");
  if (out == NULL) {
    fprintf(stderr, "Cannot open %s\n", pubkeyname);
    return tidy(hContext, 1);
  }
  fwrite(derBlob, 1, derBlobLen, out);
  fclose(out);

  return tidy(hContext, 0);
}
