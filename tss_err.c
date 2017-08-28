/*
 * Print TSS error results.
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
#include <tss/tspi.h>
#include "tpm_quote.h"

const char *tss_result(TSS_RESULT result)
{
  switch (ERROR_CODE(result)) {
  case TSS_SUCCESS:
    return "TSS_SUCCESS";
  case TSS_E_FAIL:
    return "TSS_E_FAIL";
  case TSS_E_BAD_PARAMETER:
    return "TSS_E_BAD_PARAMETER";
  case TSS_E_INTERNAL_ERROR:
    return "TSS_E_INTERNAL_ERROR";
  case TSS_E_OUTOFMEMORY:
    return "TSS_E_OUTOFMEMORY";
  case TSS_E_NOTIMPL:
    return "TSS_E_NOTIMPL";
  case TSS_E_KEY_ALREADY_REGISTERED:
    return "TSS_E_KEY_ALREADY_REGISTERED";
  case TSS_E_TPM_UNEXPECTED:
    return "TSS_E_TPM_UNEXPECTED";
  case TSS_E_COMM_FAILURE:
    return "TSS_E_COMM_FAILURE";
  case TSS_E_TIMEOUT:
    return "TSS_E_TIMEOUT";
  case TSS_E_TPM_UNSUPPORTED_FEATURE:
    return "TSS_E_TPM_UNSUPPORTED_FEATURE";
  case TSS_E_CANCELED:
    return "TSS_E_CANCELED";
  case TSS_E_PS_KEY_NOTFOUND:
    return "TSS_E_PS_KEY_NOTFOUND";
  case TSS_E_PS_KEY_EXISTS:
    return "TSS_E_PS_KEY_EXISTS";
  case TSS_E_PS_BAD_KEY_STATE:
    return "TSS_E_PS_BAD_KEY_STATE";
  case TSS_E_INVALID_OBJECT_TYPE:
    return "TSS_E_INVALID_OBJECT_TYPE";
  case TSS_E_NO_CONNECTION:
    return "TSS_E_NO_CONNECTION";
  case TSS_E_CONNECTION_FAILED:
    return "TSS_E_CONNECTION_FAILED";
  case TSS_E_CONNECTION_BROKEN:
    return "TSS_E_CONNECTION_BROKEN";
  case TSS_E_HASH_INVALID_ALG:
    return "TSS_E_HASH_INVALID_ALG";
  case TSS_E_HASH_INVALID_LENGTH:
    return "TSS_E_HASH_INVALID_LENGTH";
  case TSS_E_HASH_NO_DATA:
    return "TSS_E_HASH_NO_DATA";
  case TSS_E_INVALID_ATTRIB_FLAG:
    return "TSS_E_INVALID_ATTRIB_FLAG";
  case TSS_E_INVALID_ATTRIB_SUBFLAG:
    return "TSS_E_INVALID_ATTRIB_SUBFLAG";
  case TSS_E_INVALID_ATTRIB_DATA:
    return "TSS_E_INVALID_ATTRIB_DATA";
  case TSS_E_INVALID_OBJECT_INITFLAG:
    return "TSS_E_INVALID_OBJECT_INITFLAG";
  case TSS_E_NO_PCRS_SET:
    return "TSS_E_NO_PCRS_SET";
  case TSS_E_KEY_NOT_LOADED:
    return "TSS_E_KEY_NOT_LOADED";
  case TSS_E_KEY_NOT_SET:
    return "TSS_E_KEY_NOT_SET";
  case TSS_E_VALIDATION_FAILED:
    return "TSS_E_VALIDATION_FAILED";
  case TSS_E_TSP_AUTHREQUIRED:
    return "TSS_E_TSP_AUTHREQUIRED";
  case TSS_E_TSP_AUTH2REQUIRED:
    return "TSS_E_TSP_AUTH2REQUIRED";
  case TSS_E_TSP_AUTHFAIL:
    return "TSS_E_TSP_AUTHFAIL";
  case TSS_E_TSP_AUTH2FAIL:
    return "TSS_E_TSP_AUTH2FAIL";
  case TSS_E_KEY_NO_MIGRATION_POLICY:
    return "TSS_E_KEY_NO_MIGRATION_POLICY";
  case TSS_E_POLICY_NO_SECRET:
    return "TSS_E_POLICY_NO_SECRET";
  case TSS_E_INVALID_OBJ_ACCESS:
    return "TSS_E_INVALID_OBJ_ACCESS";
  case TSS_E_INVALID_ENCSCHEME:
    return "TSS_E_INVALID_ENCSCHEME";
  case TSS_E_INVALID_SIGSCHEME:
    return "TSS_E_INVALID_SIGSCHEME";
  case TSS_E_ENC_INVALID_LENGTH:
    return "TSS_E_ENC_INVALID_LENGTH";
  case TSS_E_ENC_NO_DATA:
    return "TSS_E_ENC_NO_DATA";
  case TSS_E_ENC_INVALID_TYPE:
    return "TSS_E_ENC_INVALID_TYPE";
  case TSS_E_INVALID_KEYUSAGE:
    return "TSS_E_INVALID_KEYUSAGE";
  case TSS_E_VERIFICATION_FAILED:
    return "TSS_E_VERIFICATION_FAILED";
  case TSS_E_HASH_NO_IDENTIFIER:
    return "TSS_E_HASH_NO_IDENTIFIER";
  case TSS_E_INVALID_HANDLE:
    return "TSS_E_INVALID_HANDLE";
  case TSS_E_SILENT_CONTEXT:
    return "TSS_E_SILENT_CONTEXT";
  case TSS_E_EK_CHECKSUM:
    return "TSS_E_EK_CHECKSUM";
  case TSS_E_DELEGATION_NOTSET:
    return "TSS_E_DELEGATION_NOTSET";
  case TSS_E_DELFAMILY_NOTFOUND:
    return "TSS_E_DELFAMILY_NOTFOUND";
  case TSS_E_DELFAMILY_ROWEXISTS:
    return "TSS_E_DELFAMILY_ROWEXISTS";
  case TSS_E_VERSION_MISMATCH:
    return "TSS_E_VERSION_MISMATCH";
  case TSS_E_DAA_AR_DECRYPTION_ERROR:
    return "TSS_E_DAA_AR_DECRYPTION_ERROR";
  case TSS_E_DAA_AUTHENTICATION_ERROR:
    return "TSS_E_DAA_AUTHENTICATION_ERROR";
  case TSS_E_DAA_CHALLENGE_RESPONSE_ERROR:
    return "TSS_E_DAA_CHALLENGE_RESPONSE_ERROR";
  case TSS_E_DAA_CREDENTIAL_PROOF_ERROR:
    return "TSS_E_DAA_CREDENTIAL_PROOF_ERROR";
  case TSS_E_DAA_CREDENTIAL_REQUEST_PROOF_ERROR:
    return "TSS_E_DAA_CREDENTIAL_REQUEST_PROOF_ERROR";
  case TSS_E_DAA_ISSUER_KEY_ERROR:
    return "TSS_E_DAA_ISSUER_KEY_ERROR";
  case TSS_E_DAA_PSEUDONYM_ERROR:
    return "TSS_E_DAA_PSEUDONYM_ERROR";
  case TSS_E_INVALID_RESOURCE:
    return "TSS_E_INVALID_RESOURCE";
  case TSS_E_NV_AREA_EXIST:
    return "TSS_E_NV_AREA_EXIST";
  case TSS_E_NV_AREA_NOT_EXIST:
    return "TSS_E_NV_AREA_NOT_EXIST";
  case TSS_E_TSP_TRANS_AUTHFAIL:
    return "TSS_E_TSP_TRANS_AUTHFAIL";
  case TSS_E_TSP_TRANS_AUTHREQUIRED:
    return "TSS_E_TSP_TRANS_AUTHREQUIRED";
  case TSS_E_TSP_TRANS_NOTEXCLUSIVE:
    return "TSS_E_TSP_TRANS_NOTEXCLUSIVE";
  case TSS_E_TSP_TRANS_FAIL:
    return "TSS_E_TSP_TRANS_FAIL";
  case TSS_E_TSP_TRANS_NO_PUBKEY:
    return "TSS_E_TSP_TRANS_NO_PUBKEY";
  case TSS_E_NO_ACTIVE_COUNTER:
    return "TSS_E_NO_ACTIVE_COUNTER";
  default:
    return NULL;
  }
}

int tss_err(TSS_RESULT rc, const char *msg)
{
  const char *result = tss_result(rc);
  if (result)
    fprintf(stderr, "Error while %s. Error code: %s\n", msg, result);
  else
    fprintf(stderr, "Error while %s. Error code: 0x%x\n", msg, rc);
  return 1;
}
