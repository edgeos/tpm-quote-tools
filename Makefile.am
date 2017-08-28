bin_PROGRAMS = tpm_mkuuid tpm_mkaik tpm_getpcrhash tpm_loadkey	\
tpm_unloadkey tpm_getquote tpm_verifyquote tpm_updatepcrhash

noinst_PROGRAMS = createek takeownership

noinst_LIBRARIES = libtpm_quote.a

noinst_HEADERS = include/tss/compat11b.h include/tss/platform.h		\
include/tss/tcpa_defines.h include/tss/tcpa_error.h			\
include/tss/tcpa_struct.h include/tss/tcpa_typedef.h			\
include/tss/tcs_defines.h include/tss/tcs_error.h include/tss/tcs.h	\
include/tss/tcs_structs.h include/tss/tcs_typedef.h			\
include/tss/tddlapi_error.h include/tss/tddl_error.h			\
include/tss/tddli.h include/tss/tpm_error.h include/tss/tpm.h		\
include/tss/tpm_ordinal.h include/tss/tspi.h include/tss/tss_defines.h	\
include/tss/tss_error_basics.h include/tss/tss_error.h			\
include/tss/tss_structs.h include/tss/tss_typedef.h

libtpm_quote_a_SOURCES = tpm_quote.h tss_err.c tidy.c loadkey.c	\
pcr_mask.c quote.c quote_nonce.c toutf16le.c getcodeset.c

tpm_mkuuid_SOURCES = tpm_quote.h tpm_mkuuid.c
tpm_mkuuid_LDADD = libtpm_quote.a

tpm_mkaik_SOURCES = tpm_quote.h tpm_mkaik.c
tpm_mkaik_LDADD = libtpm_quote.a

tpm_getpcrhash_SOURCES = tpm_quote.h tpm_getpcrhash.c
tpm_getpcrhash_LDADD = libtpm_quote.a

tpm_loadkey_SOURCES = tpm_quote.h tpm_loadkey.c
tpm_loadkey_LDADD = libtpm_quote.a

tpm_unloadkey_SOURCES = tpm_quote.h tpm_unloadkey.c
tpm_unloadkey_LDADD = libtpm_quote.a

tpm_getquote_SOURCES = tpm_quote.h tpm_getquote.c
tpm_getquote_LDADD = libtpm_quote.a

tpm_verifyquote_SOURCES = tpm_quote.h tpm_verifyquote.c
tpm_verifyquote_LDADD = libtpm_quote.a

tpm_updatepcrhash_SOURCES = tpm_quote.h tpm_updatepcrhash.c
tpm_updatepcrhash_LDADD = libtpm_quote.a

createek_SOURCES = tpm_quote.h createek.c
createek_LDADD = libtpm_quote.a

takeownership_SOURCES = tpm_quote.h takeownership.c
takeownership_LDADD = libtpm_quote.a

dist_man_MANS = tpm_mkuuid.8 tpm_mkaik.8 tpm_loadkey.8 tpm_unloadkey.8	\
tpm_getpcrhash.8 tpm_getquote.8 tpm_verifyquote.8 tpm_updatepcrhash.8	\
tpm_quote_tools.8

EXTRA_DIST = README_win32.txt win32.txt control
