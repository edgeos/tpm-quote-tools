AC_INIT(TPM Quote Tools, 1.0.2,, tpm-quote-tools)

AC_CONFIG_SRCDIR(tpm_mkaik.c)

AM_INIT_AUTOMAKE

AM_CONFIG_HEADER(config.h)

AC_CANONICAL_HOST

# Older versions of autoconf don't know about C99,
# so you may have to commented this out and use:
# AC_PROG_CC
AC_PROG_CC_C99
AC_STDC_HEADERS
AC_PROG_RANLIB
AC_PROG_INSTALL

AC_ARG_WITH([tss12],
            [AS_HELP_STRING([--without-tss12],
              [disable support for TSS 1.2])],
            [],
            [with_tss12=yes])

case "$host_os" in
  *mingw32 | *cygwin)
    AC_DEFINE([WIN32], 1, [Define to 1 for the Windows operating system.])
    CPPFLAGS="$CPPFLAGS -Iinclude"
    LDFLAGS="$LDFLAGS -mconsole"
    ;;
esac

AC_CHECK_HEADERS([tss/tspi.h], [],
  [AC_MSG_ERROR([TSS header files not found])])

# On Windows, the name of the TSS library may differ from libtspi.
# You should specify the name with
#   LIBS=-l<library>
# on the command line used to invoke ./configure
AC_SEARCH_LIBS([Tspi_Context_Create], [tspi], [],
  [AC_MSG_ERROR([TSS 1.1 lib not found])])

if test "X$with_tss12" = Xyes ; then
  AC_SEARCH_LIBS([Tspi_TPM_SetOperatorAuth], [tspi])
else
  ac_cv_search_Tspi_TPM_SetOperatorAuth=no
fi

if test "X$ac_cv_search_Tspi_TPM_SetOperatorAuth" = Xno ; then
  AC_MSG_NOTICE([Configuring for TSS 1.1])
else
  AC_DEFINE([HAVE_TSS_12_LIB], 1,
            [Define to 1 if you have a TSS 1.2 library.])
  AC_MSG_NOTICE([Configuring for TSS 1.2])
fi

# See if TrouSerS extensions are available
AC_CHECK_HEADERS([trousers/tss.h])
AC_CHECK_HEADERS([trousers/trousers.h], [], [],
[#ifdef HAVE_TROUSERS_TSS_H
#include <trousers/tss.h>
#endif])

# See if POSIX character conversion routines are available
AC_CHECK_HEADERS([iconv.h])

# See if POSIX langinfo header is available
AC_CHECK_HEADERS([langinfo.h])

# See if the OpenSSL UI is available
AC_CHECK_HEADERS([openssl/ui.h])
AC_SEARCH_LIBS([UI_new], [crypto])

if test "X$ac_cv_search_ssl_UI_new" != Xno ; then
  AC_MSG_NOTICE([OpenSSL UI available])
  AC_DEFINE([HAVE_OPENSSL_UI_LIB], 1,
            [Define to 1 if you have the OpenSSL UI library.])
fi

# Add warning when using GCC
if test "X$GCC" = Xyes ; then
  CFLAGS="$CFLAGS -Wall"
fi

AC_CONFIG_FILES([Makefile tpm-quote-tools.spec])

AC_OUTPUT
