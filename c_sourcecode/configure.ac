AC_PREREQ([2.69])
AC_INIT([crashupload], [1.0], [support@rdkcentral.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
#AC_PROG_CC_C11
AM_PROG_AR

# Checks for libraries.
#PKG_CHECK_MODULES([LIBCURL], [libcurl >= 7.0])
#PKG_CHECK_MODULES([OPENSSL], [openssl >= 1.0])
#PKG_CHECK_MODULES([ZLIB], [zlib >= 1.2])

# Checks for header files.
#AC_CHECK_HEADERS([fcntl.h stdlib.h string.h sys/time.h unistd.h])
#AC_CHECK_HEADERS([curl/curl.h openssl/ssl.h zlib.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gettimeofday memset strchr strdup strerror])

# Compiler flags
CFLAGS="$CFLAGS -Wall -Werror -O2"
#CFLAGS="$CFLAGS -Wall -Werror -O2 -std=c11"
#CFLAGS="$CFLAGS -D_POSIX_C_SOURCE=200809L"

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT

echo ""
echo "Configuration Summary:"
echo "======================"
echo "  Package:        ${PACKAGE_NAME} ${PACKAGE_VERSION}"
echo "  C Compiler:     ${CC}"
echo "  CFLAGS:         ${CFLAGS}"
echo "  LIBCURL_CFLAGS: ${LIBCURL_CFLAGS}"
echo "  LIBCURL_LIBS:   ${LIBCURL_LIBS}"
echo "  OPENSSL_CFLAGS: ${OPENSSL_CFLAGS}"
echo "  OPENSSL_LIBS:   ${OPENSSL_LIBS}"
echo "  ZLIB_CFLAGS:    ${ZLIB_CFLAGS}"
echo "  ZLIB_LIBS:      ${ZLIB_LIBS}"
echo ""
