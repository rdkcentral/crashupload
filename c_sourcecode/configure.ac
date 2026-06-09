##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2025 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

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
CFLAGS="$CFLAGS -Wall -Werror -O2 -DT2_EVENT_ENABLED"
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
