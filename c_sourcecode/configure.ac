AC_INIT([crashupload], [1.0.0], [support@rdkcentral.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AC_PROG_CC_C11
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
 Makefile
 src/Makefile
])

# Check for required libraries
AC_CHECK_LIB([crypto], [SHA1_Init], [], [AC_MSG_ERROR([OpenSSL crypto library required])])

# Compiler flags for embedded systems
CFLAGS="$CFLAGS -Wall -Wextra -Werror -O2 -fstack-protector-strong"

AC_OUTPUT
