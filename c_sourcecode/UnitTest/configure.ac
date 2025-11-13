AC_INIT([crashupload-tests], [1.0.0], [support@rdkcentral.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CXX
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

# Check for GTest
AC_CHECK_LIB([gtest], [main], [], [AC_MSG_ERROR([Google Test library required])])
AC_CHECK_LIB([gtest_main], [main], [], [AC_MSG_ERROR([Google Test main library required])])
AC_CHECK_LIB([pthread], [pthread_create], [], [AC_MSG_ERROR([pthread library required])])
AC_CHECK_LIB([crypto], [SHA1_Init], [], [AC_MSG_ERROR([OpenSSL crypto library required])])

# Compiler flags
CXXFLAGS="$CXXFLAGS -Wall -Wextra -O2 -std=c++11"
CFLAGS="$CFLAGS -Wall -Wextra -O2"

AC_OUTPUT
