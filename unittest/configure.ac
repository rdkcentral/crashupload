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

# configure.ac for crashupload unit tests
# Autoconf configuration for building GTest-based unit tests

AC_PREREQ([2.69])
AC_INIT([crashupload-unittest], [1.0.0], [support@rdkcentral.com])
AM_INIT_AUTOMAKE([foreign subdir-objects -Wall -Werror])
AC_CONFIG_SRCDIR([config_manager_gtest.cpp])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs
AC_PROG_CXX
AC_PROG_CC
AC_PROG_RANLIB
AM_PROG_AR

# Require C++11 support
#AX_CXX_COMPILE_STDCXX([11], [noext], [mandatory])

# Add common include paths for header detection
CPPFLAGS="$CPPFLAGS -I/usr/include -I/usr/local/include"

# Checks for libraries
AC_CHECK_LIB([pthread], [pthread_create], [], [
    AC_MSG_ERROR([pthread library is required])
])

AC_CHECK_LIB([gtest], [main], [], [
    AC_MSG_ERROR([Google Test library is required. Install libgtest-dev])
], [-lpthread])

AC_CHECK_LIB([gtest_main], [main], [], [
    AC_MSG_WARN([Google Test main library not found, but continuing])
], [-lgtest -lpthread])

AC_CHECK_LIB([gmock], [main], [], [
    AC_MSG_WARN([Google Mock library not found, but continuing])
], [-lgtest -lpthread])

AC_CHECK_LIB([gmock_main], [main], [], [
    AC_MSG_WARN([Google Mock main library not found, but continuing])
], [-lgmock -lgtest -lpthread])

# Checks for header files
AC_CHECK_HEADERS([stdio.h stdlib.h string.h unistd.h stdbool.h stdint.h sys/types.h])

# Check for GTest headers (with warning instead of error)
AC_CHECK_HEADERS([gtest/gtest.h], [HAVE_GTEST=yes], [
    AC_MSG_WARN([Google Test headers not found in default paths. Will rely on explicit -I flags in Makefile])
    HAVE_GTEST=no
])

AC_CHECK_HEADERS([gmock/gmock.h], [HAVE_GMOCK=yes], [
    AC_MSG_WARN([Google Mock headers not found, but continuing])
    HAVE_GMOCK=no
])

# Checks for typedefs, structures, and compiler characteristics
AC_TYPE_SIZE_T
AC_TYPE_OFF_T
AC_C_INLINE
AC_TYPE_UINT64_T

# Checks for library functions
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strdup strerror strncpy strcpy strcmp atoi fopen fclose fgets fprintf fscanf])

# Enable code coverage support
AC_ARG_ENABLE([coverage],
    [AS_HELP_STRING([--enable-coverage], [Enable code coverage analysis])],
    [enable_coverage=$enableval],
    [enable_coverage=yes])

if test "x$enable_coverage" = "xyes"; then
    AC_MSG_NOTICE([Code coverage enabled])
    CFLAGS="$CFLAGS -fprofile-arcs -ftest-coverage -O0 -g"
    CXXFLAGS="$CXXFLAGS -fprofile-arcs -ftest-coverage -O0 -g"
    LDFLAGS="$LDFLAGS -lgcov -fprofile-arcs"
    
    # Check for lcov
    AC_PATH_PROG([LCOV], [lcov])
    if test -z "$LCOV"; then
        AC_MSG_WARN([lcov not found - coverage reports will not be available])
    fi
    
    # Check for genhtml
    AC_PATH_PROG([GENHTML], [genhtml])
    if test -z "$GENHTML"; then
        AC_MSG_WARN([genhtml not found - HTML coverage reports will not be available])
    fi
fi

# Enable extra compiler warnings
AC_ARG_ENABLE([warnings],
    [AS_HELP_STRING([--enable-warnings], [Enable extra compiler warnings])],
    [enable_warnings=$enableval],
    [enable_warnings=yes])

if test "x$enable_warnings" = "xyes"; then
    CFLAGS="$CFLAGS -Wall -Wextra"
    CXXFLAGS="$CXXFLAGS -Wall -Wextra"
fi

# Optional: Enable valgrind support for memory leak detection
AC_ARG_ENABLE([valgrind],
    [AS_HELP_STRING([--enable-valgrind], [Enable Valgrind memory checks])],
    [enable_valgrind=$enableval],
    [enable_valgrind=no])

if test "x$enable_valgrind" = "xyes"; then
    AC_PATH_PROG([VALGRIND], [valgrind])
    if test -z "$VALGRIND"; then
        AC_MSG_ERROR([Valgrind requested but not found])
    fi
fi

AM_CONDITIONAL([ENABLE_VALGRIND], [test "x$enable_valgrind" = "xyes"])

# Output configuration summary
AC_MSG_NOTICE([
========================================
Configuration Summary:
========================================
  Package:              $PACKAGE_NAME
  Version:              $PACKAGE_VERSION
  Compiler (C):         $CC
  Compiler (C++):       $CXX
  CFLAGS:               $CFLAGS
  CXXFLAGS:             $CXXFLAGS
  LDFLAGS:              $LDFLAGS
  Code Coverage:        $enable_coverage
  Extra Warnings:       $enable_warnings
  Valgrind Support:     $enable_valgrind
========================================
])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
