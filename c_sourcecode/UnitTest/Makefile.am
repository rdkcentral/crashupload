check_PROGRAMS = \
test_network_utils \
test_file_utils \
test_system_utils

TESTS = $(check_PROGRAMS)

# Common flags for all tests
AM_CPPFLAGS = -I$(top_srcdir)/../include
AM_LDFLAGS = -lgtest -lgtest_main -lpthread -lcrypto

# Network utils tests
test_network_utils_SOURCES = \
src/test_network_utils.cpp \
../src/utils/network_utils.c

# File utils tests
test_file_utils_SOURCES = \
src/test_file_utils.cpp \
../src/utils/file_utils.c

# System utils tests
test_system_utils_SOURCES = \
src/test_system_utils.cpp \
../src/utils/system_utils.c
