SUBDIRS = src

bin_PROGRAMS = crashupload

crashupload_SOURCES = \
src/main.c \
src/config/config.c \
src/platform/platform.c \
src/utils/network_utils.c \
src/utils/file_utils.c \
src/utils/system_utils.c \
src/scanner/scanner.c \
src/archive/archive.c \
src/upload/upload.c \
src/ratelimit/ratelimit.c

crashupload_CPPFLAGS = -I$(top_srcdir)/include
crashupload_LDADD = -lcrypto

EXTRA_DIST = include
