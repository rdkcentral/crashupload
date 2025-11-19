bin_PROGRAMS = crashupload

# Common include directories
AM_CPPFLAGS = -I$(top_srcdir)/common \
              -I$(top_srcdir)/src/init \
              -I$(top_srcdir)/src/config \
              -I$(top_srcdir)/src/platform \
              -I$(top_srcdir)/src/core \
              -I$(top_srcdir)/src/utils

# External library flags
AM_CFLAGS = $(LIBCURL_CFLAGS) $(OPENSSL_CFLAGS) $(ZLIB_CFLAGS)
AM_LDFLAGS = $(LIBCURL_LIBS) $(OPENSSL_LIBS) $(ZLIB_LIBS)

# Source files for crashupload
crashupload_SOURCES = \
    main.c \
    init/system_init.c \
    init/system_init.h \
    config/config_manager.c \
    config/config_manager.h \
    platform/platform.c \
    platform/platform.h \
    core/scanner.c \
    core/scanner.h \
    core/archive_smart.c \
    core/archive_smart.h \
    core/upload_typeaware.c \
    core/upload_typeaware.h \
    core/ratelimit_unified.c \
    core/ratelimit_unified.h \
    utils/prerequisites.c \
    utils/prerequisites.h \
    utils/privacy.c \
    utils/privacy.h \
    utils/cleanup_batch.c \
    utils/cleanup_batch.h \
    utils/lock_manager.c \
    utils/lock_manager.h \
    utils/logger.c \
    utils/logger.h

# Include common headers
crashupload_SOURCES += \
    $(top_srcdir)/common/types.h \
    $(top_srcdir)/common/constants.h \
    $(top_srcdir)/common/errors.h

# Clean up
CLEANFILES = *~
