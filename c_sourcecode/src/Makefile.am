bin_PROGRAMS = crashupload

# Common include directories
AM_CPPFLAGS = -I$(top_srcdir)/common \
              -I$(top_srcdir)/src/init \
              -I$(top_srcdir)/src/config \
              -I$(top_srcdir)/src/platform \
              -I$(top_srcdir)/include \
              -I$(top_srcdir)/src/utils

# External library flags
AM_CFLAGS = $(LIBCURL_CFLAGS) $(OPENSSL_CFLAGS) $(ZLIB_CFLAGS)
AM_LDFLAGS = $(LIBCURL_LIBS) $(OPENSSL_LIBS) $(ZLIB_LIBS) -L$(PKG_CONFIG_SYSROOT_DIR)/$(libdir)
AM_LDFLAGS += -lrdkloggers -ldwnlutil -lfwutils -lsecure_wrapper -lparsejson -lpthread -larchive -luploadutil

# Source files for crashupload
crashupload_SOURCES = \
    main.c \
    init/system_init.c \
    init/system_init.h \
    config/config_manager.c \
    config/config_manager.h \
    platform/platform.c \
    platform/platform.h \
    utils/file_utils.c \
    utils/prerequisites.c \
    utils/prerequisites.h \
    utils/lock_manager.c \
    utils/lock_manager.h \
    utils/cleanup_batch.c \
    utils/cleanup_batch.h \
    scanner/scanner.c \
    archive/archive.c \
    archive/archive_crash.h \
    ratelimit/ratelimit.c \
    utils/system_utils.c \
    upload/upload.c \
    rfcInterface/rfcinterface.c \
    rfcInterface/rfcinterface.h \
    utils/logger.c \
    utils/logger.h

crashupload_LDADD = -lrdkloggers -ldwnlutil -lfwutils -lsecure_wrapper -lparsejson -lpthread -lcrypto -larchive -luploadutil
crashupload_LDFLAGS = -L$(PKG_CONFIG_SYSROOT_DIR)/$(libdir) -lcrypto -larchive -luploadutil

# Include common headers
crashupload_SOURCES += \
    $(top_srcdir)/common/types.h \
    $(top_srcdir)/common/constants.h \
    $(top_srcdir)/common/errors.h

# Clean up
CLEANFILES = *~
