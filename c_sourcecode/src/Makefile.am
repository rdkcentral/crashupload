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

bin_PROGRAMS = crashupload

# Common include directories
AM_CPPFLAGS = -I$(top_srcdir)/common \
              -I$(top_srcdir)/src/init \
              -I$(top_srcdir)/src/config \
              -I$(top_srcdir)/src/platform \
              -I$(top_srcdir)/include \
              -I$(top_srcdir)/src/utils \
              -I${top_srcdir}/src/t2Interface 

# External library flags
AM_CFLAGS = $(LIBCURL_CFLAGS) $(OPENSSL_CFLAGS) $(ZLIB_CFLAGS)
AM_LDFLAGS = $(LIBCURL_LIBS) $(OPENSSL_LIBS) $(ZLIB_LIBS) -L$(PKG_CONFIG_SYSROOT_DIR)/$(libdir)
AM_LDFLAGS += -lrdkloggers -ldwnlutil -lfwutils -lsecure_wrapper -lparsejson -lpthread -larchive -luploadutil -ltelemetry_msgsender -lt2utils

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
    utils/logger.h \
    t2Interface/telemetryinterface.c \
    t2Interface/telemetryinterface.h

crashupload_LDADD = -lrdkloggers -ldwnlutil -lfwutils -lsecure_wrapper -lparsejson -lpthread -lcrypto -larchive -luploadutil -ltelemetry_msgsender -lt2utils
crashupload_LDFLAGS = -L$(PKG_CONFIG_SYSROOT_DIR)/$(libdir) -lcrypto -larchive -luploadutil -ltelemetry_msgsender -lt2utils

# Include common headers
crashupload_SOURCES += \
    $(top_srcdir)/common/types.h \
    $(top_srcdir)/common/constants.h \
    $(top_srcdir)/common/errors.h

# Clean up
CLEANFILES = *~
