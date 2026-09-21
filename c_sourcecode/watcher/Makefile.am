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

bin_PROGRAMS = inotify-minidump-watcher

# Match legacy crashupload/src/Makefile: link only secure_wrapper.
# Extra defines such as -DYOCTO_BUILD continue to come from the
# environment / configure CFLAGS (same as crashupload).
AM_LDFLAGS = -L$(PKG_CONFIG_SYSROOT_DIR)/$(libdir)

inotify_minidump_watcher_SOURCES = inotify-minidump-watcher.c
inotify_minidump_watcher_LDADD = -lsecure_wrapper

EXTRA_DIST = README.md

CLEANFILES = *~
