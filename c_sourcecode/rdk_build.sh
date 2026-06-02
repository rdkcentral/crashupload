#!/bin/bash
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

#######################################
#
# Build Framework standard script for
#
# crashupload C binary component

# use -e to fail on any shell issue
# -e is the requirement from Build Framework
set -ex

# default PATHs - use `man readlink` for more info
# the path to combined build
export RDK_PROJECT_ROOT_PATH="${RDK_PROJECT_ROOT_PATH-$(readlink -m ..)}"
export COMBINED_ROOT="$RDK_PROJECT_ROOT_PATH"

# path to build script (this script)
export RDK_SCRIPTS_PATH="${RDK_SCRIPTS_PATH-$(readlink -m "$0" | xargs dirname)}"

# path to components sources and target
export RDK_SOURCE_PATH="${RDK_SOURCE_PATH-$RDK_SCRIPTS_PATH}"
export RDK_TARGET_PATH="${RDK_TARGET_PATH-$RDK_SOURCE_PATH}"

# fsroot and toolchain (valid for all devices)
export RDK_FSROOT_PATH="${RDK_FSROOT_PATH-$(readlink -m "$RDK_PROJECT_ROOT_PATH/sdk/fsroot/ramdisk")}"
export RDK_TOOLCHAIN_PATH="${RDK_TOOLCHAIN_PATH-$(readlink -m "$RDK_PROJECT_ROOT_PATH/sdk/toolchain/arm-linux-gnueabihf")}"

# default component name
export RDK_COMPONENT_NAME="${RDK_COMPONENT_NAME-$(basename "$RDK_SOURCE_PATH")}"

# Setup cross-compilation toolchain
if [ -f ${RDK_PROJECT_ROOT_PATH}/build/components/amba/sdk/setenv2 ]; then
    source ${RDK_PROJECT_ROOT_PATH}/build/components/amba/sdk/setenv2
else
    export CC=${RDK_TOOLCHAIN_PATH}/bin/arm-linux-gnueabihf-gcc
    export CXX=${RDK_TOOLCHAIN_PATH}/bin/arm-linux-gnueabihf-g++
    export AR=${RDK_TOOLCHAIN_PATH}/bin/arm-linux-gnueabihf-ar
    export LD=${RDK_TOOLCHAIN_PATH}/bin/arm-linux-gnueabihf-ld
    export NM=${RDK_TOOLCHAIN_PATH}/bin/arm-linux-gnueabihf-nm
    export RANLIB=${RDK_TOOLCHAIN_PATH}/bin/arm-linux-gnueabihf-ranlib
    export STRIP=${RDK_TOOLCHAIN_PATH}/bin/arm-linux-gnueabihf-strip
    export LINK=${RDK_TOOLCHAIN_PATH}/bin/arm-linux-gnueabihf-g++
fi

# parse arguments
INITIAL_ARGS=$@

function usage()
{
    set +x
    echo "Usage: $(basename "$0") [-h|--help] [-v|--verbose] [action]"
    echo "    -h    --help                  : this help"
    echo "    -v    --verbose               : verbose output"
    echo
    echo "Supported actions:"
    echo "      configure, clean, build (DEFAULT), rebuild, install"
}

# options may be followed by one colon to indicate they have a required argument
if ! GETOPT=$(getopt -n "build.sh" -o hv -l help,verbose -- "$@")
then
    usage
    exit 1
fi

eval set -- "$GETOPT"

while true; do
  case "$1" in
    -h | --help ) usage; exit 0 ;;
    -v | --verbose ) set -x ;;
    -- ) shift; break;;
    * ) break;;
  esac
  shift
done

ARGS=$@

# functional modules
function configure()
{
    pd=$(pwd)
    cd ${RDK_SOURCE_PATH}

    aclocal
    libtoolize --automake
    autoheader
    automake --foreign --add-missing
    rm -f configure
    autoconf

    configure_options="--host=arm-linux --target=arm-linux"

    export CFLAGS="${CFLAGS} -I${RDK_FSROOT_PATH}/usr/include \
        -I${RDK_FSROOT_PATH}/usr/include/rbus \
        -I${RDK_FSROOT_PATH}/usr/include/rfc \
        -I${RDK_PROJECT_ROOT_PATH}/common_utilities/dwnlutils \
        -I${RDK_PROJECT_ROOT_PATH}/common_utilities/parsejson \
        -I${RDK_PROJECT_ROOT_PATH}/common_utilities/utils"

    export LDFLAGS="${LDFLAGS} -L${RDK_FSROOT_PATH}/usr/lib \
        -Wl,-rpath-link,${RDK_FSROOT_PATH}/usr/lib \
        -lrdkloggers -ldwnlutil -lfwutils -lsecure_wrapper -lparsejson \
        -lpthread -lcrypto -larchive -lrfcapi -ltelemetry_msgsender \
        -lt2utils -lrbus -lcurl"

    ./configure --prefix=${RDK_FSROOT_PATH}/usr --sysconfdir=${RDK_FSROOT_PATH}/etc $configure_options

    cd $pd
}

function clean()
{
    pd=$(pwd)
    cd ${RDK_SOURCE_PATH}
    if [ -f Makefile ]; then
        make distclean-am
        make clean
    fi
    rm -f configure
    rm -rf aclocal.m4 autom4te.cache config.log config.status libtool
    find . -iname "Makefile.in" -exec rm -f {} \;
    find . -iname "Makefile" | xargs rm -f
    cd $pd
}

function build()
{
    cd ${RDK_SOURCE_PATH}
    make
}

function rebuild()
{
    clean
    configure
    build
}

function install()
{
    cd ${RDK_SOURCE_PATH}

    # Install the crashupload binary
    mkdir -p $RDK_FSROOT_PATH/usr/bin
    install -m 0755 src/crashupload $RDK_FSROOT_PATH/usr/bin/crashupload

    # Install the shell script as fallback
    mkdir -p $RDK_FSROOT_PATH/lib/rdk
    if [ -f ${RDK_SOURCE_PATH}/../uploadDumps.sh ]; then
        install -m 0755 ${RDK_SOURCE_PATH}/../uploadDumps.sh $RDK_FSROOT_PATH/lib/rdk/uploadDumps.sh
    fi

    # Install RFC defaults
    CPC_PATH=${CPC_PATH-$RDK_PROJECT_ROOT_PATH/cpg-utils}
    if [ -f "$CPC_PATH/rfcdefaults/crashupload.ini" ]; then
        mkdir -p $RDK_FSROOT_PATH/etc/rfcdefaults
        install -m 0644 $CPC_PATH/rfcdefaults/crashupload.ini $RDK_FSROOT_PATH/etc/rfcdefaults/crashupload.ini
    fi
}

# run the logic
HIT=false

for i in "$ARGS"; do
    case $i in
        configure)  HIT=true; configure ;;
        clean)      HIT=true; clean ;;
        build)      HIT=true; build ;;
        rebuild)    HIT=true; rebuild ;;
        install)    HIT=true; install ;;
        *)
            #skip unknown
        ;;
    esac
done

# Default action - build
if ! $HIT; then
  build
fi
