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

# Build script for crashupload binary
#
# Usage:
#   ./cov_build.sh         - Build crashupload binary
#   ./cov_build.sh --clean - Clean all build artifacts and exit

WORKDIR=$(pwd)
export ROOT=/usr
export INSTALL_DIR=${ROOT}/local

# Command-line flags
CLEAN_ONLY=false
L2_TEST_MODE=false

# Parse command-line arguments
for arg in "$@"; do
    case $arg in
        --clean)
            CLEAN_ONLY=true
            ;;
        --l2-test)
            L2_TEST_MODE=true
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  (none)      Build crashupload binary (default)"
            echo "  --clean     Clean all build artifacts from c_sourcecode and exit"
            echo "  --l2-test   Build with -DL2_TEST (reads uptime from /opt/uptime instead of /proc/uptime)"
            echo "  --help, -h  Show this help message"
            echo ""
            exit 0
            ;;
        *)
            echo "Error: Unknown option '$arg'"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Function to clean build artifacts
clean_build_artifacts() {
    echo "========================================"
    echo "Cleaning Build Artifacts (c_sourcecode)"
    echo "========================================"
    echo ""
    
    cd c_sourcecode
    
    echo "[1/5] Running make clean..."
    if [ -f Makefile ]; then
        make clean >/dev/null 2>&1 || true
        make distclean >/dev/null 2>&1 || true
    fi
    
    echo "[2/5] Removing object files and libraries..."
    find . -type f -name "*.o" -delete 2>/dev/null || true
    find . -type f -name "*.lo" -delete 2>/dev/null || true
    find . -type f -name "*.la" -delete 2>/dev/null || true
    find . -type f -name "*.a" -delete 2>/dev/null || true
    find . -type d -name ".libs" -exec rm -rf {} + 2>/dev/null || true
    find . -type d -name ".deps" -exec rm -rf {} + 2>/dev/null || true
    
    echo "[3/5] Removing autotools generated files..."
    rm -rf autom4te.cache 2>/dev/null || true
    rm -f config.log config.status 2>/dev/null || true
    rm -f config.h config.h.in config.h.in~ 2>/dev/null || true
    rm -f stamp-h1 2>/dev/null || true
    rm -f libtool 2>/dev/null || true
    rm -f configure 2>/dev/null || true
    rm -f Makefile.in Makefile src/Makefile.in 2>/dev/null || true
    rm -f aclocal.m4 2>/dev/null || true
    rm -f compile depcomp install-sh missing 2>/dev/null || true
    rm -f config.sub config.guess 2>/dev/null || true
    rm -f ar-lib test-driver 2>/dev/null || true
    
    echo "[4/5] Removing coverage files..."
    find . -type f -name "*.gcda" -delete 2>/dev/null || true
    find . -type f -name "*.gcno" -delete 2>/dev/null || true
    find . -type f -name "*.gcov" -delete 2>/dev/null || true
    
    echo "[5/5] Removing backup and temporary files..."
    find . -type f -name "*~" -delete 2>/dev/null || true
    find . -type f -name "*.swp" -delete 2>/dev/null || true
    find . -type f -name ".*.swp" -delete 2>/dev/null || true
    find . -type f -name ".dirstamp" -delete 2>/dev/null || true
    
    cd ..
    
    echo ""
    echo "========================================"
    echo "Clean completed successfully!"
    echo "========================================"
    exit 0
}

# If --clean flag is set, clean and exit
if [ "$CLEAN_ONLY" = true ]; then
    clean_build_artifacts
fi

echo "========================================"
echo "Build Script for crashupload"
echo "========================================"
echo "Working Directory: $WORKDIR"
echo "Install Directory: $INSTALL_DIR"
echo ""

# Create installation directory
mkdir -p "$INSTALL_DIR"

# Clone and build common_utilities
# echo "========================================"
# echo "Building common_utilities dependency"
# echo "========================================"
# cd ${ROOT}
# #git clone https://github.com/rdkcentral/common_utilities.git -b feature/upload_L2
# git clone https://github.com/rdkcentral/common_utilities.git
# cd common_utilities
# sh cov_build.sh
# echo ""

# Return to working directory and change to c_sourcecode directory
cd "$WORKDIR"
cd c_sourcecode

# Generate configure script
echo "[1/3] Running autoreconf to generate build files..."
autoreconf -i

# Configure build
echo "[2/3] Configuring build..."
BASE_CFLAGS="-DRDK_LOGGER -I/usr/local/include -include rdkcertselector.h -Wall -Werror -O2"
if [ "$L2_TEST_MODE" = true ]; then
    echo "L2 TEST MODE: Building with -DL2_TEST flag (will use /opt/uptime instead of /proc/uptime)"
    BASE_CFLAGS="$BASE_CFLAGS -DL2_TEST"
fi
./configure \
    --enable-rdkcertselector \
    --prefix="${INSTALL_DIR}" \
    CFLAGS="$BASE_CFLAGS" \
    LDFLAGS="-L/usr/local/lib" \
    PKG_CONFIG_PATH="/usr/local/lib/pkgconfig"

# Post-configure: Remove T2_EVENT_ENABLED from generated Makefiles
# This avoids dependency on telemetry_busmessage_sender.h which isn't available
echo "Removing T2_EVENT_ENABLED and telemetry libraries from generated Makefiles..."
sed -i 's/-DT2_EVENT_ENABLED//g' Makefile src/Makefile
sed -i 's/-ltelemetry_msgsender//g' Makefile src/Makefile
sed -i 's/-lt2utils//g' Makefile src/Makefile

# Build and install the binary
echo "[3/3] Building and installing crashupload binary..."
if make && make install; then
    echo ""
    echo "========================================"
    echo "Build completed successfully!"
    echo "========================================"
    echo "Binary installed to: ${INSTALL_DIR}/bin/crashupload"
    echo "========================================"
else
    echo ""
    echo "========================================"
    echo "Build failed!"
    echo "========================================"
    exit 1
fi
