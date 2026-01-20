#!/bin/bash

# Build script for crashupload binary

WORKDIR=$(pwd)
export ROOT=/usr
export INSTALL_DIR=${ROOT}/local

echo "========================================"
echo "Build Script for crashupload"
echo "========================================"
echo "Working Directory: $WORKDIR"
echo "Install Directory: $INSTALL_DIR"
echo ""

# Create installation directory
mkdir -p "$INSTALL_DIR"

# Change to c_sourcecode directory
cd c_sourcecode

# Generate configure script
echo "[1/3] Running autoreconf to generate build files..."
autoreconf -i

# Configure build
echo "[2/3] Configuring build..."
./configure \
    --enable-rdkcertselector \
    --prefix="${INSTALL_DIR}" \
    CFLAGS="-DRDK_LOGGER -I/usr/local/include -include rdkcertselector.h -Wall -Werror -O2" \
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
