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

###############################################################################
# build_and_test.sh
# Quick build and test script for config_manager unit tests
###############################################################################

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "========================================="
echo "Config Manager Unit Test Build Script"
echo "========================================="
echo

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check prerequisites
echo "Checking prerequisites..."

check_command() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}ERROR: $1 is not installed${NC}"
        return 1
    else
        echo -e "${GREEN}✓${NC} $1 found"
        return 0
    fi
}

PREREQ_OK=true
check_command g++ || PREREQ_OK=false
check_command autoconf || PREREQ_OK=false
check_command automake || PREREQ_OK=false
check_command lcov || echo -e "${YELLOW}WARNING: lcov not found - coverage reports unavailable${NC}"

if [ "$PREREQ_OK" = false ]; then
    echo -e "${RED}Please install missing prerequisites${NC}"
    exit 1
fi

echo

# Clean previous build
echo "Cleaning previous build..."
make clean &> /dev/null || true
make coverage-clean &> /dev/null || true
rm -rf coverage_html coverage.info
rm -f config_manager_gtest
rm -f *.gcda *.gcno *.gcov
rm -rf autom4te.cache config.h config.h.in~ config.log config.status
rm -f Makefile Makefile.in aclocal.m4 compile depcomp install-sh missing
echo -e "${GREEN}✓${NC} Clean complete"
echo

# Generate autotools files
if [ ! -f "configure" ] || [ ! -f "install-sh" ] || [ ! -f "compile" ]; then
    echo "Generating autotools configuration..."
    autoreconf --install --force
    echo -e "${GREEN}✓${NC} Configuration generated"
    echo
fi

# Configure
echo "Configuring build..."
./configure --enable-coverage --enable-warnings
echo -e "${GREEN}✓${NC} Configuration complete"
echo

# Build
echo "Building tests..."
make
echo -e "${GREEN}✓${NC} Build complete"
echo

# Run tests
echo "Running tests..."
echo "========================================="
make check
TEST_RESULT=$?
echo "========================================="

if [ $TEST_RESULT -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi
echo

# Generate coverage
if command -v lcov &> /dev/null; then
    echo "Generating coverage report..."
    make coverage
    echo -e "${GREEN}✓${NC} Coverage report generated in coverage_html/index.html"
    echo
    
    # Display summary
    echo "Coverage Summary:"
    echo "========================================="
    lcov --list coverage.info --rc lcov_branch_coverage=1 | grep "c_sourcecode/src" || true
    echo "========================================="
    echo
    
    # Check if we can open the coverage report
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "Opening coverage report..."
        open coverage_html/index.html
    elif command -v xdg-open &> /dev/null; then
        echo "Opening coverage report..."
        xdg-open coverage_html/index.html
    else
        echo "Open coverage_html/index.html in your browser to view the report"
    fi
else
    echo -e "${YELLOW}Skipping coverage report (lcov not available)${NC}"
fi

echo
echo "========================================="
echo -e "${GREEN}Build and test completed successfully!${NC}"
echo "========================================="
