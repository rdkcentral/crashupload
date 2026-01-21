#!/bin/sh
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
# run_ut.sh
# Comprehensive unit test build and execution script for crashupload
# Run from crashupload root directory
#
# Usage:
#   ./run_ut.sh              - Full clean, build, test, and coverage
#   ./run_ut.sh --test       - Preserve autotools files for faster rebuilds
#   ./run_ut.sh --clean      - Deep clean only (no build/test)
###############################################################################

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory and root
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
UNITTEST_DIR="$SCRIPT_DIR/unittest"
SRC_DIR="$SCRIPT_DIR/c_sourcecode/src"

# Test binaries to run (space-separated list)
TEST_BINARIES="config_manager_gtest platform_gtest scanner_gtest archive_gtest utils_gtest upload_gtest mainapp_gtest"

# Test results tracking (using temp file instead of associative array)
TEST_RESULTS_FILE="/tmp/crashupload_test_results_$$.tmp"
ALL_TESTS_PASSED=true

# Command-line flags
CLEAN_ONLY=false
PRESERVE_AUTOTOOLS=false

# Parse command-line arguments
for arg in "$@"; do
    case $arg in
        --clean)
            CLEAN_ONLY=true
            ;;
        --test)
            PRESERVE_AUTOTOOLS=true
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  (none)      Full clean, build, test, and coverage (default)"
            echo "  --test      Preserve autotools generated files for faster rebuilds"
            echo "  --clean     Deep clean only (removes all build artifacts, no build/test)"
            echo "  --help, -h  Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0              # Full fresh build and test"
            echo "  $0 --test       # Quick rebuild (preserves configure, Makefile.in)"
            echo "  $0 --clean      # Clean all artifacts and exit"
            exit 0
            ;;
        *)
            printf "${RED}Error: Unknown option '$arg'${NC}\n"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

###############################################################################
# Function: print_header
# Description: Print a formatted header message
###############################################################################
print_header() {
    echo
    echo "========================================="
    echo "$1"
    echo "========================================="
    echo
}

###############################################################################
# Function: print_step
# Description: Print a step message
###############################################################################
print_step() {
    printf "${BLUE}==>${NC} %s\n" "$1"
}

###############################################################################
# Function: print_success
# Description: Print a success message
###############################################################################
print_success() {
    printf "${GREEN}✓${NC} %s\n" "$1"
}

###############################################################################
# Function: print_error
# Description: Print an error message
###############################################################################
print_error() {
    printf "${RED}✗${NC} %s\n" "$1"
}

###############################################################################
# Function: print_warning
# Description: Print a warning message
###############################################################################
print_warning() {
    printf "${YELLOW}⚠${NC} %s\n" "$1"
}

###############################################################################
# Function: check_prerequisites
# Description: Check if required tools are installed
###############################################################################
check_prerequisites() {
    print_header "Checking Prerequisites"
    
    prereq_ok=true
    
    # Required tools
    for tool in g++ autoconf automake make; do
        if command -v "$tool" >/dev/null 2>&1; then
            print_success "$tool found"
        else
            print_error "$tool is not installed"
            prereq_ok=false
        fi
    done
    
    # Optional tools
    if command -v lcov >/dev/null 2>&1; then
        print_success "lcov found (coverage reports enabled)"
    else
        print_warning "lcov not found - coverage reports will be unavailable"
    fi
    
    if [ "$prereq_ok" = "false" ]; then
        print_error "Please install missing prerequisites"
        exit 1
    fi
}

###############################################################################
# Function: clean_build
# Description: Deep clean of all build artifacts, coverage data, and intermediate files
###############################################################################
clean_build() {
    if [ "$CLEAN_ONLY" = "true" ]; then
        print_header "Deep Clean Mode (Clean Only)"
    else
        print_header "Deep Cleaning Build Artifacts"
    fi
    
    print_step "Cleaning unittest directory..."
    cd "$UNITTEST_DIR"
    
    # Run make clean targets if Makefile exists
    if [ -f Makefile ]; then
        make clean >/dev/null 2>&1 || true
        make coverage-clean >/dev/null 2>&1 || true
        make distclean >/dev/null 2>&1 || true
    fi
    
    # Remove all test binaries
    print_step "Removing test binaries..."
    for test_bin in $TEST_BINARIES; do
        rm -f "$test_bin" 2>/dev/null || true
        rm -f "${test_bin}.trs" 2>/dev/null || true
    done
    
    # Remove all coverage files from unittest directory
    print_step "Removing coverage files from unittest..."
    find . -type f -name "*.gcda" -delete 2>/dev/null || true
    find . -type f -name "*.gcno" -delete 2>/dev/null || true
    find . -type f -name "*.gcov" -delete 2>/dev/null || true
    rm -rf coverage_html 2>/dev/null || true
    rm -f coverage.info coverage.filtered.info 2>/dev/null || true
    
    # Remove object files and dependencies
    print_step "Removing object files and dependencies..."
    find . -type f -name "*.o" -delete 2>/dev/null || true
    find . -type f -name "*.obj" -delete 2>/dev/null || true
    find . -type f -name "*.lo" -delete 2>/dev/null || true
    find . -type f -name "*.la" -delete 2>/dev/null || true
    rm -rf .libs 2>/dev/null || true
    rm -rf .deps 2>/dev/null || true
    
    # Remove autotools cache and generated files
    print_step "Removing autotools cache and config files..."
    rm -rf autom4te.cache 2>/dev/null || true
    rm -f config.log config.status 2>/dev/null || true
    rm -f config.h config.h.in config.h.in~ 2>/dev/null || true
    rm -f stamp-h1 2>/dev/null || true
    rm -f test-suite.log 2>/dev/null || true
    rm -f *.log 2>/dev/null || true
    rm -f libtool 2>/dev/null || true
    
    # Conditionally remove autotools generated scripts
    if [ "$PRESERVE_AUTOTOOLS" = "false" ]; then
        print_step "Removing autotools generated scripts (full clean)..."
        rm -f configure 2>/dev/null || true
        rm -f Makefile.in 2>/dev/null || true
        rm -f Makefile 2>/dev/null || true
        rm -f aclocal.m4 2>/dev/null || true
        rm -f compile depcomp install-sh missing 2>/dev/null || true
        rm -f test-driver 2>/dev/null || true
        rm -f ar-lib 2>/dev/null || true
        rm -f config.sub config.guess 2>/dev/null || true
    else
        print_step "Preserving autotools generated scripts (--test mode)..."
        rm -f Makefile 2>/dev/null || true
        print_warning "Keeping: configure, Makefile.in, install-sh, compile, etc."
    fi
    
    # Remove test-generated dump files and archives
    print_step "Removing test-generated dump files..."
    find . -type f -name "*.dmp" -delete 2>/dev/null || true
    find . -type f -name "*.dmp.tgz" -delete 2>/dev/null || true
    find . -type f -name "*.dmp.tar.gz" -delete 2>/dev/null || true
    # Remove test dump directories if they exist
    rm -rf subdir.dmp 2>/dev/null || true
    
    # Remove backup and temp files
    print_step "Removing backup and temporary files..."
    find . -type f -name "*~" -delete 2>/dev/null || true
    find . -type f -name "*.swp" -delete 2>/dev/null || true
    find . -type f -name "*.swo" -delete 2>/dev/null || true
    find . -type f -name ".*.swp" -delete 2>/dev/null || true
    
    cd "$SCRIPT_DIR"
    
    # Clean coverage files from c_sourcecode directory
    print_step "Removing coverage files from c_sourcecode..."
    find "$SRC_DIR" -type f -name "*.gcda" -delete 2>/dev/null || true
    find "$SRC_DIR" -type f -name "*.gcno" -delete 2>/dev/null || true
    find "$SRC_DIR" -type f -name "*.gcov" -delete 2>/dev/null || true
    
    # Remove object files from c_sourcecode
    print_step "Removing object files from c_sourcecode..."
    find "$SRC_DIR" -type f -name "*.o" -delete 2>/dev/null || true
    find "$SRC_DIR" -type f -name "*.lo" -delete 2>/dev/null || true
    find "$SRC_DIR" -type d -name ".libs" -exec rm -rf {} + 2>/dev/null || true
    find "$SRC_DIR" -type d -name ".deps" -exec rm -rf {} + 2>/dev/null || true
    
    # Remove dirstamp files
    find "$SCRIPT_DIR" -type f -name ".dirstamp" -delete 2>/dev/null || true
    
    # Clean any test result temp files
    rm -f /tmp/crashupload_test_results_*.tmp 2>/dev/null || true
    
    print_success "Deep clean completed"
    echo
    
    # If --clean flag, exit after cleaning
    if [ "$CLEAN_ONLY" = "true" ]; then
        print_header "Clean Complete"
        printf "${GREEN}✓ All build artifacts removed${NC}\n"
        echo
        exit 0
    fi
    
    cd "$SCRIPT_DIR"
}

###############################################################################
# Function: configure_build
# Description: Configure the build system using autotools
###############################################################################
configure_build() {
    print_header "Configuring Build System"
    
    cd "$UNITTEST_DIR"
    
    # Check if configure script exists and autotools files are present
    if [ ! -f "configure" ] || [ ! -f "install-sh" ] || [ ! -f "compile" ]; then
        print_step "Generating autotools configuration files..."
        automake --add-missing 2>/dev/null || true
        autoreconf --install --force
        print_success "Autotools configuration generated"
    else
        print_step "Configuration files already exist"
    fi
    
    # Run configure
    print_step "Running configure script..."
    ./configure --enable-coverage --enable-warnings
    print_success "Configuration complete"
    
    cd "$SCRIPT_DIR"
}

###############################################################################
# Function: build_tests
# Description: Build all test binaries
###############################################################################
build_tests() {
    print_header "Building Test Binaries"
    
    cd "$UNITTEST_DIR"
    
    print_step "Compiling tests with coverage support..."
    # Use 'make check' or build check_PROGRAMS explicitly
    make check TESTS= || make all
    
    print_success "Build completed"
    
    # Verify binaries exist and have execute permissions
    echo
    print_step "Verifying test binaries and permissions:"
    binaries_found=0
    binaries_missing=0
    binaries_fixed=0
    
    for test_bin in $TEST_BINARIES; do
        if [ -f "$test_bin" ]; then
            # Get detailed file info for diagnostics
            perms=$(ls -l "$test_bin" | awk '{print $1}')
            
            # Check if binary is executable
            if [ ! -x "$test_bin" ]; then
                print_warning "$test_bin [$perms] - NOT EXECUTABLE, fixing..."
                chmod +x "$test_bin"
                binaries_fixed=$((binaries_fixed + 1))
                # Verify fix
                if [ -x "$test_bin" ]; then
                    perms=$(ls -l "$test_bin" | awk '{print $1}')
                    print_success "$test_bin [$perms] - permissions fixed"
                else
                    print_error "$test_bin - FAILED to fix permissions (possible filesystem issue)"
                fi
            else
                print_success "$test_bin [$perms]"
            fi
            binaries_found=$((binaries_found + 1))
        else
            print_warning "$test_bin not found"
            binaries_missing=$((binaries_missing + 1))
        fi
    done
    
    if [ $binaries_fixed -gt 0 ]; then
        echo
        print_warning "Fixed execute permissions on $binaries_fixed test binaries"
        print_warning "This may indicate a build system or filesystem issue"
    fi
    
    if [ $binaries_missing -gt 0 ]; then
        echo
        print_error "Failed to build $binaries_missing test binaries"
        print_error "Build may have failed. Check the output above for errors."
        cd "$SCRIPT_DIR"
        exit 1
    fi
    
    cd "$SCRIPT_DIR"
}

###############################################################################
# Function: run_single_test
# Description: Run a single test binary and capture result
# Parameters: $1 - test binary name
###############################################################################
run_single_test() {
    test_name="$1"
    test_path="$UNITTEST_DIR/$test_name"
    
    if [ ! -f "$test_path" ]; then
        print_warning "Test binary $test_name not found, skipping..."
        echo "$test_name:-1" >> "$TEST_RESULTS_FILE"
        return
    fi
    
    # Double-check execute permission before running
    if [ ! -x "$test_path" ]; then
        print_warning "Test binary $test_name is not executable, fixing..."
        chmod +x "$test_path"
    fi
    
    echo
    print_step "Running $test_name..."
    echo "========================================="
    
    cd "$UNITTEST_DIR"
    
    # Run test and capture exit code
    if ./"$test_name"; then
        exit_code=0
    else
        exit_code=$?
        # Check if exit code 126 (permission/execution issue)
        if [ $exit_code -eq 126 ]; then
            print_error "Exit code 126: Cannot execute $test_name"
            print_error "This usually means missing execute permission or shared library"
            # Try to provide more diagnostic info
            if command -v ldd >/dev/null 2>&1; then
                echo "Checking shared library dependencies:"
                ldd "$test_name" 2>&1 | head -10
            fi
        fi
    fi
    
    echo "========================================="
    
    # Store result in file
    echo "$test_name:$exit_code" >> "$TEST_RESULTS_FILE"
    
    if [ $exit_code -eq 0 ]; then
        print_success "$test_name passed (exit code: $exit_code)"
    else
        print_error "$test_name failed (exit code: $exit_code)"
        ALL_TESTS_PASSED=false
    fi
    
    cd "$SCRIPT_DIR"
}

###############################################################################
# Function: cleanup_test_artifacts
# Description: Clean up test-generated files after test execution
###############################################################################
cleanup_test_artifacts() {
    print_step "Cleaning up test-generated artifacts..."
    
    cd "$UNITTEST_DIR"
    
    # Remove dump files created by tests
    find . -maxdepth 1 -type f -name "*.dmp" -delete 2>/dev/null || true
    find . -maxdepth 1 -type f -name "*.dmp.tgz" -delete 2>/dev/null || true
    find . -maxdepth 1 -type f -name "*.dmp.tar.gz" -delete 2>/dev/null || true
    
    # Remove test directories with .dmp extension
    find . -maxdepth 1 -type d -name "*.dmp" -exec rm -rf {} + 2>/dev/null || true
    
    # Clean up any temporary test files in /tmp
    rm -f /tmp/test_dump*.dmp 2>/dev/null || true
    rm -f /tmp/test_dump*.dmp.tgz 2>/dev/null || true
    
    cd "$SCRIPT_DIR"
}

###############################################################################
# Function: run_all_tests
# Description: Run all test binaries
###############################################################################
run_all_tests() {
    print_header "Running Unit Tests"
    
    # Initialize results file
    rm -f "$TEST_RESULTS_FILE"
    touch "$TEST_RESULTS_FILE"
    
    for test_bin in $TEST_BINARIES; do
        run_single_test "$test_bin"
    done
    
    # Clean up test artifacts after all tests complete
    cleanup_test_artifacts
}

###############################################################################
# Function: print_test_summary
# Description: Print summary of all test results
###############################################################################
print_test_summary() {
    print_header "Test Results Summary"
    
    passed=0
    failed=0
    skipped=0
    total=0
    
    # Read results from file
    while IFS=: read -r test_name result; do
        total=$((total + 1))
        
        if [ "$result" -eq 0 ]; then
            printf "${GREEN}✓ PASS${NC} - %s\n" "$test_name"
            passed=$((passed + 1))
        elif [ "$result" -eq -1 ]; then
            printf "${YELLOW}⊘ SKIP${NC} - %s (binary not found)\n" "$test_name"
            skipped=$((skipped + 1))
            # Treat skipped tests as failures
            ALL_TESTS_PASSED=false
        else
            printf "${RED}✗ FAIL${NC} - %s (exit code: %s)\n" "$test_name" "$result"
            failed=$((failed + 1))
            ALL_TESTS_PASSED=false
        fi
    done < "$TEST_RESULTS_FILE"
    
    echo
    echo "Total: $total tests"
    printf "${GREEN}Passed: %d${NC}\n" "$passed"
    if [ $failed -gt 0 ]; then
        printf "${RED}Failed: %d${NC}\n" "$failed"
    fi
    if [ $skipped -gt 0 ]; then
        printf "${YELLOW}Skipped: %d${NC}\n" "$skipped"
    fi
    echo
    
    # Cleanup temp file
    rm -f "$TEST_RESULTS_FILE"
}

###############################################################################
# Function: generate_coverage
# Description: Generate coverage reports using lcov
###############################################################################
generate_coverage() {
    if ! command -v lcov >/dev/null 2>&1; then
        print_warning "Skipping coverage report (lcov not available)"
        return
    fi
    
    print_header "Generating Coverage Report"
    
    cd "$UNITTEST_DIR"
    
    print_step "Checking for coverage data files..."
    gcda_count=$(find ../c_sourcecode/src -name "*.gcda" 2>/dev/null | wc -l)
    gcno_count=$(find ../c_sourcecode/src -name "*.gcno" 2>/dev/null | wc -l)
    
    echo "Found $gcda_count .gcda files and $gcno_count .gcno files"
    
    if [ "$gcda_count" -eq 0 ]; then
        print_warning "No coverage data files found. Tests may not have generated coverage data."
        cd "$SCRIPT_DIR"
        return
    fi
    
    print_step "Capturing coverage data..."
    lcov --capture \
         --directory "$SRC_DIR" \
         --output-file coverage.info \
         --rc lcov_branch_coverage=1 2>/dev/null || \
    lcov --capture \
         --directory "$SRC_DIR" \
         --output-file coverage.info \
         --rc lcov_branch_coverage=1 \
         --ignore-errors gcov,source || true
    
    if [ -f coverage.info ]; then
        print_step "Filtering coverage data..."
        lcov --extract coverage.info '*/c_sourcecode/src/*.c' \
             --output-file coverage.filtered.info \
             --rc lcov_branch_coverage=1 --quiet 2>/dev/null || true
        
        lcov --remove coverage.filtered.info '/usr/*' \
             --output-file coverage.info \
             --rc lcov_branch_coverage=1 --quiet 2>/dev/null || true
        
        print_step "Generating HTML report..."
        genhtml coverage.info \
                --output-directory coverage_html \
                --branch-coverage \
                --quiet 2>/dev/null || \
        genhtml coverage.info \
                --output-directory coverage_html \
                --branch-coverage \
                --ignore-errors source \
                --quiet 2>/dev/null || true
        
        if [ -d coverage_html ]; then
            print_success "Coverage report generated: $UNITTEST_DIR/coverage_html/index.html"
            
            echo
            print_step "Coverage Summary:"
            echo "========================================="
            # Use lcov --summary for cleaner output
            lcov --summary coverage.info --rc lcov_branch_coverage=1 2>/dev/null || \
            lcov --list coverage.info --rc lcov_branch_coverage=1 2>/dev/null | head -20 || \
            echo "Coverage data available in HTML report"
            echo "========================================="
            echo
            
            # Try to open the coverage report
            if [ "$(uname)" = "Darwin" ]; then
                print_step "Opening coverage report in browser..."
                open coverage_html/index.html
            elif command -v xdg-open >/dev/null 2>&1; then
                print_step "Opening coverage report in browser..."
                xdg-open coverage_html/index.html
            else
                echo "To view the report, open: $UNITTEST_DIR/coverage_html/index.html"
            fi
        else
            print_warning "Failed to generate HTML coverage report"
        fi
    else
        print_warning "Failed to capture coverage data"
    fi
    
    cd "$SCRIPT_DIR"
}

###############################################################################
# Function: main
# Description: Main execution flow
###############################################################################
main() {
    print_header "Crashupload Unit Test Runner"
    echo "Script directory: $SCRIPT_DIR"
    echo "Unit test directory: $UNITTEST_DIR"
    echo "Source directory: $SRC_DIR"
    
    # Show mode
    if [ "$CLEAN_ONLY" = "true" ]; then
        echo "Mode: Clean only"
    elif [ "$PRESERVE_AUTOTOOLS" = "true" ]; then
        echo "Mode: Quick rebuild (preserving autotools files)"
    else
        echo "Mode: Full fresh build"
    fi
    echo
    
    # Execute build and test workflow
    check_prerequisites
    clean_build  # Will exit here if --clean flag is set
    configure_build
    build_tests
    run_all_tests
    print_test_summary
    
    # Generate coverage if tests passed
    if [ "$ALL_TESTS_PASSED" = "true" ]; then
        generate_coverage
        
        print_header "SUCCESS"
        printf "${GREEN}✓ All unit tests passed successfully!${NC}\n"
        printf "${GREEN}✓ Build and test completed${NC}\n"
        echo
        exit 0
    else
        print_header "FAILURE"
        printf "${RED}✗ Some unit tests failed${NC}\n"
        printf "${RED}✗ Please check the test results and fix the issues${NC}\n"
        echo
        exit 1
    fi
}

# Run main function
main
