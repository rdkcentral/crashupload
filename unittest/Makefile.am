# Makefile.am for crashupload unit tests
# Autotools build configuration for GTest-based unit tests

AUTOMAKE_OPTIONS = foreign subdir-objects

# Test programs
TESTS = config_manager_gtest platform_gtest scanner_gtest
check_PROGRAMS = config_manager_gtest platform_gtest scanner_gtest

# Common include directories
AM_CPPFLAGS = \
	-I$(top_srcdir)/../c_sourcecode/src/config \
	-I$(top_srcdir)/../c_sourcecode/common \
	-I$(top_srcdir)/../c_sourcecode/include \
	-I$(top_srcdir)/../c_sourcecode/src/utils \
	-I$(top_srcdir)/../c_sourcecode/src/platform \
	-I$(top_srcdir)/../c_sourcecode/src/scanner \
	-I/usr/include \
	-I/usr/local/include

# Common compiler flags
AM_CXXFLAGS = \
	-g -O0 \
	-fprofile-arcs \
	-ftest-coverage \
	-Wall \
	-Wextra \
	-Werror \
	-std=c++11 \
	-fno-inline

AM_CFLAGS = \
	-g -O0 \
	-fprofile-arcs \
	-ftest-coverage \
	-Wall \
	-Wextra \
	-std=c99 \
	-fno-inline

# config_manager_gtest configuration
config_manager_gtest_SOURCES = \
	config_manager_gtest.cpp \
	config_manager_mock.cpp \
	../c_sourcecode/src/config/config_manager.c \
	../c_sourcecode/src/rfcInterface/rfcinterface.c

config_manager_gtest_LDADD = \
	-lgtest \
	-lgtest_main \
	-lgmock \
	-lgmock_main \
	-lpthread \
	-lgcov

config_manager_gtest_LDFLAGS = \
	-fprofile-arcs

# platform_gtest configuration
platform_gtest_SOURCES = \
	platform_gtest.cpp \
	platform_gmock.cpp \
	../c_sourcecode/src/platform/platform.c

platform_gtest_LDADD = \
	-lgtest \
	-lgtest_main \
	-lgmock \
	-lgmock_main \
	-lpthread \
	-lgcov

platform_gtest_LDFLAGS = \
	-fprofile-arcs

# scanner_gtest configuration
scanner_gtest_SOURCES = \
	scanner_gtest.cpp \
	scanner_gmock.cpp \
	../c_sourcecode/src/scanner/scanner.c

scanner_gtest_LDADD = \
	-lgtest \
	-lgtest_main \
	-lgmock \
	-lgmock_main \
	-lpthread \
	-lgcov

scanner_gtest_LDFLAGS = \
	-fprofile-arcs

# Coverage targets
.PHONY: coverage coverage-clean coverage-report

coverage-clean:
	@echo "Cleaning coverage data..."
	@find . -name "*.gcda" -delete
	@find . -name "*.gcno" -delete
	@find ../c_sourcecode/src/config -name "*.gcda" -delete 2>/dev/null || true
	@find ../c_sourcecode/src/config -name "*.gcno" -delete 2>/dev/null || true
	@rm -rf coverage_html coverage.info

coverage:
	@echo "Running tests with coverage..."
	@$(MAKE) check
	@echo ""
	@echo "Checking for coverage files..."
	@find ../ -name "*.gcno" -o -name "*.gcda" | sort
	@echo ""
	@echo "Generating coverage report..."
	@echo "Capturing coverage from source directory..."
	@lcov --capture --directory ../c_sourcecode/src/config --output-file coverage.info --rc lcov_branch_coverage=1 2>/dev/null || \
	 lcov --capture --directory ../c_sourcecode/src/config --output-file coverage.info --rc lcov_branch_coverage=1 --ignore-errors gcov,source || \
	 lcov --capture --directory ../c_sourcecode/src/config --output-file coverage.info --rc lcov_branch_coverage=1
	@echo "Filtering coverage data..."
	@lcov --extract coverage.info '*/config_manager.c' --output-file coverage.info --rc lcov_branch_coverage=1
	@lcov --remove coverage.info '/usr/*' --output-file coverage.info --rc lcov_branch_coverage=1
	@echo "Generating HTML report..."
	@genhtml coverage.info --output-directory coverage_html --branch-coverage 2>/dev/null || \
	 genhtml coverage.info --output-directory coverage_html --branch-coverage --ignore-errors source
	@echo ""
	@echo "========================================="
	@echo "Coverage report generated successfully!"
	@echo "========================================="
	@echo "Open: coverage_html/index.html"
	@echo ""

coverage-report:
	@echo "Coverage Summary for config_manager.c:"
	@echo "========================================="
	@lcov --list coverage.info --rc lcov_branch_coverage=1 | grep -E "(Lines|Functions|Branches|config_manager)" || echo "No coverage data available"
	@echo "========================================="

# Clean targets
CLEANFILES = \
	*.gcda \
	*.gcno \
	*.gcov \
	coverage.info

clean-local:
	@rm -rf coverage_html

# Additional make targets
.PHONY: check-valgrind

check-valgrind: $(check_PROGRAMS)
	@echo "Running tests with Valgrind..."
	@for test in $(TESTS); do \
		echo "Testing $$test..."; \
		valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --error-exitcode=1 ./$$test; \
	done
