# Makefile for crashupload C implementation
# Based on optimized architecture

CC = gcc
CFLAGS = -O2 -Wall -Werror -std=c11 -I.
LDFLAGS = -lcurl -lssl -lcrypto -lz

TARGET = crashupload

SRCS = main.c \
       init/system_init.c \
       config/config_manager.c \
       platform/platform.c \
       core/scanner.c \
       core/archive_smart.c \
       core/upload_typeaware.c \
       core/ratelimit_unified.c \
       utils/prerequisites.c \
       utils/privacy.c \
       utils/cleanup_batch.c \
       utils/lock_manager.c \
       utils/logger.c

OBJS = $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
$(CC) $(CFLAGS) -c $< -o $@

clean:
rm -f $(TARGET) $(OBJS)

install: $(TARGET)
install -m 0755 $(TARGET) /usr/bin/

.PHONY: help
help:
@echo "Crashupload C Implementation (Optimized Architecture)"
@echo "Targets:"
@echo "  all     - Build the crashupload binary (default)"
@echo "  clean   - Remove build artifacts"
@echo "  install - Install to /usr/bin"
@echo ""
@echo "Based on:"
@echo "  - docs/migration/hld/updateduploadDumps-hld.md"
@echo "  - docs/migration/lld/updateduploadDumps-lld.md"
@echo "  - docs/migration/diagrams/flowcharts/optimizeduploadDumps-flowcharts.md"
@echo "  - docs/migration/diagrams/sequence/updateuploadDumps-sequence.md"
