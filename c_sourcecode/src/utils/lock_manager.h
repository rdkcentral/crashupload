/**
 * @file lock_manager.h
 * @brief Process lock manager
 * SKELETON: Interface definition
 */
#ifndef LOCK_MANAGER_H
#define LOCK_MANAGER_H

#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * @brief Acquire process lock
 * @param lock_file Path to lock file
 * @param timeout_sec Timeout in seconds
 * @return File descriptor on success, -1 on failure
 */
int lock_acquire(const char *lock_file, int timeout_sec);

/**
 * @brief Release process lock
 * @param fd File descriptor from lock_acquire
 */
void lock_release(int fd, const char *file);

#endif
