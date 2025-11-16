/**
 * @file lock_manager.h
 * @brief Process lock manager
 * SKELETON: Interface definition
 */
#ifndef LOCK_MANAGER_H
#define LOCK_MANAGER_H

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
void lock_release(int fd);

#endif
