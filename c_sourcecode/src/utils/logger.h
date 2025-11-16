/**
 * @file logger.h
 * @brief Logging utility
 * SKELETON: Interface definition
 */
#ifndef LOGGER_H
#define LOGGER_H

/**
 * @brief Log error message
 */
void logger_error(const char *fmt, ...);

/**
 * @brief Log warning message
 */
void logger_warn(const char *fmt, ...);

/**
 * @brief Log info message
 */
void logger_info(const char *fmt, ...);

#endif
