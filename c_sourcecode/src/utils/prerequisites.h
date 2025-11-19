/**
 * @file prerequisites.h
 * @brief Combined prerequisites checker
 * SKELETON: Interface definition
 */
#ifndef PREREQUISITES_H
#define PREREQUISITES_H

/**
 * @brief Wait for network and time sync
 * @param timeout_sec Timeout in seconds
 * @return ERR_SUCCESS when ready
 */
int prerequisites_wait(int timeout_sec);

#endif
