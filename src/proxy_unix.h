/**
 * @file proxy_unix.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libnetconf2 UNIX proxy header
 *
 * @copyright
 * Copyright (c) 2025 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NC_PROXY_UNIX_H_
#define NC_PROXY_UNIX_H_

#include <stdint.h>

#include "session.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup proxy_unix UNIX Proxy
 *
 * @brief UNIX proxy communication.
 * @{
 */

/**
 * @brief Connect to a server UNIX socket to act as a NETCONF proxy.
 *
 * @param[in] address UNIX socket path to connect to.
 * @param[in] username NETCONF username to use for UNIX authentication.
 * @return Connected non-blocking file descriptor.
 * @return -1 on error.
 */
int nc_proxy_unix_connect(const char *address, const char *username);

/**
 * @brief Read a full chunked-framing message from a FD.
 *
 * @param[in] fd File descriptor to read from.
 * @param[in] version NETCONF version to use for message encapsulation.
 * @param[in] timeout_ms Timeout for reading in milliseconds. Use negative value for blocking read, 0 for non-blocking read.
 * @param[in,out] buf Buffer to write into, is enlarged as needed.
 * @param[in,out] buf_len Length of @p buf.
 * @return Number of message characters read (not counting metadata).
 * @return 0 if no data were read before the timeout elapsed.
 * @return -1 on error.
 */
int nc_proxy_read_msg(int fd, NC_PROT_VERSION version, int timeout_ms, char **buf, uint32_t *buf_len);

/**
 * @brief Write data encapsulated as a chunked-framing message to a FD.
 *
 * Keeps writing until all the data are written or a fatal error is encountered.
 *
 * @param[in] fd File descriptor to write to.
 * @param[in] version NETCONF version to use for message encapsulation.
 * @param[in] buf Buffer with the message to write.
 * @param[in] buf_len Length of the message in @p buf.
 * @return Number of message characters written (not counting metadata).
 * @return 0 if no data were written before the timeout elapsed.
 * @return -1 on error.
 */
int nc_proxy_write_msg(int fd, NC_PROT_VERSION version, const char *buf, uint32_t buf_len);

/**
 * @brief Close the UNIX proxy connection to a server.
 *
 * @param[in] fd Connected UNIX socket file descriptor.
 * @return 0 on success.
 * @return -1 on error.
 */
int nc_proxy_unix_close(int fd);

/** @} UNIX Proxy */

#ifdef __cplusplus
}
#endif

#endif /* NC_PROXY_UNIX_H_ */
