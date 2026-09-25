/**
 * @file netconf-subsystem.c
 * @author Joachim Wiberg <troglobit@gmail.com>
 * @brief NETCONF subsystem for sshd, bridges stdio to a UNIX socket endpoint
 *
 * Lets an SSH daemon own the SSH transport for a libnetconf2 server that
 * listens on a UNIX socket, see nc_server_add_unix_endpt():
 *
 *     Subsystem netconf /usr/libexec/libnetconf2/netconf-subsystem
 *
 * sshd has already authenticated the user and runs us as that user.  The
 * server learns who we are from the socket peer credentials, so this is a
 * plain byte pump that neither frames nor parses NETCONF.
 *
 * @copyright
 * Copyright (c) 2026 Joachim Wiberg
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "nc_client.h"

#ifndef NC_SUBSYSTEM_SOCKET
# define NC_SUBSYSTEM_SOCKET "/run/netconf.sock"
#endif

static int
write_all(int fd, const char *buf, size_t len)
{
    ssize_t n;

    while (len) {
        n = write(fd, buf, len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        buf += n;
        len -= n;
    }

    return 0;
}

/**
 * @brief Move whatever is readable on @p from to @p to.
 *
 * @return 1 while the direction is alive, 0 on EOF or error.
 */
static int
forward(int from, int to)
{
    char buf[65536];
    ssize_t n;

    n = read(from, buf, sizeof buf);
    if ((n < 0) && (errno == EINTR)) {
        return 1;
    }
    if (n <= 0) {
        return 0;
    }

    return !write_all(to, buf, n);
}

static void
usage(FILE *fp, const char *prog)
{
    fprintf(fp, "Usage: %s [-h] [-s PATH]\n"
            "\n"
            "  -h       This help text\n"
            "  -s PATH  UNIX socket of the NETCONF server, default %s\n",
            prog, NC_SUBSYSTEM_SOCKET);
}

int
main(int argc, char *argv[])
{
    const char *path = NC_SUBSYSTEM_SOCKET;
    struct pollfd pfd[2];
    int c, sock, flags;

    while ((c = getopt(argc, argv, "hs:")) != -1) {
        switch (c) {
        case 'h':
            usage(stdout, argv[0]);
            return 0;
        case 's':
            path = optarg;
            break;
        default:
            usage(stderr, argv[0]);
            return 1;
        }
    }

    /* a vanished peer is reported by write() instead */
    signal(SIGPIPE, SIG_IGN);

    /* connect and announce our own username, libnetconf2 logs any failure */
    sock = nc_proxy_unix_connect(path, NULL);
    if (sock < 0) {
        return 1;
    }

    /* the proxy leaves the socket non-blocking, we want plain blocking writes */
    flags = fcntl(sock, F_GETFL);
    if ((flags < 0) || (fcntl(sock, F_SETFL, flags & ~O_NONBLOCK) < 0)) {
        fprintf(stderr, "%s: fcntl failed (%s)\n", argv[0], strerror(errno));
        return 1;
    }

    pfd[0].fd = STDIN_FILENO;
    pfd[0].events = POLLIN;
    pfd[1].fd = sock;
    pfd[1].events = POLLIN;

    while (1) {
        if (poll(pfd, 2, -1) < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        /* client to server, on EOF tell the server we are done but keep draining its replies */
        if (pfd[0].revents && !forward(STDIN_FILENO, sock)) {
            shutdown(sock, SHUT_WR);
            pfd[0].fd = -1;
        }

        /* server to client, EOF here ends the session */
        if (pfd[1].revents && !forward(sock, STDOUT_FILENO)) {
            break;
        }
    }

    nc_proxy_unix_close(sock);
    return 0;
}
