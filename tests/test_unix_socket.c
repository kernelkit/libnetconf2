/**
 * @file test_unix_socket.c
 * @author Roman Janota <janota@cesnet.cz>
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libnetconf2 UNIX socket test
 *
 * @copyright
 * Copyright (c) 2022 - 2025 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "ln2_test.h"
#include "nc_client.h"

static int
setup_f(void **state)
{
    int ret;
    struct ln2_test_ctx *test_ctx;
    struct lyd_node *config = NULL;

    ret = ln2_glob_test_setup(&test_ctx);
    assert_int_equal(ret, 0);

    *state = test_ctx;

    /* create the UNIX socket */
    ret = nc_server_config_add_unix_socket(test_ctx->ctx,
            "unix", "/tmp/nc2_test_unix_sock", NULL, NULL, NULL, &config);
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup_data(config);
    assert_int_equal(ret, 0);

    lyd_free_all(config);

    return 0;
}

/* TEST */
static void *
connect_client_thread(void *arg)
{
    int ret = 0;
    struct nc_session *session = NULL;
    struct ln2_test_ctx *test_ctx = arg;

    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    pthread_barrier_wait(&test_ctx->barrier);
    session = nc_connect_unix("/tmp/nc2_test_unix_sock", NULL);
    assert_non_null(session);

    nc_session_free(session, NULL);
    return NULL;
}

static void
test_connect(void **state)
{
    int ret, i;
    pthread_t tids[2];

    assert_non_null(state);

    ret = pthread_create(&tids[0], NULL, connect_client_thread, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

/* TEST */
static void *
invalid_user_client_thread(void *arg)
{
    int ret = 0;
    struct nc_session *session = NULL;
    struct ln2_test_ctx *test_ctx = arg;

    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    /* set an invalid username */
    nc_client_unix_set_username("INVALID");

    pthread_barrier_wait(&test_ctx->barrier);

    /* session fails to be created */
    session = nc_connect_unix("/tmp/nc2_test_unix_sock", NULL);
    assert_null(session);

    return NULL;
}

static void *
invalid_user_server_thread(void *arg)
{
    NC_MSG_TYPE msgtype;
    struct nc_session *session = NULL;
    struct ln2_test_ctx *test_ctx = arg;

    /* wait for the client to be ready to connect */
    pthread_barrier_wait(&test_ctx->barrier);

    /* session of an invalid user is not accepted */
    msgtype = nc_accept(NC_ACCEPT_TIMEOUT, test_ctx->ctx, &session);
    assert_int_equal(msgtype, NC_MSG_ERROR);

    return NULL;
}

static void
test_invalid_user(void **state)
{
    int ret, i;
    pthread_t tids[2];

    assert_non_null(state);

    ret = pthread_create(&tids[0], NULL, invalid_user_client_thread, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, invalid_user_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

/* TEST */
static void *
proxy_client_thread(void *arg)
{
    int ret, fd;
    const char *msg;
    char *buf = NULL;
    uint32_t buf_len = 0;
    struct ln2_test_ctx *test_ctx = arg;

    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    /* wait before connecting */
    pthread_barrier_wait(&test_ctx->barrier);

    /* connect the proxy */
    fd = nc_proxy_unix_connect("/tmp/nc2_test_unix_sock", NULL);
    assert_int_not_equal(fd, 0);

    /* send the hello message */
    msg = "<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
            "<capabilities>"
            "<capability>urn:ietf:params:netconf:base:1.0</capability>"
            "<capability>urn:ietf:params:netconf:base:1.1</capability>"
            "</capabilities>"
            "</hello>";
    ret = nc_proxy_write_msg(fd, NC_PROT_VERSION_10, msg, strlen(msg));
    assert_int_equal(ret, strlen(msg));

    /* read the hello message */
    ret = nc_proxy_read_msg(fd, NC_PROT_VERSION_10, -1, &buf, &buf_len);
    assert_int_not_equal(ret, -1);

    /* close session */
    msg = "<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"first\">"
            "<close-session/>"
            "</rpc>";
    ret = nc_proxy_write_msg(fd, NC_PROT_VERSION_11, msg, strlen(msg));
    assert_int_equal(ret, strlen(msg));

    /* read OK reply */
    ret = nc_proxy_read_msg(fd, NC_PROT_VERSION_11, -1, &buf, &buf_len);
    assert_int_not_equal(ret, -1);
    assert_string_equal(buf, "<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"first\"><ok/></rpc-reply>");

    /* close the proxy */
    ret = nc_proxy_unix_close(fd);
    assert_int_equal(ret, 0);

    free(buf);
    return NULL;
}

static void
test_proxy(void **state)
{
    int ret, i;
    pthread_t tids[2];

    assert_non_null(state);

    ret = pthread_create(&tids[0], NULL, proxy_client_thread, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_connect),
        cmocka_unit_test(test_invalid_user),
        cmocka_unit_test(test_proxy),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, setup_f, ln2_glob_test_teardown);
}
