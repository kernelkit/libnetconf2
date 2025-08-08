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
#include <grp.h>
#include <pthread.h>
#include <pwd.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <cmocka.h>

#include "ln2_test.h"
#include "nc_client.h"

static int
setup_glob_f(void **state)
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

static int
setup_local_f(void **UNUSED(state))
{
    /* set verbosity */
    nc_verbosity(NC_VERB_VERBOSE);
    ly_log_level(LY_LLERR);

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

/* TEST */
static void *
auth_client_thread(void *arg)
{
    int ret = 0;
    struct nc_session *session = NULL;
    struct ln2_test_ctx *test_ctx = arg;

    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    pthread_barrier_wait(&test_ctx->barrier);

    /* session fails to be created with the default username */
    session = nc_connect_unix("/tmp/nc2_test_unix_sock", NULL);
    assert_null(session);

    /* set the expected username */
    nc_client_unix_set_username("auth_user");

    /* session created */
    session = nc_connect_unix("/tmp/nc2_test_unix_sock", NULL);
    assert_non_null(session);

    /* free the session */
    nc_session_free(session, NULL);

    return NULL;
}

static void *
auth_server_thread(void *arg)
{
    int ret;
    NC_MSG_TYPE msgtype;
    struct nc_session *session = NULL;
    struct ln2_test_ctx *test_ctx = arg;
    struct nc_pollsession *ps = NULL;
    struct lyd_node *config = NULL;
    struct passwd *pw;

    pw = getpwuid(getuid());
    assert_non_null(pw);

    /* create UNIX user mapping */
    ret = nc_server_config_add_unix_socket(test_ctx->ctx,
            "unix", "/tmp/nc2_test_unix_sock", NULL, NULL, NULL, &config);
    assert_int_equal(ret, 0);
    ret = nc_server_config_add_unix_user_mapping(test_ctx->ctx, "unix", pw->pw_name, "auth_user", &config);
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup_data(config);
    assert_int_equal(ret, 0);

    lyd_free_all(config);

    /* wait for the client to be ready to connect */
    pthread_barrier_wait(&test_ctx->barrier);

    /* session of the process user is not accepted */
    msgtype = nc_accept(NC_ACCEPT_TIMEOUT, test_ctx->ctx, &session);
    assert_int_equal(msgtype, NC_MSG_ERROR);

    /* session with the correct username is accepted */
    msgtype = nc_accept(NC_ACCEPT_TIMEOUT, test_ctx->ctx, &session);
    assert_int_equal(msgtype, NC_MSG_HELLO);

    /* session closed */
    ps = nc_ps_new();
    assert_non_null(ps);
    ret = nc_ps_add_session(ps, session);
    assert_int_equal(ret, 0);
    do {
        ret = nc_ps_poll(ps, NC_PS_POLL_TIMEOUT, NULL);
        assert_true(ret & NC_PSPOLL_RPC);
    } while (!(ret & NC_PSPOLL_SESSION_TERM));
    nc_ps_clear(ps, 1, NULL);
    nc_ps_free(ps);

    return NULL;
}

static void
test_auth(void **state)
{
    int ret, i;
    pthread_t tids[2];

    assert_non_null(state);

    ret = pthread_create(&tids[0], NULL, auth_client_thread, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, auth_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

/* TEST */
static void
test_config(void **state)
{
    int ret, i, ngroups = 0;
    struct ln2_test_ctx *test_ctx = *state;
    struct lyd_node *config = NULL;
    struct passwd *pw;
    struct group *gr = NULL;
    gid_t *groups;

    /* get the current user and one of its groups to use */
    pw = getpwuid(getuid());
    assert_non_null(pw);

    getgrouplist(pw->pw_name, pw->pw_gid, NULL, &ngroups);
    groups = malloc(ngroups * sizeof *groups);
    assert_non_null(groups);
    getgrouplist(pw->pw_name, pw->pw_gid, groups, &ngroups);

    /* keep the last group */
    for (i = 0; i < ngroups; ++i) {
        gr = getgrgid(groups[i]);
        assert_non_null(gr);
    }
    free(groups);

    /* create the UNIX socket */
    ret = nc_server_config_add_unix_socket(test_ctx->ctx,
            "unix2", "/tmp/nc2_test_unix_sock2", "0666", pw->pw_name, gr->gr_name, &config);
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup_data(config);
    assert_int_equal(ret, 0);

    /* deletes the UNIX socket */
    ret = nc_server_config_del_endpt("unix2", &config);
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup_data(config);
    assert_int_equal(ret, 0);

    lyd_free_all(config);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_connect, setup_local_f),
        cmocka_unit_test_setup(test_invalid_user, setup_local_f),
        cmocka_unit_test_setup(test_proxy, setup_local_f),
        cmocka_unit_test_setup(test_auth, setup_local_f),
        cmocka_unit_test_setup(test_config, setup_local_f),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, setup_glob_f, ln2_glob_test_teardown);
}
