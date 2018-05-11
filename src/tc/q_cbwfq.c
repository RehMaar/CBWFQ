/*
 * q_cbwfq.c        CBWFQ.
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 * Authors: Maria Kuklina, <kuklina.md@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "utils.h"
#include "tc_util.h"

static void explain(void)
{
    fprintf(stderr, "Usage: ... qdisc add .. cbwfq bandwidth B limit L "
                                                   "[default limit L]\n"
            "\tbandwidth    total bandwidth in Mbps\n"
            "\tlimit        maximum value of packets in the CBWFQ system\n"
            "... class add ... cbwfq rate R [percent] [limit L]\n"
            "\trate R [percent]   rate for the class in bps (or in percents "
                                        "with ``percent'' keyword)\n"
            "\tlimit              max queue length (in packets)\n"
    );
}

          
static void explain1(char *arg)
{
    fprintf(stderr, "Illegal \"%s\"\n", arg);
    explain();
}

static int cbwfq_parse_opt(struct qdisc_util *qu, int argc, char **argv,
                           struct nlmsghdr *n)
{
    struct tc_cbwfq_glob opt;
    struct rtattr *tail;

    memset(&opt, 0, sizeof(opt));
    while (argc > 0) {
        if (matches(*argv, "default") == 0) {
            NEXT_ARG();
            if (matches(*argv, "limit") == 0) {
                NEXT_ARG();
                if (get_u32(&opt.cbwfq_gl_default_limit, *argv, 10)) {
                    explain1("limit");
                    return -1;
                }
            } else {
                fprintf(stderr, "Unknown default parameter: \"%s\".\n", *argv);
                explain();
                return -1;
            }
        } else if (matches(*argv, "bandwidth") == 0) {
            NEXT_ARG();
            if (get_u32(&opt.cbwfq_gl_if_bandwidth, *argv, 10)) {
                explain1("bandwidth");
                return -1;
            }
            opt.cbwfq_gl_if_bandwidth *= 1000000;
        } else if (matches(*argv, "limit") == 0) {
            NEXT_ARG();
            if (get_u32(&opt.cbwfq_gl_limit, *argv, 10)) {
                explain1("limit");
                return -1;
            }
        } else {
            fprintf(stderr, "What is \"%s\"?\n", *argv);
            explain();
            return -1;
        }
        argc--; argv++;
    }

    if (opt.cbwfq_gl_if_bandwidth <= 0) {
        fprintf(stderr, "Bandwidth must be set in Mbps.");
        explain();
        return -1;
    }

    tail = NLMSG_TAIL(n);
    addattr_l(n, 1024, TCA_OPTIONS, NULL, 0);
    addattr_l(n, 2024, TCA_CBWFQ_INIT, &opt, NLMSG_ALIGN(sizeof(opt)));
    tail->rta_len = (void *) NLMSG_TAIL(n) - (void *) tail;
    return 0;
}

static int cbwfq_parse_class_opt(struct qdisc_util *qu, int argc, char **argv,
                                 struct nlmsghdr *n)
{
    struct tc_cbwfq_copt opt;
    struct rtattr *tail;

    memset(&opt, 0, sizeof(opt));
    while (argc > 0) {
        if (matches(*argv, "rate") == 0) {
            NEXT_ARG();
            if (get_u32(&opt.cbwfq_cl_rate, *argv, 10)) {
                explain1("rate");
                return -1;
            }
            /* Check optional parameter. */
            argv++; argc--;
            if (argc <= 0) {
                break;
            } else if (matches(*argv, "percent") == 0) {
                opt.cbwfq_cl_rate_type = CBWFQ_RF_RATE;
            } else {
                opt.cbwfq_cl_rate_type = CBWFQ_RF_BYTES;
            }
        } else if (matches(*argv, "limit") == 0) {
            NEXT_ARG();
            if (get_u32(&opt.cbwfq_cl_limit, *argv, 10)) {
                explain1("limit");
                return -1;
            }
        } else {
            fprintf(stderr, "What is \"%s\"?\n", *argv);
            explain();
            return -1;
        }
        argc--; argv++;
    }

    if (opt.cbwfq_cl_rate <= 0) {
        fprintf(stderr, "Rate must be set.\n");
        explain();
        return -1;
    }

    tail = NLMSG_TAIL(n);
    addattr_l(n, 1024, TCA_OPTIONS, NULL, 0);
    addattr_l(n, 1024, TCA_CBWFQ_PARAMS, &opt, sizeof(opt));
    tail->rta_len = (void *) NLMSG_TAIL(n) - (void *) tail;
    return 0;
}

int cbwfq_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
    struct tc_cbwfq_glob *qopt = NULL;
    struct rtattr *tb[TCA_CBWFQ_MAX+1];

    if (opt == NULL) {
        return 0;
    }

    if (parse_rtattr_nested(tb, TCA_CBWFQ_MAX, opt)) {
        return -1;
    }

    if (tb[TCA_CBWFQ_INIT] == NULL) {
        return -1;
    }

    if (RTA_PAYLOAD(tb[TCA_CBWFQ_INIT]) < sizeof(*opt)) {
        fprintf(stderr, "qdisc opt is too short\n");
    } else {
        qopt = RTA_DATA(tb[TCA_CBWFQ_INIT]);
    }

    if (qopt != NULL) {
        fprintf(f, "total bandwidth %d limit %d ", qopt->cbwfq_gl_if_bandwidth,
                                                   qopt->cbwfq_gl_limit);
    }
    return 0;
}
static int cbwfq_print_copt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
    struct rtattr *tb[TCA_CBWFQ_MAX+1];
    struct tc_cbwfq_copt *copt = NULL;

    if (opt == NULL)
        return 0;

    if (parse_rtattr_nested(tb, TCA_CBWFQ_MAX, opt))
        return -1;

    if (tb[TCA_CBWFQ_PARAMS] != NULL) {
        if (RTA_PAYLOAD(tb[TCA_CBWFQ_PARAMS]) < sizeof(*opt))
            fprintf(stderr, "CBWFQ: class opt is too short\n");
        else
            copt = RTA_DATA(tb[TCA_CBWFQ_PARAMS]);
    }

    if (copt) {
        fprintf(f, "limit %d rate %d ", copt->cbwfq_cl_limit,
                						copt->cbwfq_cl_rate);
    }

    return 0;
}

struct qdisc_util cbwfq_qdisc_util = {
    .id           = "cbwfq",
    .parse_copt   = cbwfq_parse_class_opt,
    .parse_qopt   = cbwfq_parse_opt,
    .print_qopt   = cbwfq_print_opt,
    .print_copt   = cbwfq_print_copt,
};
