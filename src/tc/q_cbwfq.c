/*
 * q_cbwfq.c		CBWFQ.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
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


/**
 *  Usage: 
 * 	qdisc add cbwfq classes C1
 *		classes 	number of classes
 * 	class add ... cbwfq bandwidth B1 weight W1 limit L1 [drop_policy wred | default]
 * 
 */

static void explain(void)
{
	fprintf(stderr, "Usage: ... qdisc add .. cbwfq  ncls C1\n"
            "\tncls   number of classes\n"
            "... class add ... cbwfq bandwidth B1 weight W1 [limit L1] [drop_policy wred]\n"
            "\tbandwidth 	bandwidth for the class (in percents)\n"
            "\tweight		weight of the class\n"
            "\tlimit		max queue length (in packets)\n"
            "\tdrop_policy	set a drop policy for the class; default is tail drop\n"
}

static void explain1(char *arg)
{
    fprintf(stderr, "Illegal \"%s\"\n", arg);
    explain();
}
            
static int
cbwfq_parse_opt(struct qdisc_util *qu, int argc, char **argv, struct nlmsghdr *n)
{ return -1; }

static int
cbwfq_parse_class_opt(struct qdisc_util *qu, int argc, char **argv, struct nlmsghdr *n)
{ return -1; }
static int
cbwfq_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{ return -1; }
static int
cbwfq_print_xstats(struct qdisc_util *qu, FILE *f, struct rtattr *xstats)
{ return -1; }

struct qdisc_util cbwfq_qdisc_util = {
	.id             = "cbwfq",
	.parse_qopt	    = cbwfq_parse_opt,
	.print_qopt	    = cbwfq_print_opt,
	.print_xstats 	= cbwfq_print_xstats,
	.parse_copt	    = cbwfq_parse_class_opt,
	.print_copt	    = cbwfq_print_opt,
};
