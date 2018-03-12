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


static void explain(void)
{
	fprintf(stderr, "Usage: ... cbwfq bands NUMBER priomap P1 P2...[multiqueue]\n");
}

static void explain1(char *arg)
{
    fprintf(stderr, "Illegal \"%s\"\n", arg);
    explain();
}

static int cbwfq_parse_opt(struct qdisc_util *qu, int argc, char **argv, struct nlmsghdr *n)
{
	int pmap_mode = 0;
	int idx = 0;
	struct tc_cbwfq_qopt opt={3,{ 1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1 }};
	struct rtattr *nest;
	unsigned char mq = 0;

	while (argc > 0) {
		if (strcmp(*argv, "bands") == 0) {
			if (pmap_mode)
				explain();
			NEXT_ARG();
			if (get_integer(&opt.bands, *argv, 10)) {
				fprintf(stderr, "Illegal \"bands\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "priomap") == 0) {
			if (pmap_mode) {
				fprintf(stderr, "Error: duplicate priomap\n");
				return -1;
			}
			pmap_mode = 1;
		} else if (strcmp(*argv, "multiqueue") == 0) {
			mq = 1;
		} else if (strcmp(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			unsigned band;
			if (!pmap_mode) {
				fprintf(stderr, "What is \"%s\"?\n", *argv);
				explain();
				return -1;
			}
			if (get_unsigned(&band, *argv, 10)) {
				fprintf(stderr, "Illegal \"priomap\" element\n");
				return -1;
			}
			if (band > opt.bands) {
				fprintf(stderr, "\"priomap\" element is out of bands\n");
				return -1;
			}
			if (idx > TC_PRIO_MAX) {
				fprintf(stderr, "\"priomap\" index > TC_PRIO_MAX=%u\n", TC_PRIO_MAX);
				return -1;
			}
			opt.priomap[idx++] = band;
		}
		argc--; argv++;
	}

/*
	if (pmap_mode) {
		for (; idx < TC_PRIO_MAX; idx++)
			opt.priomap[idx] = opt.priomap[TC_PRIO_BESTEFFORT];
	}
*/
	nest = addattr_nest_compat(n, 1024, TCA_OPTIONS, &opt, sizeof(opt));
	if (mq)
		addattr_l(n, 1024, TCA_PRIO_MQ, NULL, 0);
	addattr_nest_compat_end(n, nest);
	return 0;
}

static int
cbwfq_parse_class_opt(struct qdisc_util *qu, int argc, char **argv, struct nlmsghdr *n)
{
	struct tc_cbwfq_copt opt;
    struct rtattr *tail;

    memset(&opt, 0, sizeof(opt));

    while (argc > 0) {

		if (matches(*argv, "prio") == 0) {
			NEXT_ARG();
			if (get_u32(&opt.prio, *argv, 10)) {
				explain1("prio");
				return -1;
    		}
    		fprintf(stderr, "Parse prio: %d", opt.prio);
		} else {
    			fprintf(stderr, "What is \"%s\"?\n", *argv);
    			explain();
    			return -1;
		}

		argc--; argv--;
    }

    tail = NLMSG_TAIL(n);
	addattr_l(n, 1024, TCA_OPTIONS, NULL, 0);
	addattr_l(n, 1024, TCA_CBWFQ_PARAMS, &opt, sizeof(opt));
	tail->rta_len = (void *) NLMSG_TAIL(n) - (void *) tail;
	fprintf(stderr, "length: %d", (int)tail->rta_len);
	return 0;
}

int cbwfq_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
	int i;
	struct tc_cbwfq_qopt *qopt;
	struct rtattr *tb[TCA_PRIO_MAX+1];

	if (opt == NULL)
		return 0;

	if (parse_rtattr_nested_compat(tb, TCA_PRIO_MAX, opt, qopt,
					sizeof(*qopt)))
                return -1;

	fprintf(f, "bands %u priomap ", qopt->bands);
	for (i=0; i<=TC_PRIO_MAX; i++)
		fprintf(f, " %d", qopt->priomap[i]);

	if (tb[TCA_PRIO_MQ])
		fprintf(f, " multiqueue: %s ",
		    *(unsigned char *)RTA_DATA(tb[TCA_PRIO_MQ]) ? "on" : "off");

	return 0;
}

struct qdisc_util cbwfq_qdisc_util = {
	.id	 	= "cbwfq",
	.parse_copt	= cbwfq_parse_class_opt,
	.parse_qopt	= cbwfq_parse_opt,
	.print_qopt	= cbwfq_print_opt,
};



/*
enum {
    TC_CBWFQ_DP_TD,     
    TC_CBWFQ_DP_WRED  
}

struct tc_cbwfq_qopt {
    __u32 bandwidth;
    __u32 weigth;
    __u32 limit;
    __u32 drop_policy;
};

struct tc_cbwfq_glob {
    __u32 ncls;
};
*/

#if 0
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
            "\tncls   number of classes; max is 64\n"
            "... class add ... cbwfq bandwidth B1 weight W1 [limit L1] [drop_policy wred]\n"
            "\tbandwidth 	bandwidth for the class (in percents)\n"
            "\tweight		weight of the class\n"
            "\tlimit		max queue length (in packets)\n"
            "\tdrop_policy	set a drop policy for the class; default is tail drop\n"
}


            
static int
cbwfq_parse_opt(struct qdisc_util *qu, int argc, char **argv, struct nlmsghdr *n)
{
	struct tc_cbwfq_glob opt;
	struct rtattr *tail;

	while (argc > 0) {
		if (matches(*argv, "ncls") == 0) {
			NEXT_ARG();

			if (get_u32(&opt.ncls, *argv, 10)) {
				explain1("ncls");
			} else if (opt.ncls > TC_CBWFQ_MAX_NCLS) {
				explain1("ncls is bigger than maximum number of classes");
			} else {
    			fprintf(stderr, "What is \"%s\"?\n", *argv);
    			explain();
				return 1;
			}
    		argc--; argv++;
		}
	}

	tail = NLMSG_TAIL(n);
	addattr_l(n, 1024, TCA_OPTIONS, NULL, 0);
	addattr_l(n, 2024, TCA_CBWFQ_INIT, &opt, NLMSG_ALIGN(sizeof(opt)));
	tail->rta_len = (void *) NLMSG_TAIL(n) - (void *) tail;
	return 0;
}

static int
cbwfq_parse_class_opt(struct qdisc_util *qu, int argc, char **argv, struct nlmsghdr *n)
{

    
	return 0;
}

static int
cbwfq_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{ return -1; }

static int
cbwfq_print_xstats(struct qdisc_util *qu, FILE *f, struct rtattr *xstats)
{ return -1; }

struct qdisc_util cbwfq_qdisc_util = {
	.id             = "cbwfq",
	.parse_qopt	    = cbwfq_parse_opt,
	.parse_copt	    = cbwfq_parse_class_opt,

	.print_qopt	    = cbwfq_print_opt,
	.print_xstats 	= cbwfq_print_xstats,
	.print_copt	    = cbwfq_print_opt,
};
#endif
