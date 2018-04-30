/* TODO:
 * 1. Dynamic bands.            [+]
 * 2. Separate bands adding.    [+]
 * 3. Classfull pq.             [+]
 * 4. Filters				    [+]
 * 5. BANDWIDTH ALLOCATING      [ ]
 * 6. Usefull dump				[ ]
 * 
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>

/* CBWFQ

	-- flow 1 --					    -- class 1 ---> +-----+    +-----+
				 \						-- class 2 ---> | WFQ | __ | Out |
	-- flow 2 -- - -> [ Classifier] ->  -- class 3 ---> |     |    |	 |
				 /						-- class 4 ---> +-----+    +-----+
	-- flow 3 --

  | First part                                | Second part               |
*/


//define PRINT_CALLS
#define PRINT_ALERT(msg) printk(KERN_ALERT"cbwfq: %s: " msg, __FUNCTION__);
#define PRINT_INFO(msg)  printk(KERN_INFO"cbwfq: %s: " msg, __FUNCTION__);
#define PRINT_INFO_ARGS(fmt, args...)  printk(KERN_INFO"cbwfq: %s: " fmt, __FUNCTION__, ##args);

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) > (b) ? (b) : (a))

/**
 * cbwfq_class -- class description
 * @common 		Common qdisc data. Used in hash-table.
 * @queue		Class queue.

 */
struct cbwfq_class {
    struct Qdisc_class_common common;
    struct Qdisc *queue;

	ktime_t ft;      /* Finish time of peek packet. */
	ktime_t prev_ft; /* Previous finish time. */
    u32 limit; 
    u32 rate;
};

/**
 * cbwfq_sched_data -- scheduler data
 * 
 * @clhash	Hash table  of classes
 * 
 * @filter_list 	List of attached filters.
 * @block			HZ, needs for filters.
 * 
 * @default_queue	Default class with default queue, NUFF SAID. 
 * 
 */
struct cbwfq_sched_data {
    struct Qdisc_class_hash clhash;
    
    struct tcf_proto __rcu *filter_list;
    struct tcf_block *block;

	/* Default queue. */
    struct cbwfq_class *default_queue;
	u32 if_bandwidth; /* using ethtool_ops from dev_settings*/
	u32 used_rate;   /* Rate that is already used (the rest need
                      * to give the default queue.
                      */
	u32 limit;
};


/* For parsing netlink messages. */
static const struct nla_policy cbwfq_policy[TCA_CBWFQ_MAX + 1] = {
    [TCA_CBWFQ_PARAMS]  = { .len = sizeof(struct tc_cbwfq_copt) },
    [TCA_CBWFQ_INIT]    = { .len = sizeof(struct tc_cbwfq_glob) },
};

/* TOOLS. */

/**
 * TODO: IMPLEMENT IT!
 */
u64
get_bandwidth(struct Qdisc *sch) {
	return 10000;
}

psched_time_t
eval_finish_time(struct cbwfq_class *cl, struct sk_buff *skb) 
{
    ktime_t t = MAX(skb->tstamp, cl->prev_ft);
    ktime_t n = skb->len / cl->rate;
//    PRINT_INFO_ARGS("tstamp: %lld, prev_ft: %lld, len: %ld (data_len %ld)\n rate: %d, t: %d, n: %d, n + t:%d",
//                    skb->tstamp, cl->prev_ft, skb->len, skb->data_len, cl->rate, t, n, t + n);
    return t + n;
}
/* ---- Class support. ---- */

static void
print_class(struct cbwfq_class *cl)
{
    PRINT_INFO_ARGS("classid: %d, limit: %d, rate: %d, q.len: %d, ft: %ld",
            cl->common.classid, cl->limit, cl->rate, cl->queue->q.qlen, cl->ft
    );
}
/* Just print classes and their fields. */
static void
print_classes(struct cbwfq_sched_data *q) {
    struct cbwfq_class *it;
    int i;

    for (i = 0; i < q->clhash.hashsize; i++) {
        hlist_for_each_entry(it, &q->clhash.hash[i], common.hnode) {
			print_class(it);
        }
    }
}

/**
 * Add class to the hash table.
 * 
 * Class is allocate outside.
 */
static void
cbwfq_add_class(struct Qdisc *sch, struct cbwfq_class *cl)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
#ifdef PRINT_CALLS
    PRINT_INFO_ARGS("called: classid %u", cl->common.classid);
#endif

    cl->queue = qdisc_create_dflt(sch->dev_queue,
                                  &pfifo_qdisc_ops, cl->common.classid);
    qdisc_class_hash_insert(&q->clhash, &cl->common);
// DEBUG
    print_classes(q);
}

/**
 *  Destroy class; free space and so on.
 */
static void
cbwfq_destroy_class(struct Qdisc *sch, struct cbwfq_class *cl)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);

#ifdef PRINT_CALLS
    PRINT_INFO("called");
#endif
    qdisc_tree_reduce_backlog(cl->queue, cl->queue->q.qlen,
                      cl->queue->qstats.backlog);
    qdisc_class_hash_remove(&q->clhash, &cl->common);

    if (cl->queue) {
        qdisc_destroy(cl->queue);
    }
    kfree(cl);
}

/* */
static inline struct cbwfq_class *
cbwfq_class_lookup(struct cbwfq_sched_data *q, u32 classid)
{
    struct Qdisc_class_common *clc;

    // ATTENTION: classid must not be 0.
    clc = qdisc_class_find(&q->clhash, classid);
    if (clc == NULL)
        return NULL;
    return container_of(clc, struct cbwfq_class, common);
}

/* Returns pointer to the class. */
static unsigned long
cbwfq_find(struct Qdisc *sch, u32 classid)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    unsigned long cid = (unsigned long)cbwfq_class_lookup(q, classid);
#ifdef PRINT_CALLS
    PRINT_INFO_ARGS("called: classid: %u: cid: %lu", classid, cid);
#endif
	return cid;
}

static int
cbwfq_change_class(struct Qdisc *sch, u32 classid, u32 parentid,
                   struct nlattr **tca, unsigned long *arg)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    struct cbwfq_class *cl;
    struct nlattr *opt = tca[TCA_OPTIONS];
    struct nlattr *tb[TCA_CBWFQ_MAX + 1];
    struct tc_cbwfq_copt *copt;
    int err = -EINVAL;
    int cid_maj, cid_min, p_maj;
    
    PRINT_INFO_ARGS("classid: %d, parentid: %d, arg: %ld", (int)classid, (int)parentid, (long)*arg);
    PRINT_INFO_ARGS("classid: %d:%d, parentid: %d:%d", TC_H_MAJ(classid) >> 16, TC_H_MIN(classid),
                    TC_H_MAJ(parentid) >> 16, TC_H_MIN(parentid));

    p_maj = TC_H_MAJ(parentid) >> 16;
    cid_maj = TC_H_MAJ(classid) >> 16;

    /* Both have to be 1, because there's no class heirarchy. */
    if (p_maj != 1 || cid_maj != 1)
        return -EINVAL;

    cid_min = TC_H_MIN(classid);
    // TODO: probably leak
    PRINT_INFO_ARGS("classid: cid_min -- %d", cid_min);
    if (cbwfq_class_lookup(q, cid_min) != NULL) {
        return -EEXIST;
    }
    PRINT_INFO("classid: class doesn't exists.");

    if (opt == NULL) {
        goto failure;
    }

    err = nla_parse_nested(tb, TCA_CBWFQ_MAX, opt, cbwfq_policy, NULL);
    if (err < 0) {
        goto failure;
    }

    err = -EINVAL;
    if (tb[TCA_CBWFQ_PARAMS] == NULL) {
        goto failure;
    }

    copt = nla_data(tb[TCA_CBWFQ_PARAMS]);
    cl = kmalloc( sizeof(struct cbwfq_class), GFP_KERNEL);
    if (cl == NULL)
        return  -ENOMEM;

    cl->ft             = 0;
	cl->prev_ft        = 0;
    cl->common.classid = classid;

    if (copt->cbwfq_cl_limit != 0) {
        cl->limit = copt->cbwfq_cl_limit;
    } else {
    	cl->limit = 1024;
    }
	// Rate must be set.
	if (copt->cbwfq_cl_rate_type == CBWFQ_RF_BYTES) {
        cl->rate = copt->cbwfq_cl_rate;
	} else {
		cl->rate = (copt->cbwfq_cl_rate * q->if_bandwidth) / 100;
	}

	PRINT_INFO_ARGS("class -- id: %d, rate: %d, limit: %d\n", cl->common.classid, cl->rate, cl->limit);
    PRINT_INFO_ARGS("rate info -- total: %d, used: %d, requested rate: %d\n",
                     q->if_bandwidth, q->used_rate, cl->rate);
	q->used_rate -= cl->rate;
	if (q->used_rate < 0) {
		kfree(cl);

		return -EINVAL;
	}
	q->default_queue->rate = q->if_bandwidth - q->used_rate;
    cbwfq_add_class(sch, cl);

#ifdef PRINT_CALLS
	PRINT_INFO("end\n");
#endif
    return 0;

failure:
#ifdef PRINT_CALLS
    PRINT_INFO("fail end\n");
#endif
    return err;
}

/* --- Main qdisc support --- */

static struct cbwfq_class *
cbwfq_classify(struct sk_buff *skb, struct Qdisc *sch, int *qerr)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    struct cbwfq_class *cl;
    struct tcf_result res;
    struct tcf_proto *fl;
    int err;
    u32 classid = TC_H_MAKE(1 << 16, 1);

#ifdef PRINT_CALLS
    PRINT_INFO("called");
    PRINT_INFO_ARGS("skb->prior: %d, sch->handle: %d", TC_H_MAJ(skb->priority), sch->handle);
	PRINT_INFO("\n");
#endif
    *qerr = NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
    if (TC_H_MAJ(skb->priority) != sch->handle) {
        fl = rcu_dereference_bh(q->filter_list);
        /* net/sched/cls_api.c: scans classifier chain attached to the qdisc. */
        err = tcf_classify(skb, fl, &res, false);
#ifdef CONFIG_NET_CLS_ACT
        switch (err) {
            case TC_ACT_STOLEN:
            case TC_ACT_QUEUED:
            case TC_ACT_TRAP:
                *qerr = NET_XMIT_SUCCESS | __NET_XMIT_STOLEN;
                /* fall through */
            case TC_ACT_SHOT:
                return NULL;
        }
#endif
#ifdef PRINT_CALLS
        PRINT_INFO_ARGS("(not a signal) res.classid: %d\n", (int)res.classid);
#endif
        if (!fl || err < 0) {
            PRINT_INFO("use default\n");
            return q->default_queue;
        }
        classid = res.classid;
    }

    cl = cbwfq_class_lookup(q, classid);
    if (cl) { PRINT_INFO_ARGS("class: classid -- %d, limit -- %d, rate -- %d\n", cl->common.classid, cl->limit, cl->rate);}
    else { PRINT_INFO_ARGS("class is zero, id: %d\n", classid); }
#ifdef PRINT_CALLS
    PRINT_INFO("end\n");
#endif
    return cl;
}

typedef enum drop_type {
	CBWFQ_PKT_ENQ,
	CBWFQ_PKT_DROP,
	CBWFQ_PKT_DROP_WORST
} drop_type_t;

/* Need to deside drop packet, enqueue packet or
 * enqueue and drop other packet.
 */
static drop_type_t
cbwfq_pkt_for_drop(struct Qdisc *sch, struct Qdisc *queue, struct sk_buff *pkt)
{
    struct cbwfq_sched_data *dat = qdisc_priv(sch);
	struct sk_buff *skb_fst;
    PRINT_INFO_ARGS("queue: limit: %u, len: %u", queue->limit, queue->q.qlen);
    PRINT_INFO_ARGS("sch: limit: %u, len: %u", sch->limit, sch->q.qlen);

    if (sch->q.qlen < dat->limit && queue->q.qlen < dat->limit) {
    	PRINT_INFO("Yes, enqueue!");
    	return CBWFQ_PKT_ENQ;
    }

	/*
	 * It is not the way of evaluation dropping of WFQ (my eng sucks).
	 * We do simple evaluations, without official WFQ shit.
	 * 
	 * Here we drop packet if it is bigger than the FIRST one in the queue.
	 * Because it's easier to dequeue the first packet.
	 */
	skb_fst = queue->ops->peek(queue);
	if (skb_fst->data_len > pkt->data_len) {
		return CBWFQ_PKT_DROP;
	}

	if (sch->q.qlen > dat->limit) {
		return CBWFQ_PKT_DROP_WORST;
	}

   return CBWFQ_PKT_ENQ; 
}

static int
cbwfq_enqueue(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free)
{
    struct cbwfq_class *cl;
    struct Qdisc *qdisc;
    int ret;
#ifdef PRINT_CALLS
    PRINT_INFO("called");
#endif
	if (skb->tstamp == 0)
    	skb->tstamp = ktime_get_real();
    
    cl = cbwfq_classify(skb, sch, &ret);
    //print_class(cl);
#ifdef CONFIG_NET_CLS_ACT
    if (cl == NULL || cl->queue == NULL) {
        if (ret & __NET_XMIT_BYPASS)
            qdisc_qstats_drop(sch);
        __qdisc_drop(skb, to_free);
        return ret;
    }
#endif

	qdisc = cl->queue;
    ret = qdisc_enqueue(skb, qdisc, to_free);
    if (ret == NET_XMIT_SUCCESS) {
        if (cl->ft == 0) {
    		cl->ft = eval_finish_time(cl, skb);
    		PRINT_INFO_ARGS("new finish time: %ld", cl->ft);
        }
        qdisc_qstats_backlog_inc(sch, skb);
        sch->q.qlen++;
        return NET_XMIT_SUCCESS;
    }
    if (net_xmit_drop_count(ret)) {
        qdisc_qstats_drop(sch);
    }
#if 0
    ret = qdisc_enqueue(skb, qdisc, to_free);
    if (ret == NET_XMIT_SUCCESS) {
        qdisc_qstats_backlog_inc(sch, skb);
        sch->q.qlen++;
        PRINT_INFO("end success\n");
        return NET_XMIT_SUCCESS;
    }

    if (net_xmit_drop_count(ret))
        qdisc_qstats_drop(sch);
#endif
#if 0
	switch (cbwfq_pkt_for_drop(sch, qdisc, skb)) {
		case CBWFQ_PKT_DROP: {
    		PRINT_INFO("wfq-drop: packet drop");
        	qdisc_drop(skb, qdisc, to_free);
            qdisc_qstats_drop(qdisc);
			break;
		}
    	case CBWFQ_PKT_DROP_WORST: {
        	struct sk_buff *skb_drp = qdisc->ops->dequeue(qdisc);
    		PRINT_INFO("wfq-drop: packet drop with worst time");
        	qdisc_drop(skb_drp, qdisc, to_free);
            qdisc_qstats_drop(qdisc);
    	} /* fallthrough */
    	case CBWFQ_PKT_ENQ: {
#endif
#if 0

#endif
#if 0
    		break;
    	}
	}
#endif
    PRINT_INFO("end\n");
    return ret;
}

static struct sk_buff *
cbwfq_peek(struct Qdisc *sch)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    struct cbwfq_class *it;
    int i;

#ifdef PRINT_CALLS
    PRINT_INFO("begin");
#endif
    for (i = 0; i < q->clhash.hashsize; i++) {
        hlist_for_each_entry(it, &q->clhash.hash[i], common.hnode) {
            struct sk_buff *skb = it->queue->ops->peek(it->queue);
            if (skb) {
#ifdef PRINT_CALLS
                PRINT_INFO("end");
#endif
                return skb;
            }
        }
    }


#ifdef PRINT_CALLS
    PRINT_INFO("end null");
#endif
    return NULL;
}

static struct sk_buff *
cbwfq_dequeue(struct Qdisc *sch)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    struct cbwfq_class *it, *cl = NULL;
    struct sk_buff *skb, *skb_next;
	int i;
	ktime_t ft = KTIME_MAX;
#ifdef PRINT_CALLS
    PRINT_INFO("begin");
#endif

#if 1
	// Find class with min finish time. 
	for (i = 0; i < q->clhash.hashsize; i++) {
		hlist_for_each_entry(it, &q->clhash.hash[i], common.hnode) {
#ifdef PRINT_CALLS
    		PRINT_INFO_ARGS("class -- id: %d rate: %d, limit: %d, ft: %lld, prev_ft: %lld\n",
                            it->common.classid, it->rate, it->limit, it->ft, it->prev_ft);
#endif
    		// Only for queues that are not empty.
    		if (it->queue->q.qlen > 0) {
    			cl = it->ft > ft ? cl : it;
    			ft = it->ft;
    		}
		}
	}
	if (cl == NULL) {
		PRINT_INFO("class with min finish time wasn't found ??");
		return NULL;
	}

//#ifdef PRINT_CALLS
	PRINT_INFO_ARGS("out class -- id: %d", cl->common.classid);
//#endif
	cl->prev_ft = cl->ft;
	skb_next = cl->queue->ops->peek(cl->queue);
	if (skb_next != NULL) {
    	cl->ft = eval_finish_time(cl, skb_next);
	} else {
		cl->ft = 0;
	}

    skb = cl->queue->ops->dequeue(cl->queue);
    if (skb != NULL) {
        qdisc_bstats_update(sch, skb);
        qdisc_qstats_backlog_dec(sch, skb);
        sch->q.qlen--;
#ifdef PRINT_CALLS
        PRINT_INFO_ARGS("end: classid: %u -- %d:%d", cl->common.classid,
                        TC_H_MAJ(cl->common.classid) << 16, TC_H_MIN(cl->common.classid));
#endif
        return skb;
    }
#else
    for (i = 0; i < q->clhash.hashsize; i++) {
        hlist_for_each_entry(it, &q->clhash.hash[i], common.hnode) {
            //print_class(it);
            skb = qdisc_dequeue_peeked(it->queue);
            if (skb != NULL) {
                qdisc_bstats_update(sch, skb);
                qdisc_qstats_backlog_dec(sch, skb);
                sch->q.qlen--;
#ifdef PRINT_CALLS
                PRINT_INFO_ARGS("end: classid: %lu -- %d:%d", it->common.classid,
                                TC_H_MAJ(it->common.classid) << 16, TC_H_MIN(it->common.classid));
#endif
                return skb;
            }
        }
    }
#endif
#ifdef PRINT_CALLS
    PRINT_INFO("end null (empty even default queue)");
#endif
    return NULL;
}

static void
cbwfq_reset(struct Qdisc *sch)
{
    int i;
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    struct cbwfq_class *it;

    for (i = 0; i < q->clhash.hashsize; i++) {
        hlist_for_each_entry(it, &q->clhash.hash[i], common.hnode) {
            //printk(KERN_ALERT" cbwfq: %s: classid: %d, prio %d, q %p", __FUNCTION__,
            //        it->common.classid, it->prio, it->queue
            //);
            qdisc_reset(it->queue);
        }
    }
    sch->qstats.backlog = 0;
    sch->q.qlen = 0;
}

static void
cbwfq_destroy(struct Qdisc *sch)
{
    int i;
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    struct cbwfq_class *it;
    struct hlist_node *next;
#ifdef PRINT_CALLS
    PRINT_INFO("called");
#endif
    tcf_block_put(q->block);

    for (i = 0; i < q->clhash.hashsize; i++) {
        hlist_for_each_entry_safe(it, next, &q->clhash.hash[i], common.hnode) {
            if (it != NULL) {
                int id = it->common.classid;
                cbwfq_destroy_class(sch, it);
            }
        }
    }
    qdisc_class_hash_destroy(&q->clhash);
}

static int
cbwfq_change(struct Qdisc *sch, struct nlattr *opt)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    struct tc_cbwfq_glob *qopt;

#ifdef PRINT_CALLS
    PRINT_INFO("begins");
#endif
    if (nla_len(opt) < sizeof(*qopt)) {
        PRINT_ALERT("no options are given");
        return -EINVAL;
    }
    qopt = nla_data(opt);

    /* ATTENTION: TODO: what is a reasonable value? */
    if (qopt->cbwfq_gl_limit == 0) {
        return -EINVAL;
    }
    sch_tree_lock(sch);

	if (qopt->cbwfq_gl_default_limit > 0)
        q->default_queue->limit = qopt->cbwfq_gl_default_limit;

    if (qopt->cbwfq_gl_if_bandwidth > 0)
        q->if_bandwidth = qopt->cbwfq_gl_if_bandwidth;

    sch_tree_unlock(sch);
#ifdef PRINT_CALLS
    PRINT_INFO("and all is okay!");
#endif
    return 0;
}

static int
cbwfq_init(struct Qdisc *sch, struct nlattr *opt)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    struct cbwfq_class *cl;
    struct tc_cbwfq_glob *qopt;
    struct nlattr *tb[TCA_CBWFQ_MAX + 1];
    int err;

#ifdef PRINT_CALLS
    PRINT_INFO("begins");
#endif
    if (!opt)
        return -EINVAL;

	// Init filter system
    err = tcf_block_get(&q->block, &q->filter_list, sch);
    if (err)
        return err;

	// Init hash table for class storing.
    err = qdisc_class_hash_init(&q->clhash);
    if (err < 0)
        return err;

	// Init default queue.
    cl = kmalloc( sizeof(struct cbwfq_class), GFP_KERNEL);
    if (cl == NULL) {
        return  -ENOMEM;
    }
	q->default_queue = cl;

	// Set max queue length.
	q->limit = qdisc_dev(sch)->tx_queue_len;
	
	// Set classid for default class.
    cl->common.classid = TC_H_MAKE(1 << 16, 1);
	cl->prev_ft = 0;
	cl->ft      = 0;
	cl->rate    = 0;
	cl->limit   = 1024;

	// Parse options.
#if 0
    if (nla_len(opt) < sizeof(*qopt))
        return -EINVAL;
    qopt = nla_data(opt);
#else
	err = nla_parse_nested(tb, TCA_CBWFQ_MAX, opt, cbwfq_policy, NULL);
	if (err < 0)
    	return err;
	qopt = nla_data(tb[TCA_CBWFQ_INIT]);
#endif

    // If value set.
    if (qopt->cbwfq_gl_default_limit != 0) {
        PRINT_INFO_ARGS("Default queue limit: %d", qopt->cbwfq_gl_default_limit);
        cl->limit = qopt->cbwfq_gl_default_limit;
    }

	// Value must be set.
    q->used_rate = cl->rate = q->if_bandwidth = qopt->cbwfq_gl_if_bandwidth;
    PRINT_INFO_ARGS("Rate: %d", qopt->cbwfq_gl_if_bandwidth);

	// If value set.
	if (qopt->cbwfq_gl_limit != 0) {
        PRINT_INFO_ARGS("Queue limit: %d", qopt->cbwfq_gl_limit);
		q->limit = qopt->cbwfq_gl_limit;
	}

	// I don't know why need to lock.
    sch_tree_lock(sch);
	// Add class to hash table
    cbwfq_add_class(sch, cl);

    sch_tree_unlock(sch);
    return 0;
}

static int
cbwfq_dump(struct Qdisc *sch, struct sk_buff *skb)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    unsigned char *b = skb_tail_pointer(skb);
    struct tc_cbwfq_glob opt;
    struct nlattr *nest;

#ifdef PRINT_CALLS
    PRINT_INFO("called");
#endif

    memset(&opt, 0, sizeof(opt));
    opt.cbwfq_gl_limit = q->limit;
    opt.cbwfq_gl_if_bandwidth  = q->if_bandwidth; 

    nest = nla_nest_start(skb, TCA_OPTIONS);
    if (nest == NULL)
        goto nla_put_failure;

    if (nla_put(skb, TCA_HTB_PARMS, sizeof(opt), &opt))
        goto nla_put_failure;

    return nla_nest_end(skb, nest);

nla_put_failure:
    nlmsg_trim(skb, b);
    return -1;
}

static int
cbwfq_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
            struct Qdisc **old)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    struct cbwfq_class *cl;
    //unsigned long band = arg - 1;
#ifdef PRINT_CALLS
    PRINT_INFO("called");
#endif
    if (new == NULL)
        new = &noop_qdisc;

    //*old = qdisc_replace(sch, new, &q->queues[band]);
    cl = cbwfq_class_lookup(q, arg);
    if (cl) {
        *old = qdisc_replace(sch, new, &cl->queue);
        return 0;
    }
    return -1;
}

static struct Qdisc *
cbwfq_leaf(struct Qdisc *sch, unsigned long arg)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    //unsigned long band = arg - 1;
    struct cbwfq_class *cl = cbwfq_class_lookup(q, arg);

#ifdef PRINT_CALLS
    PRINT_INFO("called");
#endif
    //return q->queues[band];
    return cl == NULL? NULL : cl->queue;
}

static unsigned long
cbwfq_bind(struct Qdisc *sch, unsigned long parent, u32 classid)
{

#ifdef PRINT_CALLS
    PRINT_INFO("called");
#endif
    return cbwfq_find(sch, classid);
}


static void
cbwfq_unbind(struct Qdisc *q, unsigned long cl)
{
#ifdef PRINT_CALLS
    PRINT_INFO("called");
#endif
}

static int
cbwfq_dump_class(struct Qdisc *sch, unsigned long cl,
                 struct sk_buff *skb, struct tcmsg *tcm)
{
    struct cbwfq_class *c = (struct cbwfq_class *)cl;
    struct nlattr *nest;
    struct tc_cbwfq_copt opt;
    
#ifdef PRINT_CALLS
    PRINT_INFO("called");
#endif
    
    if (c == NULL) {
        return -1;
    }

    tcm->tcm_handle = c->common.classid;
    tcm->tcm_info = c->queue->handle;

    nest = nla_nest_start(skb, TCA_OPTIONS);
    if (nest == NULL)
        goto failure;

    memset(&opt, 0, sizeof(opt));
    opt.cbwfq_cl_limit = c->limit;
    opt.cbwfq_cl_rate  = c->rate;

    if (nla_put(skb, TCA_CBWFQ_PARAMS, sizeof(opt), &opt))
        goto failure;

    return nla_nest_end(skb, nest);

failure:
    nla_nest_cancel(skb, nest);
    return -1;
}

static int
cbwfq_dump_class_stats(struct Qdisc *sch, unsigned long cl,
                       struct gnet_dump *d)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    struct cbwfq_class *c = (struct cbwfq_class*)cl;
    struct Qdisc *cl_q;

#ifdef PRINT_CALLS
    PRINT_INFO("called");
#endif

    if (c == NULL)
        return -1;

    cl_q = c->queue; 
    int gs_base = gnet_stats_copy_basic(qdisc_root_sleeping_running(sch), d, NULL, &cl_q->bstats);
    int gs_queue = gnet_stats_copy_queue(d, NULL, &cl_q->qstats, cl_q->q.qlen);

	return gs_base < 0 || gs_queue < 0 ? -1 : 0;
}

static void
cbwfq_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    struct cbwfq_class *cl;
    int h;

#ifdef PRINT_CALLS
    PRINT_INFO("called");
#endif
    if (arg->stop)
        return;

    for (h = 0; h < q->clhash.hashsize; h++) {
        hlist_for_each_entry(cl, &q->clhash.hash[h], common.hnode) {
            if (arg->count < arg->skip) {
                arg->count++;
                continue;
            }
            if (arg->fn(sch, (unsigned long)cl, arg) < 0) {
                arg->stop = 1;
                break;
            }
            arg->count++;
        }
    }
}

static struct tcf_block *
cbwfq_tcf_block(struct Qdisc *sch, unsigned long cl)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    //struct cbwfq_class *c = (struct cbwfq_class *)cl;
#ifdef PRINT_CALLS
    PRINT_INFO("called");
#endif
	PRINT_INFO_ARGS("with argument: %ld", cl);
    //if (c != NULL) {
    //    PRINT_INFO_ARGS("classid: %d", c->common.classid);
    //    return c->block;
    //}
    return q->block;
}

static const struct Qdisc_class_ops cbwfq_class_ops = {
    /* Attach a new qdisc to a class and return the prev attached qdisc. */
    .graft      =   cbwfq_graft,
    /* Returns a pointer to the qdisc of class. */
    .leaf       =   cbwfq_leaf,
    /* */
    .find       =   cbwfq_find,
    /* Iterates over all classed of a qdisc */
    .walk       =   cbwfq_walk,
    /* */
    .change     =   cbwfq_change_class,
    /* */
    .tcf_block  =   cbwfq_tcf_block,
    /* Binds an instance of a filter to the class. */
    .bind_tcf   =   cbwfq_bind,
    /* Removes an instalce of a filter from the class. */
    .unbind_tcf =   cbwfq_unbind,
    /* Returns stats for a class*/
    .dump       =   cbwfq_dump_class,
    .dump_stats =   cbwfq_dump_class_stats,
};

static struct Qdisc_ops cbwfq_qdisc_ops __read_mostly = {
    /* Points to next Qdisc_ops. */
    .next       =   NULL,
    /* Points to structure that provides a set of functions for
     * a particular class. */
    .cl_ops     =   &cbwfq_class_ops,
    /* Char array contains identity of the qdsic. */
    .id         =   "cbwfq",

    .priv_size  =   sizeof(struct cbwfq_sched_data),
    /* Enqueuing function. */
    .enqueue    =   cbwfq_enqueue,
    /* Dequeuing function. */
    .dequeue    =   cbwfq_dequeue,
    /* Like dequeue, but doesn't delete packet from a queue.*/
    .peek       =   cbwfq_peek,
    /* Initilize new queueing discipline. */
    .init       =   cbwfq_init,
    /* Reset the qdisc back to initial state. */
    .reset      =   cbwfq_reset,
    /* Destroys the resources usef during initilization of the qdisc. */
    .destroy    =   cbwfq_destroy,
    /* Changes values of the parameters of a qdisc. */
    .change     =   cbwfq_change,
    /* Shows statistics of the queuing discipline. */
    .dump       =   cbwfq_dump,
    .owner      =   THIS_MODULE,
};

static int __init
cbwfq_module_init(void)
{
    printk(KERN_ALERT"cbwfq: register!");
    return register_qdisc(&cbwfq_qdisc_ops);
}

static void __exit
cbwfq_module_exit(void)
{
    printk(KERN_ALERT"cbwfq: unregister!");
    unregister_qdisc(&cbwfq_qdisc_ops);
}

module_init(cbwfq_module_init)
module_exit(cbwfq_module_exit)

MODULE_LICENSE("GPL");
