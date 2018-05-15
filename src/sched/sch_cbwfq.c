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

//define PRINT_CALLS
#define PRINT_ALERT(msg) printk(KERN_ALERT"cbwfq: %s: " msg, __FUNCTION__);
#define PRINT_INFO(msg)  printk(KERN_INFO"cbwfq: %s: " msg, __FUNCTION__);
#define PRINT_INFO_ARGS(fmt, args...)  printk(KERN_INFO"cbwfq: %s: " fmt, __FUNCTION__, ##args);
#define MAX(a, b) ((a) > (b) ? (a) : (b))

/**
 * cbwfq_class -- class description
 * @common     Common qdisc data. Used in hash-table.
 * @queue      Class queue.
 * @ft         Finish time of the first packet in the queue.
 * @prev_ft    Finish time of the previous packet (that is already sent).
 * @limit      Limit for amount of packets in the queue.
 * @rate	   Allocated rate for the queue.
 */
struct cbwfq_class {
    struct Qdisc_class_common common;
    struct Qdisc *queue;

    psched_time_t ft;
    psched_time_t prev_ft;
    u32 limit;
    u32 weight;
};

/**
 * cbwfq_sched_data -- scheduler data
 * 
 * @clhash  Hash table of classes.
 * 
 * @filter_list       List of attached filters.
 * @block             Field used for filters to work.
 * 
 * @default_queue     Default class with default queue, NUFF SAID. 
 * 
 * @if_bandwidth      Bandwidth of the link. 
 * @used_by_cl_rate   Rate that is already used by classes.
 */
struct cbwfq_sched_data {
    struct Qdisc_class_hash clhash;

    struct tcf_proto __rcu *filter_list;
    struct tcf_block *block;

    struct cbwfq_class *default_queue;

    s32 used_by_cl_weight;
};


/* For parsing netlink messages. */
static const struct nla_policy cbwfq_policy[TCA_CBWFQ_MAX + 1] = {
    [TCA_CBWFQ_PARAMS]  = { .len = sizeof(struct tc_cbwfq_copt) },
    [TCA_CBWFQ_INIT]    = { .len = sizeof(struct tc_cbwfq_glob) },
};

/* ---- Class support. ---- */
static void
print_class(struct cbwfq_class *cl)
{
    PRINT_INFO_ARGS("classid: %d, limit: %d, rate: %d, q.len: %d, ft: %lld",
            cl->common.classid, cl->limit, cl->weight, cl->queue->q.qlen, cl->ft
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
    
    p_maj = TC_H_MAJ(parentid) >> 16;
    cid_maj = TC_H_MAJ(classid) >> 16;

    /* Both have to be 1, because there's no class heirarchy. */
    if (p_maj != 1 || cid_maj != 1)
        return -EINVAL;

    cid_min = TC_H_MIN(classid);

    // TODO: probably leak
    if (cbwfq_class_lookup(q, cid_min) != NULL) {
        PRINT_INFO("can't change class!");
        return -EEXIST;
    }

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

	c->weight = copt->cbwfq_cl_weight;
	if (q->used_by_cl_weight + c->weight > 100) {
    	PRINT_INFO_ARGS("sum class weight must be less or equal to 100%; now: %d", q->used_by_cl_weight + c->weight);
    	kfree(cl);
		return -EINVAL;
	}
	q->used_by_cl_weight += c->weight;
	q->default_queue->weight = 100 - q->used_by_cl_weight;

    cbwfq_add_class(sch, cl);

    PRINT_INFO_ARGS("classid: %d:%d (%d), parentid: %d:%d\n", TC_H_MAJ(classid) >> 16, TC_H_MIN(classid), classid,
                    TC_H_MAJ(parentid) >> 16, TC_H_MIN(parentid));
	PRINT_INFO_ARGS("Weight: %d\nLimit: %d\nDefault weight: %d\n", cl->weight, cl->limit, q->default_queue->weight);

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
    PRINT_INFO_ARGS("skb->prior: %d, sch->handle: %d\n", TC_H_MAJ(skb->priority), sch->handle);
#endif

    *qerr = NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
    if (TC_H_MAJ(skb->priority) != sch->handle) {
        fl = rcu_dereference_bh(q->filter_list);
        err = tcf_classify(skb, fl, &res, false);

        if (!fl || err < 0) {
            return q->default_queue;
        }

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
       
        classid = res.classid;
    }

    cl = cbwfq_class_lookup(q, classid);

#ifdef PRINT_CALLS
    PRINT_INFO("end\n");
#endif

    return cl;
}

static u32
eval_active_rate(struct cbwfq_sched_data *q)
{
    struct cbwfq_class *it;
    int i;
	u32 r = 0;
    for (i = 0; i < q->clhash.hashsize; i++) {
        hlist_for_each_entry(it, &q->clhash.hash[i], common.hnode) {
			if (it->queue->q.qlen != 0) {
    			PRINT_INFO_ARGS("id: %d, len: %u", it->common.classid, it->queue->q.qlen);
				r += it->rate;
			}
        }
    }
    return r;
}

static psched_time_t
eval_virtual_time(psched_time_t t, u32 r, u32 tr) {
	return (((t) * tr) / r);
}

/*
 * sch->if_bandwidth in bps
 * cl->rate          in bps
 * skb->len          in bytes (need to bits)
 * skb->tstamp       in tiks  (need to secs)
 * 
 * len(bits) / w  = virtual length
 * w = rate / bandwidth => len * bandwidth / rate
 */
static psched_time_t
eval_finish_time(struct Qdisc *sch, struct cbwfq_class *cl,
                 struct sk_buff *skb) 
{
	struct cbwfq_sched_data *q = qdisc_priv(sch);
    psched_time_t s = 0, t = 0;
	u32 active_r = eval_active_rate(q);

	//PRINT_INFO_ARGS("elems: %d, backlog: %d, backlog2: %d\n", q->clhash.hashelems, sch->qstats.backlog, q->backlog);
	if (cl->queue->q.qlen != 0 && active_r != 0 /*&& cl->prev_ft != 0*/) { 
    	psched_time_t a = eval_virtual_time(skb->tstamp, active_r, q->if_bandwidth);
    	s = MAX(a, cl->prev_ft);
    	PRINT_INFO_ARGS("ar: %u, a: %llu, pft: %llu\n", active_r, a, cl->prev_ft);
    	//s = MAX((skb->tstamp /*+ PSCHED_NS2TICKS(skb->len)*/), cl->prev_ft);
	}
	//t = eval_virtual_time(PSCHED_NS2TICKS(skb->len << 3), cl->rate, q->if_bandwidth);
	t = (qdisc_pkt_len(skb) * q->if_bandwidth) / cl->rate;

	PRINT_INFO_ARGS("cl: %ld, s: %llu, t: %llu; len: %u\n", cl->common.classid, s, t, qdisc_pkt_len(skb));
    return s + t;
}

static int
cbwfq_enqueue(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    struct cbwfq_class *cl;
    struct Qdisc *qdisc;
    int ret;

#ifdef PRINT_CALLS
    PRINT_INFO("called");
#endif
    if (skb->tstamp == 0)
        skb->tstamp = ktime_get_real();
    
    cl = cbwfq_classify(skb, sch, &ret);
    if (cl == NULL || cl->queue == NULL) {
        if (ret & __NET_XMIT_BYPASS)
            qdisc_qstats_drop(sch);
        __qdisc_drop(skb, to_free);
        return ret;
    }

	if (cl->queue->q.qlen >= cl->limit) {
        if (net_xmit_drop_count(ret)) {
            qdisc_qstats_drop(sch);
        }
        return qdisc_drop(skb, sch, to_free);
	}

    qdisc = cl->queue;
    ret = qdisc_enqueue(skb, qdisc, to_free);
    if (ret == NET_XMIT_SUCCESS) {
        if (cl->ft == 0) {
            cl->ft = eval_finish_time(sch, cl, skb);
        }
        sch->q.qlen++;
        qdisc_qstats_backlog_inc(sch, skb);
		q->backlog++;
        return NET_XMIT_SUCCESS;
    }

    if (net_xmit_drop_count(ret)) {
        qdisc_qstats_drop(sch);
    }

#ifdef PRINT_CALLS
    PRINT_INFO("end\n");
#endif
    return ret;
}

static struct sk_buff *
cbwfq_peek(struct Qdisc *sch)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    struct cbwfq_class *it, *cl = NULL;
    int i;
    ktime_t ft = KTIME_MAX;

#ifdef PRINT_CALLS
    PRINT_INFO("begin");
#endif

    // Find class with min finish time. 
    for (i = 0; i < q->clhash.hashsize; i++) {
        hlist_for_each_entry(it, &q->clhash.hash[i], common.hnode) {
#ifdef PRINT_CALLS
            PRINT_INFO_ARGS("class -- id: %d rate: %d, limit: %d, len: %d, ft: %lld \n",
                            it->common.classid, it->rate, it->limit, it->queue->q.qlen,
                            it->ft);
#endif
            // Only for queues that are not empty.
            if (it->queue->q.qlen > 0) {
                cl = it->ft > ft ? cl : it;
                ft = it->ft;
            }
        }
    }
    if (cl == NULL) {
        return NULL;
    }

#ifdef PRINT_CALLS
    PRINT_INFO_ARGS("out class -- id: %d", cl->common.classid);
#endif

    return cl->queue->ops->dequeue(cl->queue);

#if 0
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
#endif
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

    // Find class with min finish time. 
    for (i = 0; i < q->clhash.hashsize; i++) {
        hlist_for_each_entry(it, &q->clhash.hash[i], common.hnode) {
#ifdef PRINT_CALLS
            PRINT_INFO_ARGS("class -- id: %d rate: %d, limit: %d, len: %d, ft: %lld \n",
                            it->common.classid, it->rate, it->limit, it->queue->q.qlen,
                            it->ft);
#endif
            // Only for queues that are not empty.
            if (it->queue->q.qlen > 0) {
                cl = it->ft > ft ? cl : it;
                ft = it->ft;
            }
        }
    }
    if (cl == NULL) {
        return NULL;
    }

#ifdef PRINT_CALLS
    PRINT_INFO_ARGS("out class -- id: %d", cl->common.classid);
#endif

    skb = cl->queue->ops->dequeue(cl->queue);
    if (skb == NULL) {
        return NULL;
    }

    qdisc_bstats_update(sch, skb);
    qdisc_qstats_backlog_dec(sch, skb);
    sch->q.qlen--;
    q->backlog--;

    // Save final time and evaluate a new one.
    skb_next = cl->queue->ops->peek(cl->queue);
    if (skb_next != NULL) {
        cl->prev_ft = cl->ft;
        cl->ft = eval_finish_time(sch, cl, skb_next);
    } else {
        cl->ft = 0;
        cl->prev_ft = 0;
    }

#ifdef PRINT_CALLS
    PRINT_INFO_ARGS("end: classid: %u -- %d:%d", cl->common.classid,
                    TC_H_MAJ(cl->common.classid) << 16, TC_H_MIN(cl->common.classid));
#endif
    return skb;
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
    q->backlog = 0;
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
    struct nlattr *tb[TCA_CBWFQ_MAX + 1];
    int err = -EINVAL;

#ifdef PRINT_CALLS
    PRINT_INFO("begins");
#endif
    if (opt == NULL) {
        goto failure;
    }

    err = nla_parse_nested(tb, TCA_CBWFQ_MAX, opt, cbwfq_policy, NULL);
    if (err < 0) {
        goto failure;
    }

    err = -EINVAL;
    if (tb[TCA_CBWFQ_INIT] == NULL) {
        goto failure;
    }

    qopt = nla_data(tb[TCA_CBWFQ_INIT]);

    sch_tree_lock(sch);

    if (qopt->cbwfq_gl_default_limit > 0)
        q->default_queue->limit = qopt->cbwfq_gl_default_limit;

    if (qopt->cbwfq_gl_if_bandwidth > 0)
        q->if_bandwidth = qopt->cbwfq_gl_if_bandwidth;

	q->used_by_cl_rate = 0;
	q->default_queue->rate = 100;

    sch_tree_unlock(sch);
#ifdef PRINT_CALLS
    PRINT_INFO("and all is okay!");
#endif
    return 0;
failure:
    return err;
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

    /* Init filter system. */
    err = tcf_block_get(&q->block, &q->filter_list, sch);
    if (err)
        return err;

    /* Init hash table for class storing. */
    err = qdisc_class_hash_init(&q->clhash);
    if (err < 0)
        return err;

    /* Init default queue. */
    cl = kmalloc( sizeof(struct cbwfq_class), GFP_KERNEL);
    if (cl == NULL) {
        return  -ENOMEM;
    }
    q->default_queue = cl;

    /* Set classid for default class. */
    cl->common.classid = TC_H_MAKE(1 << 16, 1);
    cl->prev_ft = 0;
    cl->ft      = 0;
    cl->rate    = 0;
    cl->limit   = 0;

    err = nla_parse_nested(tb, TCA_CBWFQ_MAX, opt, cbwfq_policy, NULL);
    if (err < 0)
        return err;

    qopt = nla_data(tb[TCA_CBWFQ_INIT]);

    if (qopt->cbwfq_gl_default_limit != 0) {
        PRINT_INFO_ARGS("Default queue limit: %d", qopt->cbwfq_gl_default_limit);
        cl->limit = qopt->cbwfq_gl_default_limit;
    }

    PRINT_INFO_ARGS("Default weight: %d", qopt->cbwfq_gl_default_weight);

    q->backlog = 0;

    sch_tree_lock(sch);
    cbwfq_add_class(sch, cl);
    sch_tree_unlock(sch);

    return 0;
}

#if 0
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
    opt.cbwfq_gl_if_bandwidth = q->if_bandwidth; 

    nest = nla_nest_start(skb, TCA_OPTIONS);
    if (nest == NULL)
        goto nla_put_failure;

    if (nla_put(skb, TCA_CBWFQ_INIT, sizeof(opt), &opt))
        goto nla_put_failure;

    return nla_nest_end(skb, nest);

nla_put_failure:
    nlmsg_trim(skb, b);
    return -1;
}
#endif

static int
cbwfq_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
            struct Qdisc **old)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    struct cbwfq_class *cl;
#ifdef PRINT_CALLS
    PRINT_INFO("called");
#endif
    if (new == NULL)
        new = &noop_qdisc;

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
    struct cbwfq_class *cl = cbwfq_class_lookup(q, arg);

#ifdef PRINT_CALLS
    PRINT_INFO("called");
#endif
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
    opt.cbwfq_cl_limit  = c->limit;
    opt.cbwfq_cl_weight = c->weight;

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
    struct cbwfq_class *c = (struct cbwfq_class*)cl;
    int gs_base, gs_queue;

#ifdef PRINT_CALLS
    PRINT_INFO("called");
#endif

    if (c == NULL)
        return -1;

    gs_base = gnet_stats_copy_basic(qdisc_root_sleeping_running(sch),
                                    d, NULL, &c->queue->bstats);
    gs_queue = gnet_stats_copy_queue(d, NULL, &c->queue->qstats,
                                     c->queue->q.qlen);

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
#ifdef PRINT_CALLS
    PRINT_INFO("called");
#endif
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
    /* Change class. */
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
    //.dump       =   cbwfq_dump,
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
