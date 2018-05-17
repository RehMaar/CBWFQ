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

#include <linux/list.h>

//define PRINT_CALLS
#define PRINT_ALERT(msg) printk(KERN_ALERT"cbwfq: %s: " msg, __FUNCTION__);
#define PRINT_INFO(msg)  printk(KERN_INFO"cbwfq: %s: " msg, __FUNCTION__);
#define PRINT_INFO_ARGS(fmt, args...)  printk(KERN_INFO"cbwfq: %s: " fmt, __FUNCTION__, ##args);
#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define DEFAULT_CL_ID    65537 

/**
 * cbwfq_class -- class description
 * @common     Common qdisc data. Used in hash-table.
 * @queue      Class queue.
 * @ft         Finish time of the first packet in the queue.
 * @prev_ft    Finish time of the previous packet (that is already sent).
 * 
 */
struct cbwfq_class {
    struct Qdisc_class_common common;
    struct Qdisc *queue;

    u64 limit;
    u64 rate;

	u64 cl_sn;


    bool is_active;
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

	u64 ifrate;

	u32 active_rate;

    u64 sch_sn;
};


/* For parsing netlink messages. */
static const struct nla_policy cbwfq_policy[TCA_CBWFQ_MAX + 1] = {
    [TCA_CBWFQ_PARAMS]  = { .len = sizeof(struct tc_cbwfq_copt) },
    [TCA_CBWFQ_INIT]    = { .len = sizeof(struct tc_cbwfq_glob) },
};


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

    sch_tree_lock(sch);

    qdisc_tree_reduce_backlog(cl->queue, cl->queue->q.qlen,
                      cl->queue->qstats.backlog);
    qdisc_class_hash_remove(&q->clhash, &cl->common);

    sch_tree_unlock(sch);

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
cbwfq_modify_class(struct Qdisc *sch, struct cbwfq_class *cl,
                   struct tc_cbwfq_copt *copt)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);

    if (copt->cbwfq_cl_limit > 0) {
        cl->limit = copt->cbwfq_cl_limit;
    }

	if (copt->cbwfq_cl_rate_type == TCA_CBWFQ_RT_BYTE) {
        cl->rate  = copt->cbwfq_cl_rate;
	} else {
        cl->rate  = copt->cbwfq_cl_rate * q->ifrate;
        do_div(cl->rate, 100);
	}

    return 0;
}

static int
cbwfq_class_create(struct Qdisc *sch, struct tc_cbwfq_copt *copt, unsigned long classid)
{
    struct cbwfq_class *cl;
    struct cbwfq_sched_data *q = qdisc_priv(sch);

    cl = kmalloc( sizeof(struct cbwfq_class), GFP_KERNEL);
    if (cl == NULL)
        return  -ENOMEM;


    cl->common.classid = classid;
    cl->limit   = 1024;
    cl->rate  = 0;
    cl->is_active = false;
	cl->cl_sn = 0;

    if (cbwfq_modify_class(sch, cl, copt) != 0) {
        kfree(cl);
        return -EINVAL;
    }

    sch_tree_lock(sch);
        cbwfq_add_class(sch, cl);
    sch_tree_unlock(sch);

    PRINT_INFO_ARGS("classid: %ld:%ld (%ld)\n", TC_H_MAJ(classid) >> 16,
                    TC_H_MIN(classid), classid);
    PRINT_INFO_ARGS("Weight: %d Limit: %d Default rate: %d\n", cl->rate,
                    cl->limit, q->default_queue->rate);
    return 0;
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
    int err;
    int p_maj   = TC_H_MAJ(parentid) >> 16;
    int cid_maj = TC_H_MAJ(classid) >> 16;

    /* Both have to be 1, because there's no class heirarchy. */
    if (p_maj != 1 || cid_maj != 1)
        return -EINVAL;

    if (opt == NULL) {
        return -EINVAL;
    }

    err = nla_parse_nested(tb, TCA_CBWFQ_MAX, opt, cbwfq_policy, NULL);
    if (err < 0) {
        return err;
    }

    if (tb[TCA_CBWFQ_PARAMS] == NULL) {
        return -EINVAL;
    }
    copt = nla_data(tb[TCA_CBWFQ_PARAMS]);

    cl = cbwfq_class_lookup(q, classid);
    if (cl != NULL) {
        return cbwfq_modify_class(sch, cl, copt);
    }
    return cbwfq_class_create(sch, copt, classid);
}


static int
cbwfq_delete_class(struct Qdisc *sch, unsigned long arg)
{
    struct cbwfq_class *cl = (struct cbwfq_class *)arg;

    if (cl == NULL || cl->common.classid == DEFAULT_CL_ID) {
        return -EINVAL;
    }

    cbwfq_destroy_class(sch, cl);
    return 0;
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
   
static int
cbwfq_enqueue(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    struct cbwfq_class *cl;
    struct Qdisc *qdisc;
    int ret;

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
       u32 virtual_len = qdisc_pkt_len(skb) * q->ifrate;
       do_div(virtual_len, cl->rate);
        if (!cl->is_active) {
           cl->cl_sn = skb->tstamp = q->sch_sn + virtual_len;
           cl->is_active    = true;
           q->active_rate += cl->rate;
        } else {
            cl->cl_sn += virtual_len; //qdisc_pkt_len(skb) * q->ifrate / cl->rate;
			skb->tstamp = cl->cl_sn;
        }

		PRINT_INFO_ARGS("%llu to %u\n", skb->tstamp, cl->common.classid);

        /* Evaluate Finish time for each packet at arrival. */
        sch->q.qlen++;
        qdisc_qstats_backlog_inc(sch, skb);
        qdisc_qstats_backlog_inc(cl->queue, skb);
        return NET_XMIT_SUCCESS;
    }

    if (net_xmit_drop_count(ret)) {
        qdisc_qstats_drop(sch);
        qdisc_qstats_drop(cl->queue);
    }

    return ret;
}

static struct cbwfq_class *
cbwfq_find_min(struct cbwfq_sched_data *q)
{
    struct cbwfq_class *it, *cl = NULL;
    ktime_t ft = KTIME_MAX;
    int i;

    // Find class with min finish time. 
    for (i = 0; i < q->clhash.hashsize; i++) {
        hlist_for_each_entry(it, &q->clhash.hash[i], common.hnode) {
#ifdef PRINT_CALLS
            PRINT_INFO_ARGS("class -- id: %d rate: %d, limit: %d, len: %d, ft: %llu acitve: %d\n",
                            it->common.classid, it->rate, it->limit, it->queue->q.qlen,
                            it->ft, it->is_active);
#endif
           // Only for queues that are not empty.
            if (it->is_active) {
				struct sk_buff *skb = it->queue->ops->peek(it->queue);
				if (skb != NULL) {
    				if (ft > skb->tstamp) {
						cl = it;
						ft = skb->tstamp;
    				}
				} else {
					PRINT_INFO("W-w-w-whaat?");
				}
            }
        }
    }
    return cl;
}
    
static struct sk_buff *
cbwfq_peek(struct Qdisc *sch)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    struct cbwfq_class *cl = NULL;

    cl = cbwfq_find_min(q);
    if (cl == NULL) {
        return NULL;
    }
    return cl->queue->ops->peek(cl->queue);
}

static struct sk_buff *
cbwfq_dequeue(struct Qdisc *sch)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    struct cbwfq_class *cl = NULL;
    struct sk_buff *skb;

    if (q->active_rate == 0) {
        return NULL;
    }

    cl = cbwfq_find_min(q);
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

	q->sch_sn = skb->tstamp;

	PRINT_INFO_ARGS("%llu from %u\n", skb->tstamp, cl->common.classid);
    qdisc_bstats_update(sch, skb);
    qdisc_qstats_backlog_dec(sch, skb);
    qdisc_qstats_backlog_dec(cl->queue, skb);
    sch->q.qlen--;

    if (cl->queue->q.qlen == 0) {
        cl->is_active   = false;
        q->active_rate -= cl->rate;
        cl->cl_sn = 0;
    }

//    if (q->active_rate == 0) {
//		q->sch_sn = 0;
//    }

    return skb;
}

static void
cbwfq_reset(struct Qdisc *sch)
{
    int i;
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    struct cbwfq_class *it;

	q->sch_sn = 0;
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
    int err;

#ifdef PRINT_CALLS
    PRINT_INFO("begins");
#endif
    if (opt == NULL) {
        return -EINVAL;
    }

    err = nla_parse_nested(tb, TCA_CBWFQ_MAX, opt, cbwfq_policy, NULL);
    if (err < 0) {
        return err;
    }

    if (tb[TCA_CBWFQ_INIT] == NULL) {
        return -EINVAL;
    }

    qopt = nla_data(tb[TCA_CBWFQ_INIT]);

    sch_tree_lock(sch);

    if (qopt->cbwfq_gl_default_limit > 0) {
        q->default_queue->limit = qopt->cbwfq_gl_default_limit;
    }

	if (qopt->cbwfq_gl_rate_type == TCA_CBWFQ_RT_BYTE) {
        q->default_queue->rate  = qopt->cbwfq_gl_default_rate;
	} else {
        q->default_queue->rate  = qopt->cbwfq_gl_default_rate * q->ifrate / 100;
	}

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

    /* Init filter system. */
    err = tcf_block_get(&q->block, &q->filter_list, sch);
    if (err)
        return err;

    /* Init hash table for class storing. */
    err = qdisc_class_hash_init(&q->clhash);
    if (err < 0)
        return err;

    q->active_rate = 0;
    q->sch_sn      = 0;

    /* Init default queue. */
    cl = kmalloc( sizeof(struct cbwfq_class), GFP_KERNEL);
    if (cl == NULL) {
        return  -ENOMEM;
    }
    q->default_queue = cl;

    /* Set classid for default class. */
    cl->common.classid = TC_H_MAKE(1 << 16, 1);
    cl->limit   = 1024;
    cl->rate  = 0;
    cl->is_active = false;
	cl->cl_sn = 0;

    err = nla_parse_nested(tb, TCA_CBWFQ_MAX, opt, cbwfq_policy, NULL);
    if (err < 0)
        return err;

    qopt = nla_data(tb[TCA_CBWFQ_INIT]);

    if (qopt->cbwfq_gl_default_limit != 0) {
        PRINT_INFO_ARGS("Default queue limit: %d", qopt->cbwfq_gl_default_limit);
        cl->limit = qopt->cbwfq_gl_default_limit;
    }

	q->ifrate = qopt->cbwfq_gl_total_rate;

	if (qopt->cbwfq_gl_rate_type == TCA_CBWFQ_RT_BYTE) {
        cl->rate  = qopt->cbwfq_gl_default_rate;
	} else {
        cl->rate = (qopt->cbwfq_gl_default_rate * q->ifrate) / 100;
	}

    PRINT_INFO_ARGS("Default rate: %d; Total Rate: %d Opt rate: %d\n", cl->rate, q->ifrate, qopt->cbwfq_gl_default_rate);

    sch_tree_lock(sch);
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
    opt.cbwfq_gl_total_rate = q->ifrate; 

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
    opt.cbwfq_cl_rate = c->rate;

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
    /* Delete class. */
    .delete     =   cbwfq_delete_class,
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
