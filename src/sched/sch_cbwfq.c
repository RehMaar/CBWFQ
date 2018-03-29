/* TODO:
 * 1. Dynamic bands.            [+]
 * 2. Separate bands adding.    [+]
 * 3. Classfull pq.             [ ]
 * 4. Weighted *pq*.            [ ]
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


struct cbwfq_class {
    struct Qdisc_class_common common;
    struct Qdisc *queue;

    u32 limit;
    u32 weight;
};

struct cbwfq_sched_data {
    /* Try to add dynamic amount of bands. */
    struct Qdisc_class_hash clhash;
    
    int bands;
    struct tcf_proto __rcu *filter_list;
    struct tcf_block *block;

	/* Default queue. */
    struct cbwfq_class *default_queue;
    /* Save old for validating. */
    u32 limit;
};

/* ---- Class support. ---- */
static void print_classes(struct cbwfq_sched_data *q) {
    struct cbwfq_class *it;
    int i;

    for (i = 0; i < q->clhash.hashsize; i++) {
        hlist_for_each_entry(it, &q->clhash.hash[i], common.hnode) {
            printk(KERN_ALERT" cbwfq: %s: classid: %d, limit: %d, weight: %d, q %p", __FUNCTION__,
                    it->common.classid, it->limit, it->weight, it->queue
                   );
        }
    }
}

/* Allocate cl outside. */
static void cbwfq_add_class(struct Qdisc *sch, struct cbwfq_class *cl)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
//#ifdef PRINT_CALLS
    PRINT_INFO_ARGS("called: classid %u", cl->common.classid);
//#endif

    cl->queue = qdisc_create_dflt(sch->dev_queue,
                                  &pfifo_qdisc_ops, cl->common.classid);
    qdisc_class_hash_insert(&q->clhash, &cl->common);
    PRINT_INFO("print classes");
    print_classes(q);
}

/* But free cl inside. */
static void cbwfq_destroy_class(struct Qdisc *sch, struct cbwfq_class *cl)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);

#ifdef PRINT_CALLS
    PRINT_INFO("called");
#endif
    qdisc_tree_reduce_backlog(cl->queue, cl->queue->q.qlen,
                      cl->queue->qstats.backlog);
    qdisc_class_hash_remove(&q->clhash, &cl->common);

    if (cl->queue) {
        PRINT_INFO("call qdisc_destroy");
        qdisc_destroy(cl->queue);
    }
    PRINT_INFO("kfree");
    kfree(cl);
}

/* In our case classid is prio. */
static inline struct cbwfq_class *
cbwfq_class_lookup(struct cbwfq_sched_data *q, u32 classid)
{
    struct Qdisc_class_common *clc;
    //struct cbwfq_class *it;
#ifdef PRINT_CALLS
    PRINT_INFO("called");
#endif
    //for (i = 0; i < q->clhash.hashsize; i++) {
    //    hlist_for_each_entry(it, &q->clhash.hash[i], common.hnode) {
    //        if (classid == it->common.classid)
    //            return it;
    //    }
    //}
    //return NULL;
    // ATTENTION: classid must not be 0.
    clc = qdisc_class_find(&q->clhash, classid);
    if (clc == NULL)
        return NULL;
    return container_of(clc, struct cbwfq_class, common);
}

/* Returns pointer to the class. */
static unsigned long cbwfq_find(struct Qdisc *sch, u32 classid)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    unsigned long cid = (unsigned long)cbwfq_class_lookup(q, classid);
//#ifdef PRINT_CALLS
    PRINT_INFO_ARGS("called: classid: %u: cid: %lu", classid, cid);
//#endif
	return cid;
}

static const struct nla_policy cbwfq_policy[TCA_CBWFQ_MAX + 1] = {
    [TCA_CBWFQ_PARAMS]  = { .len = sizeof(struct tc_cbwfq_copt) },
    [TCA_CBWFQ_INIT]    = { .len = sizeof(struct tc_cbwfq_glob) },
};

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
    if (cbwfq_class_lookup(q, cid_min) != NULL) {
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
    PRINT_INFO_ARGS("given from US values are: limit: %u, weight: %u", copt->limit, copt->weight);

    cl = kmalloc( sizeof(struct cbwfq_class), GFP_KERNEL);
    if (cl == NULL)
        return  -ENOMEM;

    cl->common.classid = classid;
    cl->weight = copt->weight;
    cl->limit  = copt->limit;

//  err = tcf_block_get(&cl->block, &cl->filter_list, sch);
//  if (err) {
//      kfree(cl);
//      goto failure;
//  }
    cbwfq_add_class(sch, cl);

    return 0;
failure:
    PRINT_INFO("ends");
    return err;
}

/* --- Other. --- */

static struct Qdisc *
cbwfq_classify(struct sk_buff *skb, struct Qdisc *sch, int *qerr)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    struct cbwfq_class *cl;
    struct tcf_result res;
    struct tcf_proto *fl;
    int err;
    u32 classid = TC_H_MAKE(1 << 16, 1);

//#ifdef PRINT_CALLS
    PRINT_INFO("called");
    PRINT_INFO_ARGS("skb->prior: %d, sch->handle: %d", TC_H_MAJ(skb->priority), sch->handle);
//#endif
	PRINT_INFO("\n");
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
        PRINT_INFO_ARGS("(not a signal) res.classid: %d", (int)res.classid);
        if (!fl || err < 0) {
            PRINT_INFO("use default");
        	PRINT_INFO("\n");
            //struct cbwfq_class *cl = cbwfq_class_lookup(q, PARENT_CLASS);
            //return cl == NULL ? NULL : cl->queue;
            return q->default_queue->queue;
        }
        classid = res.classid;
    }

    cl = cbwfq_class_lookup(q, classid);
    if (cl) { PRINT_INFO_ARGS("class: classid -- %d, limit -- %d, weight -- %d", cl->common.classid, cl->limit, cl->weight);}
    else { PRINT_INFO_ARGS("class is zero, id: %d", classid); }
#ifdef PRINT_CALLS
    PRINT_INFO("end");
#endif
	PRINT_INFO("\n");
    return cl == NULL ? NULL : cl->queue;
}

static int
cbwfq_enqueue(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free)
{
    struct Qdisc *qdisc;
    int ret;

#ifdef PRINT_CALLS
    PRINT_INFO("called");
#endif
    qdisc = cbwfq_classify(skb, sch, &ret);

#ifdef CONFIG_NET_CLS_ACT
    if (qdisc == NULL) {

        if (ret & __NET_XMIT_BYPASS)
            qdisc_qstats_drop(sch);
        __qdisc_drop(skb, to_free);
        return ret;
    }
#endif

    ret = qdisc_enqueue(skb, qdisc, to_free);
    if (ret == NET_XMIT_SUCCESS) {
        qdisc_qstats_backlog_inc(sch, skb);
        sch->q.qlen++;
#ifdef PRINT_CALLS
        PRINT_INFO("end success");
#endif
        return NET_XMIT_SUCCESS;
    }
    if (net_xmit_drop_count(ret))
        qdisc_qstats_drop(sch);
#ifdef PRINT_CALLS
    PRINT_INFO("end");
#endif
    return ret;
}

static struct sk_buff *cbwfq_peek(struct Qdisc *sch)
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

//    for (prio = 1; prio <= q->bands; prio++) {
//
//        struct cbwfq_class *cl = cbwfq_class_lookup(q, prio);
//        if (cl) {
//            struct sk_buff *skb = cl->queue->ops->peek(cl->queue);
//            if (skb)
//                return skb;
//        }
//    }

#ifdef PRINT_CALLS
    PRINT_INFO("end null");
#endif
    return NULL;
}

static struct sk_buff *cbwfq_dequeue(struct Qdisc *sch)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    struct cbwfq_class *it;
    struct sk_buff *skb;
	int i;
#ifdef PRINT_CALLS
    PRINT_INFO("begin");
#endif

    for (i = 0; i < q->clhash.hashsize; i++) {
        hlist_for_each_entry(it, &q->clhash.hash[i], common.hnode) {
            skb = qdisc_dequeue_peeked(it->queue);
            if (skb) {
                qdisc_bstats_update(sch, skb);
                qdisc_qstats_backlog_dec(sch, skb);
                sch->q.qlen--;
        //#ifdef PRINT_CALLS
                PRINT_INFO_ARGS("end: classid: %lu -- %d:%d", it->common.classid,
                                TC_H_MAJ(it->common.classid) << 16, TC_H_MIN(it->common.classid));
        //#endif
                return skb;
            }
        }
    }

//#ifdef PRINT_CALLS
    PRINT_INFO("end null (empty even default queue)");
//#endif
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
                PRINT_INFO_ARGS("class %d is destroyed", id);
            } else { PRINT_INFO("cl is NULL"); }
        }
    }
    qdisc_class_hash_destroy(&q->clhash);
}

static int cbwfq_tune(struct Qdisc *sch, struct nlattr *opt)
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
    if (qopt->limit == 0) {
        return -EINVAL;
    }
    sch_tree_lock(sch);
    q->limit = qopt->limit;
    /* ATTENTION: TODO: CHECK OLD LIMIT AND SO ON. */

    sch_tree_unlock(sch);
#ifdef PRINT_CALLS
    PRINT_INFO("and all is okay!");
#endif
    return 0;
}

static int cbwfq_init(struct Qdisc *sch, struct nlattr *opt)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    struct cbwfq_class *cl;
    struct tc_cbwfq_glob *qopt;
    int err;

#ifdef PRINT_CALLS
    PRINT_INFO("begins");
#endif
    if (!opt)
        return -EINVAL;

    err = tcf_block_get(&q->block, &q->filter_list, sch);
    if (err)
        return err;

	PRINT_INFO_ARGS("tcf_block %p, filter_list: %p", q->block, q->filter_list);

    err = qdisc_class_hash_init(&q->clhash);
    if (err < 0)
        return err;

    cl = kmalloc( sizeof(struct cbwfq_class), GFP_KERNEL);
    if (cl == NULL) {
        return  -ENOMEM;
    }

	q->default_queue = cl;

    if (nla_len(opt) >= sizeof(*qopt)) {
        qopt = nla_data(opt);
        cl->limit = qopt->limit;
    } else {
        cl->limit = qdisc_dev(sch)->tx_queue_len;
    }

    cl->common.classid = TC_H_MAKE(1 << 16, 1);

    sch_tree_lock(sch);

    cbwfq_add_class(sch, cl);
    q->limit = qopt->limit;

    sch_tree_unlock(sch);
    return 0;
}

static int cbwfq_dump(struct Qdisc *sch, struct sk_buff *skb)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    unsigned char *b = skb_tail_pointer(skb);
    struct tc_cbwfq_glob opt;
    struct nlattr *nest;

#ifdef PRINT_CALLS
    PRINT_INFO("called");
#endif

    opt.limit= q->limit;
    nest = nla_nest_start(skb, TCA_OPTIONS);
    if (nest == NULL)
        goto nla_put_failure;
    if (nla_put(skb, TCA_HTB_PARMS, sizeof(opt), &opt))
        goto nla_put_failure;
    return nla_nest_end(skb, nest);

    //if (nla_put(skb, TCA_OPTIONS, sizeof(opt), &opt))
    //  goto nla_put_failure;

nla_put_failure:
    nlmsg_trim(skb, b);
    return -1;
}

static int cbwfq_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
              struct Qdisc **old)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    struct cbwfq_class *cl;
    //unsigned long band = arg - 1;
//#ifdef PRINT_CALLS
    PRINT_INFO("called");
//#endif
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

//#ifdef PRINT_CALLS
    PRINT_INFO("called");
//#endif
    //return q->queues[band];
    return cl == NULL? NULL : cl->queue;
}

static unsigned long cbwfq_bind(struct Qdisc *sch, unsigned long parent, u32 classid)
{

//#ifdef PRINT_CALLS
    PRINT_INFO("called");
//#endif
    return cbwfq_find(sch, classid);
}


static void cbwfq_unbind(struct Qdisc *q, unsigned long cl)
{
//#ifdef PRINT_CALLS
    PRINT_INFO("called");
//#endif
}

static int cbwfq_dump_class(struct Qdisc *sch, unsigned long cl,
                            struct sk_buff *skb, struct tcmsg *tcm)
{
    struct cbwfq_class *c = (struct cbwfq_class *)cl;
    struct nlattr *nest;
    struct tc_cbwfq_copt opt;
    
#ifdef PRINT_CALLS
    PRINT_INFO("called");
#endif
    
    if (c == 0) {
        return -1;
    }

    tcm->tcm_handle = c->common.classid;
    tcm->tcm_info = c->queue->handle;

    nest = nla_nest_start(skb, TCA_OPTIONS);
    if (nest == NULL)
        goto failure;

    memset(&opt, 0, sizeof(opt));
    opt.limit = c->limit;
    opt.weight = c->weight;

    if (nla_put(skb, TCA_CBWFQ_PARAMS, sizeof(opt), &opt))
        goto failure;

    return nla_nest_end(skb, nest);

failure:
    nla_nest_cancel(skb, nest);
    return -1;
}

static int cbwfq_dump_class_stats(struct Qdisc *sch, unsigned long cl,
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
    if (gnet_stats_copy_basic(qdisc_root_sleeping_running(sch),
                  d, NULL, &cl_q->bstats) < 0 ||
        gnet_stats_copy_queue(d, NULL, &cl_q->qstats, cl_q->q.qlen) < 0)
            return -1;
    return 0;
}

static void cbwfq_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    struct cbwfq_class *cl;
    int h;

//#ifdef PRINT_CALLS
    PRINT_INFO("called");
//#endif
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

static struct tcf_block *cbwfq_tcf_block(struct Qdisc *sch, unsigned long cl)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    //struct cbwfq_class *c = (struct cbwfq_class *)cl;
//#ifdef PRINT_CALLS
    PRINT_INFO("called");
//#endif
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
    .change     =   cbwfq_tune,
    /* Shows statistics of the queuing discipline. */
    .dump       =   cbwfq_dump,
    .owner      =   THIS_MODULE,
};

static int __init cbwfq_module_init(void)
{
    printk(KERN_ALERT"cbwfq: register!");
    return register_qdisc(&cbwfq_qdisc_ops);
}

static void __exit cbwfq_module_exit(void)
{
    printk(KERN_ALERT"cbwfq: unregister!");
    unregister_qdisc(&cbwfq_qdisc_ops);
}

module_init(cbwfq_module_init)
module_exit(cbwfq_module_exit)

MODULE_LICENSE("GPL");

#if 0

struct cbwfq_class {
    /* Qdisc_class_common:
     *      u32 classid; -- unique id for a class
     *      struct hlist_node hnode; -- double linked list,
     *                                  probably, of sk_buff. 
     * Must be first in the structure.
     */
    struct Qdisc_class_common common;
    struct cbwfq_class *next;

    /* Max number of packets. */
    unsigned int limit;
    /* Currect number of packets. */
    unsigned int qlen;

    /* Filters for separate class. */
    struct tcf_proto __rcu *filter_list;
    struct tcf_block *block;
};

struct cbwfq_sched_data {
    /* User defined classes. */
    struct {
        struct cbwfq_class *head;
        struct cbwfq_class *tail;
    } queues;

    /* Default class. */
    struct cbwfq_class *default;

    
    /* Filters for qdisc itself. */
    struct tcf_proto __rcu *filter_list;
    struct tcf_block *block;

    /* */
};

#endif
