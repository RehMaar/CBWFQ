/* TODO:
 * 1. Dynamic bands.			[+]
 * 2. Separate bands adding.	[ ]
 * 3. Classfull pq.			    [ ]
 * 4. Weighted *pq*.		    [ ]
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

#define PRINT_ALERT(msg) printk(KERN_ALERT"cbwfq: %s: " msg, __FUNCTION__);
#define PRINT_INFO(msg)  printk(KERN_INFO"cbwfq: %s: " msg, __FUNCTION__);
#define PRINT_INFO_ARGS(fmt, args...)  printk(KERN_INFO"cbwfq: %s: " fmt, __FUNCTION__, ##args);

struct cbwfq_class {
    struct Qdisc_class_common common;
	struct Qdisc *queue;
	u8 prio;
};

struct cbwfq_sched_data {

	/* Try to add dynamic amount of bands. */
	struct Qdisc_class_hash clhash;
    
	int bands;
	struct tcf_proto __rcu *filter_list;
	struct tcf_block *block;

	/* Save old for validating. */
	u8  prio2band[TC_PRIO_MAX+1];
	//struct Qdisc *queues[TCQ_PRIO_BANDS];
};

/* ---- Class support. ---- */
static void print_classes(struct cbwfq_sched_data *q) {
	struct cbwfq_class *it;
	int i;

	for (i = 0; i < q->clhash.hashsize; i++) {
		hlist_for_each_entry(it, &q->clhash.hash[i], common.hnode) {
			printk(KERN_ALERT" cbwfq: %s: classid: %d, prio %d, q %p", __FUNCTION__,
                    it->common.classid, it->prio, it->queue
                   );
		}
	}
}

/* Allocate cl outside. */
static void cbwfq_add_class(struct Qdisc *sch, struct cbwfq_class *cl)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);
    PRINT_INFO("called");
	//cl->queue = qdisc_create_dflt(sch->dev_queue,
    //                              &pfifo_qdisc_ops, cl->common.classid);
    qdisc_class_hash_insert(&q->clhash, &cl->common);
}

/* But free cl inside. */
static void cbwfq_destroy_class(struct Qdisc *sch, struct cbwfq_class *cl)
{
    struct cbwfq_sched_data *q = qdisc_priv(sch);

    PRINT_INFO("called");
	qdisc_tree_reduce_backlog(cl->queue, cl->queue->q.qlen,
					  cl->queue->qstats.backlog);
    qdisc_class_hash_remove(&q->clhash, &cl->common);

    if (cl->queue)
        qdisc_destroy(cl->queue);

    kfree(cl);
}

/* In our case classid is prio. */
static inline struct cbwfq_class *
cbwfq_class_lookup(struct cbwfq_sched_data *q, u32 classid)
{
//	struct Qdisc_class_common *clc;
	struct cbwfq_class *it;
	int i;

    PRINT_INFO("called");
	for (i = 0; i < q->clhash.hashsize; i++) {
		hlist_for_each_entry(it, &q->clhash.hash[i], common.hnode) {
			if (classid == it->common.classid)
    			return it;
		}
	}

	// ATTENTION: classid must not be 0.
//	clc = qdisc_class_find(&q->clhash, classid);
//	if (clc == NULL)
//    	return NULL;
//    return container_of(clc, struct cbwfq_class, common);
}

/* Returns pointer to the class. */
static unsigned long cbwfq_find(struct Qdisc *sch, u32 classid)
{
	struct cbwfq_sched_data *q = qdisc_priv(sch);
    PRINT_INFO("called");
	return (unsigned long)cbwfq_class_lookup(q, classid);
}

/* --- Other. --- */

//static const struct nla_policy cbwfq_policy[TCA_CBWFQ_MAX + 1] = {
//	[TCA_CBWFQ_PARMS]	= { .len = sizeof(struct tc_cbwfq_qopt) },
//	[TCA_CBWFQ_INIT]	= { .len = sizeof(struct tc_cbwfq_glob) },
//};

static struct Qdisc *
cbwfq_classify(struct sk_buff *skb, struct Qdisc *sch, int *qerr)
{
	struct cbwfq_sched_data *q = qdisc_priv(sch);
	u32 band = skb->priority;
	struct tcf_result res;
	struct tcf_proto *fl;
	int err;

	PRINT_INFO("called");

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
		if (!fl || err < 0) {
			if (TC_H_MAJ(band))
				band = 0;

			/* band & TC_PRIO_MAX -- priority,
			 * id -- band number. */
			int id = q->prio2band[band & TC_PRIO_MAX];
			//struct Qdisc *t1 = q->queues[id];
			struct cbwfq_class *cl = cbwfq_class_lookup(q, q->prio2band[band & TC_PRIO_MAX]);
			if (cl) { PRINT_INFO_ARGS("class: classid -- %d, prio -- %d, id -- %d", cl->common.classid, cl->prio, id); }
			else { PRINT_INFO_ARGS("class is zero, id: %d", id); }
			return cl == NULL ? NULL : cl->queue;

			//if (t2 == NULL) {
			//	PRINT_INFO("t2 is null");
			//} else if (t1 != t2->queue) {
			//	PRINT_INFO_ARGS("t1(%p)(%d)(%d) != t2(%p)(%d)(%d)", t1, id, band & TC_PRIO_MAX, t2->queue, t2->common.classid, t2->prio);
			//}
			//return t1;
		}
		band = res.classid;
	}

	band = TC_H_MIN(band) - 1;
	if (band >= q->bands)
    	band = q->prio2band[0];

    //struct cbwfq_class *cl = cbwfq_class_lookup(q, band);
    //if (cl == NULL) {
    //    PRINT_INFO("cl is null");
    //} if (q->queues[band] != cl->queue) {;
	//	PRINT_INFO_ARGS("q->queues[band](%d) != cl->queue(%d)", band, cl->common.classid);
    //}
//	if (band >= q->bands) {
//		return q->queues[q->prio2band[0]];

	PRINT_INFO("end");
	//return q->queues[band];
	struct cbwfq_class *cl = cbwfq_class_lookup(q, band);
	//if (cl) { PRINT_INFO_ARGS("class: classid -- %d, prio -- %d, id -- %d", cl->common.classid, cl->prio, band); }
	//else { PRINT_INFO_ARGS("class is zero, id: %d", band); }
	return cl == NULL ? NULL : cl->queue;
}

static int
cbwfq_enqueue(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free)
{
	struct Qdisc *qdisc;
	int ret;

    PRINT_INFO("called");
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
    	PRINT_INFO("end success");
		return NET_XMIT_SUCCESS;
	}
	if (net_xmit_drop_count(ret))
		qdisc_qstats_drop(sch);
	PRINT_INFO("end");
	return ret;
}

static struct sk_buff *cbwfq_peek(struct Qdisc *sch)
{
	struct cbwfq_sched_data *q = qdisc_priv(sch);
	int prio;

	PRINT_INFO("begin");
	for (prio = 0; prio < q->bands; prio++) {

		//struct Qdisc *qdisc = q->queues[prio];
		//struct cbwfq_class *cl = cbwfq_class_lookup(q, prio);
		//if (cl == NULL) {
    	//	PRINT_INFO("cl is NULL");
		//} else if (qdisc != cl->queue) {;
		//	PRINT_INFO_ARGS("qdisc(%d) != cl->queue(%d)", prio, cl->common.classid);
		//}

		struct cbwfq_class *cl = cbwfq_class_lookup(q, prio);
		if (cl) {
    		struct sk_buff *skb = cl->queue->ops->peek(cl->queue);
    		if (skb)
    			return skb;
		}
	}
	PRINT_INFO("end");
	return NULL;
}

static struct sk_buff *cbwfq_dequeue(struct Qdisc *sch)
{
	struct cbwfq_sched_data *q = qdisc_priv(sch);
	int prio;
	PRINT_INFO("begin");

	//print_classes(q);


	for (prio = 0; prio < q->bands; prio++) {

		//struct Qdisc *qdisc = q->queues[prio];
		//struct Qdisc *qdisc2 = q->queues[q->prio2band[prio]];
		//struct cbwfq_class *cl = cbwfq_class_lookup(q, prio);
		//struct cbwfq_class *cl2 = cbwfq_class_lookup(q, q->prio2band[prio]);

		//PRINT_INFO_ARGS("q->prio2band[prio(%d)] = %d", prio, q->prio2band[prio]);
		//if (cl != NULL) {
		//	PRINT_INFO_ARGS("cl1: %p, id: %d, prio: %d", cl->queue, cl->common.classid, cl->prio);
		//}
		//if (cl2 != NULL) {
		//	PRINT_INFO_ARGS("cl2: %p, id: %d, prio: %d", cl2->queue, cl2->common.classid, cl2->prio);
		//}
		//if (qdisc2 != NULL) {
		//	PRINT_INFO_ARGS("qdisc2: %p", qdisc2);
		//}
		//if (qdisc != NULL) {
		//	PRINT_INFO_ARGS("qdisc1: %p", qdisc);
		//}

		//if (cl == NULL) {
		//	PRINT_INFO("cl is null");
		//} else if (qdisc != cl->queue) {;
		//	PRINT_INFO_ARGS("qdisc(%p)(%d) != cl->queue(%p)(%d);", qdisc, prio, cl->queue, cl->common.classid);
		//}

		struct cbwfq_class *cl = cbwfq_class_lookup(q, prio);
		if (cl == NULL)
    		goto out;

		struct sk_buff *skb = qdisc_dequeue_peeked(cl->queue);
		if (skb) {
			qdisc_bstats_update(sch, skb);
			qdisc_qstats_backlog_dec(sch, skb);
			sch->q.qlen--;
        	PRINT_INFO("end");
			return skb;
		}
	}
out:
	PRINT_INFO("end null");
	return NULL;
}

static void
cbwfq_reset(struct Qdisc *sch)
{
	int i;
	struct cbwfq_sched_data *q = qdisc_priv(sch);
	struct cbwfq_class *it;
	//for (p = 0; p < q->bands; p++) {
	//	qdisc_reset(q->queues[p]);
	//}
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
    PRINT_INFO("called");
	tcf_block_put(q->block);
	//for (p = 0; p < q->bands; p++)
	//	qdisc_destroy(q->queues[p]);
	for (i = 0; i < q->clhash.hashsize; i++) {
		hlist_for_each_entry(it, &q->clhash.hash[i], common.hnode) {
			//printk(KERN_ALERT" cbwfq: %s: classid: %d, prio %d, q %p", __FUNCTION__,
            //        it->common.classid, it->prio, it->queue
            //);
			qdisc_destroy(it->queue);
		}
	}
}

static int cbwfq_tune(struct Qdisc *sch, struct nlattr *opt)
{
	struct cbwfq_sched_data *q = qdisc_priv(sch);
	/* Create temp queues. */
	struct Qdisc *queues[TCQ_PRIO_BANDS];
	/* Save old amount of bands. */
	int oldbands = q->bands, i;
	/* Options from user space */
	struct tc_cbwfq_qopt *qopt;

	PRINT_INFO("begins");

	if (nla_len(opt) < sizeof(*qopt)) {
    	PRINT_ALERT("no options are given");
		return -EINVAL;
	}
	qopt = nla_data(opt);

	/* Simple checks. */
	if (qopt->bands > TCQ_PRIO_BANDS || qopt->bands < 2)
		return -EINVAL;

	for (i = 0; i <= TC_PRIO_MAX; i++) {
		if (qopt->priomap[i] >= qopt->bands) {
    		PRINT_ALERT("invalid value: qopt->priomap[i] >= qopt->bands");
			return -EINVAL;
		}
	}

	/* Add new queus if new amount of bands is bigger than the old one. */
	for (i = oldbands; i < qopt->bands; i++) {
		queues[i] = qdisc_create_dflt(sch->dev_queue, &pfifo_qdisc_ops,
					      TC_H_MAKE(sch->handle, i + 1));
		if (!queues[i]) {
			while (i > oldbands)
				qdisc_destroy(queues[--i]);
		    PRINT_ALERT("not enough memory");
			return -ENOMEM;
		}
	}

	sch_tree_lock(sch);
	q->bands = qopt->bands;
	memcpy(q->prio2band, qopt->priomap, TC_PRIO_MAX+1);

	/* Destroy newly unused queues. */
	for (i = q->bands; i < oldbands; i++) {
		//struct Qdisc *child = q->queues[i];
		struct cbwfq_class *cl = cbwfq_class_lookup(q, i);
		if (cl) {
    		qdisc_tree_reduce_backlog(cl->queue, cl->queue->q.qlen,
    					  cl->queue->qstats.backlog);
    		cbwfq_destroy_class(sch, cl);
		}

		//if (cl->queue == child) {
		//	/* All is okay, we could delete things. */
		//	cbwfq_destroy_class(sch, cl);
		//} else {
    	//	PRINT_INFO_ARGS("cl->queue(%d) != child(%d)", cl->common.classid, i);
    	//	qdisc_tree_reduce_backlog(child, child->q.qlen,
    	//				  child->qstats.backlog);
    	//	qdisc_destroy(child);
		//}
	}

	/*
	 *  priomap [1, 2, 3, 1, 1, 3, 4, 5]
	 *  where i -- prioity from 0 to len(priomap) - 1.
	 *        priomap[i] -- band.
	 */

	/* Add newly created. */
	for (i = oldbands; i < q->bands; i++) {
		struct cbwfq_class *cl = kmalloc( sizeof(struct cbwfq_class), GFP_KERNEL);
		if (cl == NULL)
    		return  -ENOMEM;

		cl->common.classid = i;
		cl->queue = queues[i];
		cl->prio  = q->prio2band[i];
		cbwfq_add_class(sch, cl);

		if (cl->queue != &noop_qdisc)
			qdisc_hash_add(cl->queue, true);
		//q->queues[i] = queues[i];
		///* Nothing panics without this lines. Maybe it just increase performance.*/
		//if (q->queues[i] != &noop_qdisc)
		//	qdisc_hash_add(q->queues[i], true);
	}

//	for (i = 0; i < q->bands; i++) {
//    	printk(KERN_ALERT" cbwfq: %s: i: %d, band: %d, q %p", __FUNCTION__,
//               i, q->prio2band[i], q->queues[i]);
//	}

	print_classes(q);
	
	sch_tree_unlock(sch);
	PRINT_INFO("and all is okay!");
	return 0;
}

static int cbwfq_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct cbwfq_sched_data *q = qdisc_priv(sch);
	int err;

    PRINT_INFO("begins");

	if (!opt)
		return -EINVAL;

	err = tcf_block_get(&q->block, &q->filter_list, sch);
	if (err)
		return err;

	err = qdisc_class_hash_init(&q->clhash);
	if (err < 0)
    	return err;

	return cbwfq_tune(sch, opt);
}

static int cbwfq_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct cbwfq_sched_data *q = qdisc_priv(sch);
	unsigned char *b = skb_tail_pointer(skb);
	struct tc_cbwfq_qopt opt;
    PRINT_INFO("called");

	opt.bands = q->bands;
	memcpy(&opt.priomap, q->prio2band, TC_PRIO_MAX + 1);

	if (nla_put(skb, TCA_OPTIONS, sizeof(opt), &opt))
		goto nla_put_failure;

	return skb->len;

nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}

static int cbwfq_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
		      struct Qdisc **old)
{
	struct cbwfq_sched_data *q = qdisc_priv(sch);
	unsigned long band = arg - 1;
    PRINT_INFO("called");

	if (new == NULL)
		new = &noop_qdisc;

	//*old = qdisc_replace(sch, new, &q->queues[band]);
	struct cbwfq_class *cl = cbwfq_class_lookup(q, band);
	if (cl) {
    	*old = qdisc_replace(sch, new, &cl->queue);
	}
	return 0;
}

static struct Qdisc *
cbwfq_leaf(struct Qdisc *sch, unsigned long arg)
{
	struct cbwfq_sched_data *q = qdisc_priv(sch);
	unsigned long band = arg - 1;
	struct cbwfq_class *cl = cbwfq_class_lookup(q, band);

    PRINT_INFO("called");
	//return q->queues[band];
	return cl == NULL? NULL : cl->queue;
}

/* Returns number of band. */
static unsigned long cbwfq_find2(struct Qdisc *sch, u32 classid)
{
	struct cbwfq_sched_data *q = qdisc_priv(sch);
	unsigned long band = TC_H_MIN(classid);

    PRINT_INFO("called");
	if (band - 1 >= q->bands)
		return 0;
	return band;
}

static unsigned long cbwfq_bind(struct Qdisc *sch, unsigned long parent, u32 classid)
{

    PRINT_INFO("called");
	return cbwfq_find(sch, classid);
}


static void cbwfq_unbind(struct Qdisc *q, unsigned long cl)
{
    PRINT_INFO("called");
}

static int cbwfq_dump_class(struct Qdisc *sch, unsigned long cl, struct sk_buff *skb,
			   struct tcmsg *tcm)
{
	struct cbwfq_sched_data *q = qdisc_priv(sch);
	struct cbwfq_class *c = cbwfq_class_lookup(q, cl - 1);
    PRINT_INFO("called");
	
    
	tcm->tcm_handle |= TC_H_MIN(cl);
	//tcm->tcm_info = q->queues[cl-1]->handle;
	tcm->tcm_info = c->queue->handle;
	return 0;
}

static int cbwfq_dump_class_stats(struct Qdisc *sch, unsigned long cl,
				 struct gnet_dump *d)
{
	struct cbwfq_sched_data *q = qdisc_priv(sch);
	struct Qdisc *cl_q;
	struct cbwfq_class *c = cbwfq_class_lookup(q, cl - 1);

    PRINT_INFO("called");

    cl_q = c->queue; 
	//cl_q = q->queues[cl - 1];
	if (gnet_stats_copy_basic(qdisc_root_sleeping_running(sch),
				  d, NULL, &cl_q->bstats) < 0 ||
	    gnet_stats_copy_queue(d, NULL, &cl_q->qstats, cl_q->q.qlen) < 0)
		return -1;

	return 0;
}

static void cbwfq_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	struct cbwfq_sched_data *q = qdisc_priv(sch);
	int p;

    PRINT_INFO("called");
	if (arg->stop)
		return;

	for (p = 0; p < q->bands; p++) {
		if (arg->count < arg->skip) {
			arg->count++;
			continue;
		}
		if (arg->fn(sch, p + 1, arg) < 0) {
			arg->stop = 1;
			break;
		}
		arg->count++;
	}
}

static struct tcf_block *cbwfq_tcf_block(struct Qdisc *sch, unsigned long cl)
{
	struct cbwfq_sched_data *q = qdisc_priv(sch);

    PRINT_INFO("called");
	if (cl)
		return NULL;
	return q->block;
}

static const struct Qdisc_class_ops cbwfq_class_ops = {
    /* Attach a new qdisc to a class and return the prev attached qdisc. */
	.graft		=	cbwfq_graft,
	/* Returns a pointer to the qdisc of class. */
	.leaf		=	cbwfq_leaf,
	/* */
	.find		=	cbwfq_find,
	/* Iterates over all classed of a qdisc */
	.walk		=	cbwfq_walk,
	/* */
	.tcf_block	=	cbwfq_tcf_block,
	/* Binds an instance of a filter to the class. */
	.bind_tcf	=	cbwfq_bind,
	/* Removes an instalce of a filter from the class. */
	.unbind_tcf	=	cbwfq_unbind,
	/* Returns stats for a class*/
	.dump		=	cbwfq_dump_class,
	.dump_stats	=	cbwfq_dump_class_stats,
};

static struct Qdisc_ops cbwfq_qdisc_ops __read_mostly = {
    /* Points to next Qdisc_ops. */
	.next		=	NULL,
	/* Points to structure that provides a set of functions for
	 * a particular class. */
	.cl_ops		=	&cbwfq_class_ops,
	/* Char array contains identity of the qdsic. */
	.id			=	"cbwfq",

	.priv_size	=	sizeof(struct cbwfq_sched_data),
	/* Enqueuing function. */
	.enqueue	=	cbwfq_enqueue,
	/* Dequeuing function. */
	.dequeue	=	cbwfq_dequeue,
	/* Like dequeue, but doesn't delete packet from a queue.*/
	.peek		=	cbwfq_peek,
	/* Initilize new queueing discipline. */
	.init		=	cbwfq_init,
	/* Reset the qdisc back to initial state. */
	.reset		=	cbwfq_reset,
	/* Destroys the resources usef during initilization of the qdisc. */
	.destroy	=	cbwfq_destroy,
	/* Changes values of the parameters of a qdisc. */
	.change		=	cbwfq_tune,
	/* Shows statistics of the queuing discipline. */
	.dump		=	cbwfq_dump,
	.owner		=	THIS_MODULE,
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
     * 		u32 classid; -- unique id for a class
     * 		struct hlist_node hnode; -- double linked list,
     * 									probably, of sk_buff. 
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
