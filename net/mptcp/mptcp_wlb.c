/* MPTCP Scheduler module selector. Highly inspired by tcp_cong.c */

#include <linux/module.h>
#include <net/mptcp.h>

static unsigned char num_segments __read_mostly = 1;
module_param(num_segments, byte, 0644);
MODULE_PARM_DESC(num_segments, "The number of consecutive segments that are part of a burst");

static bool cwnd_limited __read_mostly = 1;
module_param(cwnd_limited, bool, 0644);
MODULE_PARM_DESC(cwnd_limited, "if set to 1, the scheduler tries to fill the congestion-window on all subflows");

//TODO @y5er: add an initial weight variable
// the max number of segments that a sub-flow can send in its turn, if quota >= weight its turn is over

//static unsigned char wlb_weight __read_mostly = 10;
//module_param(wlb_weight, byte, 0644);
//MODULE_PARM_DESC(wlb_weight, "The initial weight associated to all active subflows ");

//@y5er: update for demo
//latter on we will define a proper approach for assigning weight to each subflow
static unsigned char wlb_weight1 __read_mostly = 10;
module_param(wlb_weight1, byte, 0644);
MODULE_PARM_DESC(wlb_weight1, "The initial weight associated to all active subflows from NIC#1");

static unsigned char wlb_weight2 __read_mostly = 10;
module_param(wlb_weight2, byte, 0644);
MODULE_PARM_DESC(wlb_weight2, "The initial weight associated to all active subflows from NIC#2");


// TODO @y5er:change struct name from rrsched_priv to wlbsched_priv
struct wlbsched_priv {
	unsigned char quota;
	//TODO @y5er: beside the quota, each subflow maintains a weight
	// and the quota must always <= weight
	unsigned char weight;
};

// TODO @y5er:change function name from rrsched_get_priv to wlbsched_get_priv
static struct wlbsched_priv *wlbsched_get_priv(const struct tcp_sock *tp)
{
	return (struct wlbsched_priv *)&tp->mptcp->mptcp_sched[0];
}

/* If the sub-socket sk available to send the skb? */
static bool mptcp_wlb_is_available(const struct sock *sk, const struct sk_buff *skb,
				  bool zero_wnd_test, bool cwnd_test)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	unsigned int space, in_flight;

	/* Set of states for which we are allowed to send data */
	if (!mptcp_sk_can_send(sk))
		return false;

	/* We do not send data on this subflow unless it is
	 * fully established, i.e. the 4th ack has been received.
	 */
	if (tp->mptcp->pre_established)
		return false;

	if (tp->pf)
		return false;

	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Loss) {
		/* If SACK is disabled, and we got a loss, TCP does not exit
		 * the loss-state until something above high_seq has been acked.
		 * (see tcp_try_undo_recovery)
		 *
		 * high_seq is the snd_nxt at the moment of the RTO. As soon
		 * as we have an RTO, we won't push data on the subflow.
		 * Thus, snd_una can never go beyond high_seq.
		 */
		if (!tcp_is_reno(tp))
			return false;
		else if (tp->snd_una != tp->high_seq)
			return false;
	}

	if (!tp->mptcp->fully_established) {
		/* Make sure that we send in-order data */
		if (skb && tp->mptcp->second_packet &&
		    tp->mptcp->last_end_data_seq != TCP_SKB_CB(skb)->seq)
			return false;
	}

	if (!cwnd_test)
		goto zero_wnd_test;

	in_flight = tcp_packets_in_flight(tp);
	/* Not even a single spot in the cwnd */
	if (in_flight >= tp->snd_cwnd)
		return false;

	/* Now, check if what is queued in the subflow's send-queue
	 * already fills the cwnd.
	 */
	space = (tp->snd_cwnd - in_flight) * tp->mss_cache;

	if (tp->write_seq - tp->snd_nxt > space)
		return false;

zero_wnd_test:
	if (zero_wnd_test && !before(tp->write_seq, tcp_wnd_end(tp)))
		return false;

	return true;
}

/* Are we not allowed to reinject this skb on tp? */
static int mptcp_wlb_dont_reinject_skb(const struct tcp_sock *tp, const struct sk_buff *skb)
{
	/* If the skb has already been enqueued in this sk, try to find
	 * another one.
	 */
	return skb &&
		/* Has the skb already been enqueued into this subsocket? */
		mptcp_pi_to_flag(tp->mptcp->path_index) & TCP_SKB_CB(skb)->path_mask;
}

/* We just look for any subflow that is available */
static struct sock *wlb_get_available_subflow(struct sock *meta_sk,
					     struct sk_buff *skb,
					     bool zero_wnd_test)
{
	const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *sk, *bestsk = NULL, *backupsk = NULL;

	/* Answer data_fin on same subflow!!! */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
	    skb && mptcp_is_data_fin(skb)) {
		mptcp_for_each_sk(mpcb, sk) {
			if (tcp_sk(sk)->mptcp->path_index == mpcb->dfin_path_index &&
			    mptcp_wlb_is_available(sk, skb, zero_wnd_test, true))
				return sk;
		}
	}

	/* First, find the best subflow */
	mptcp_for_each_sk(mpcb, sk) {
		struct tcp_sock *tp = tcp_sk(sk);

		if (!mptcp_wlb_is_available(sk, skb, zero_wnd_test, true))
			continue;

		if (mptcp_wlb_dont_reinject_skb(tp, skb)) {
			backupsk = sk;
			continue;
		}
		bestsk = sk;
	}

	if (bestsk) {
		sk = bestsk;
		mptcp_debug("MPTCP weightedLB scheduler : found best subflow \n");
	} else if (backupsk) {
		/* It has been sent on all subflows once - let's give it a
		 * chance again by restarting its pathmask.
		 */
		if (skb)
			TCP_SKB_CB(skb)->path_mask = 0;
		sk = backupsk;
	}

	return sk;
}

/* Returns the next segment to be sent from the mptcp meta-queue.
 * (chooses the reinject queue if any segment is waiting in it, otherwise,
 * chooses the normal write queue).
 * Sets *@reinject to 1 if the returned segment comes from the
 * reinject queue. Sets it to 0 if it is the regular send-head of the meta-sk,
 * and sets it to -1 if it is a meta-level retransmission to optimize the
 * receive-buffer.
 */
static struct sk_buff *__mptcp_wlb_next_segment(const struct sock *meta_sk, int *reinject)
{
	const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sk_buff *skb = NULL;

	*reinject = 0;

	/* If we are in fallback-mode, just take from the meta-send-queue */
	if (mpcb->infinite_mapping_snd || mpcb->send_infinite_mapping)
		return tcp_send_head(meta_sk);

	skb = skb_peek(&mpcb->reinject_queue);

	if (skb)
		*reinject = 1;
	else
		skb = tcp_send_head(meta_sk);
	return skb;
}

static struct sk_buff *mptcp_wlb_next_segment(struct sock *meta_sk,
					     int *reinject,
					     struct sock **subsk,
					     unsigned int *limit)
{
	const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *sk_it, *choose_sk = NULL;
	struct sk_buff *skb = __mptcp_wlb_next_segment(meta_sk, reinject);
	//TODO @y5er: change the intial value of split to initial weight, since we are not using num_segments
	unsigned char split = num_segments;
	// @y5er: what are the roles of split and limit variables ?
	// the value of limit is updated according to the value of split
	unsigned char iter = 0, full_subs = 0;

	/* As we set it, we have to reset it as well. */
	*limit = 0;

	if (!skb)
		return NULL;

	if (*reinject) {
		*subsk = wlb_get_available_subflow(meta_sk, skb, false);
		if (!*subsk)
			return NULL;

		return skb;
	}

retry:

	/* First, we look for a subflow who is currently being used */
	mptcp_for_each_sk(mpcb, sk_it) {
		struct tcp_sock *tp_it = tcp_sk(sk_it);
		struct wlbsched_priv *rsp = wlbsched_get_priv(tp_it);

		if (!mptcp_wlb_is_available(sk_it, skb, false, cwnd_limited))
			continue;

		iter++;

		/* Is this subflow currently being used? */
		// TODO @y5er: we change the codition here
		// rsp->quota < rsp->weight
		// and split =  rsp->weight - rsp->quota
		if (rsp->quota > 0 && rsp->quota < rsp->weight) {
			split = rsp->weight - rsp->quota;
			choose_sk = sk_it;
			goto found;
		}

		/* Or, it's totally unused */
		// TODO @y5er: if the subflow is totally unused
		// split = rsp->weight
		if (!rsp->quota) {
			split = rsp->weight;
			choose_sk = sk_it;
		}

		//TODO @y5er: replace num_segments by rsp->weight
		/* Or, it must then be fully used  */
		if (rsp->quota >= rsp->weight)
			full_subs++;

		//@y5er: this code segment helps to select the subflow for allocating the next segment
		// only one subflow will be selected, and choose_sk points to that subflow
	}

	/* All considered subflows have a full quota, and we considered at
	 * least one.
	 */
	if (iter && iter == full_subs) {
		/* So, we restart this round by setting quota to 0 and retry
		 * to find a subflow.
		 */
		mptcp_for_each_sk(mpcb, sk_it) {
			struct tcp_sock *tp_it = tcp_sk(sk_it);
			struct wlbsched_priv *rsp = wlbsched_get_priv(tp_it);

			if (!mptcp_wlb_is_available(sk_it, skb, false, cwnd_limited))
				continue;

			rsp->quota = 0;
		}

		goto retry;
	}

found:
	if (choose_sk) {
		unsigned int mss_now;
		struct tcp_sock *choose_tp = tcp_sk(choose_sk);
		struct wlbsched_priv *rsp = wlbsched_get_priv(choose_tp);

		if (!mptcp_wlb_is_available(choose_sk, skb, false, true))
			return NULL;

		*subsk = choose_sk;
		// @y5er: the subsk pointer is updated, point to selected subflow choose_sk
		// mptcp_wlb_next_segment() not only decides the next segment to be sent
		// but also deciding which subflow send that segment

		mss_now = tcp_current_mss(*subsk);
		*limit = split * mss_now;
		// @y5er: we know that split = num_segments - rsp->quota;
		// split determine the max number of segments that the selected subflow can be allocated
		// so limit = split * mss_now = max number of bytes can be allocated to selected subflow

		// update the quota
		if (skb->len > mss_now)
			rsp->quota += DIV_ROUND_UP(skb->len, mss_now);
			// skb->len / mss_now = number of segments to be allocated
			// update the subflow's quota with the number of segments to be sent
		else
			rsp->quota++;

		return skb;
	}

	return NULL;
}

//TODO: y5er: add a new init function to initialize the weight for each subflow
// Q: Need to go throught all the sub-sockets and init the weight ? -> NO
// A: Since the init function will be called once a new socket is created

// Q: How to ensure that the input of init function will be a correct meta_sk ?
// A: The input of init function is a sub-flow socket not the meta_sk

// Q: How to identify the subflow ? and init the corresponding weight
// A: Now we just simplify by init the weight increasingly, 1st subflow is w, 2nd is w+1 and so on
static void wlbsched_init(struct sock *sk)
{
	struct wlbsched_priv *wsp = wlbsched_get_priv(tcp_sk(sk));

		// wsp->weight = wlb_weight;
		// wlb_weight++;
		// wlb_weight = wlb_weight*2; // try to double the weight, easier to evaluate the load on each sub-flow
		// mptcp_debug("Subflow weight %d \n",wsp->weight);
		// @y5er: we start with a simple logic
		// when a first subflow is created, its weight is set to the wlb_weight
		// after that whenever a new sub-flow is established, wlb_weight is increased by one then assigned to the sub-flow
		// later subflows have higher weights that earlier subflows

		// just for testing purpose to see how the init function and the modified version of rr_next_segment works
		// @y5er: update for demo
		// setting weight according to path index
		struct sock *sk = (struct sock *)tp;
		if (tp->mptcp->path_index == 1)
			wsp->weight = wlb_weight1;
		else if (tp->mptcp->path_index == 2)
			wsp->weight = wlb_weight2;
}

static struct mptcp_sched_ops mptcp_sched_wlb = {
	.get_subflow = wlb_get_available_subflow,
	.next_segment = mptcp_wlb_next_segment,
	// @y5er: add call to init function
	.init = wlbsched_init,
	.name = "weightedlb",
	.owner = THIS_MODULE,
};

//TODO @y5er: change the function name from rr_fncname to wlb_fncname
static int __init wlb_register(void)
{
	BUILD_BUG_ON(sizeof(struct wlbsched_priv) > MPTCP_SCHED_SIZE);

	if (mptcp_register_scheduler(&mptcp_sched_wlb))
		return -1;

	return 0;
}

static void wlb_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_sched_wlb);
}

module_init(wlb_register);
module_exit(wlb_unregister);

MODULE_AUTHOR("Duy Nguyen");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("WEIGHTEDLB MPTCP");
MODULE_VERSION("0.91");
