/* MPTCP Scheduler module selector. Highly inspired by tcp_cong.c */

#include <linux/module.h>
#include <net/mptcp.h>

static unsigned char num_segments __read_mostly = 1;
module_param(num_segments, byte, 0644);
MODULE_PARM_DESC(num_segments, "The number of consecutive segments that are part of a burst");

static bool cwnd_limited __read_mostly = 1;
module_param(cwnd_limited, bool, 0644);
MODULE_PARM_DESC(cwnd_limited, "if set to 1, the scheduler tries to fill the congestion-window on all subflows");

//@y5er: add an initial weight variable
// the max number of segments that a sub-flow can send in its turn, if quota >= weight its turn is over

//@y5er: update for demo
//consider the case of having only two NICs, and there is one subflow per NIC
static unsigned char wlb_weight1;
module_param(wlb_weight1, byte, 0644);
MODULE_PARM_DESC(wlb_weight1, "The initial weight associated to all active subflows from NIC#1");

static unsigned char wlb_weight2;
module_param(wlb_weight2, byte, 0644);
MODULE_PARM_DESC(wlb_weight2, "The initial weight associated to all active subflows from NIC#2");

struct wlbsched_priv {
	unsigned char quota;
	// the use of quota is to count the number of segments that already been allocated to a subflow in one round
	// @y5er: beside the quota, each subflow in the weighted lb scheduler maintains its configured weight
	// and the quota must always <= weight
	unsigned char weight;
};

// @y5er: this function support getting the private variables of the weighted lb scheduler
// beside the common variables shared among scheduler implementations, the modular design also allows scheduler to
// define its own private variables to use for its own scheduling logic
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

	//@y5er: defining weight, this weight changes according subflow
	unsigned char weight = 1;
	unsigned char split = weight;
	// split is the max number of segments to be allocated to a subflow
	// while limit is the max number of bytes to be allocated to a subflow
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

	/* First, we look for a subflow which is currently being used */
	mptcp_for_each_sk(mpcb, sk_it) {
		struct tcp_sock *tp_it = tcp_sk(sk_it);
		struct wlbsched_priv *wsp = wlbsched_get_priv(tp_it);

		// @y5er: skip that check, to ensure the load balancing ratio is respect by all subflows
		// we need to wait for unavailable subflows (to become available again)
		// we only reset the quota if all established subflows reach its assigned weights
		// note on iter and full_subs, in case of waiting for unavailable subflow : iter > full_sub
		//if (!mptcp_wlb_is_available(sk_it, skb, false, cwnd_limited))
		//	continue;

		// @y5er: weight assignment, each subflow maintain a different weight value
		if (tp_it->mptcp->path_index == 1)
			weight = wlb_weight1;
		else if (tp_it->mptcp->path_index == 2)
			weight = wlb_weight2;

		iter++;

		/* Is this subflow currently being used? */
		// @y5er: enforce load balancing by adding the constraint wsp->quota < weight
		// and the max number of segment could be allocated to the subflow is split =  weight - wsp->quota
		if (wsp->quota > 0 && wsp->quota < weight) {
			split = weight - wsp->quota;
			choose_sk = sk_it;
			goto found;
		}

		/* Or, it's totally unused */
		// @y5er: if the subflow is totally unused, then split = rsp->weight
		if (!wsp->quota) {
			split = weight;
			choose_sk = sk_it;
		}

		/* Or, it must then be fully used  */
		//@y5er: if the subflow is fully used
		if (wsp->quota >= weight)
			full_subs++;

		//@y5er: the above code segment helps to select the sub-flow for allocating the next segment
		// the choose_sk points to the only selected sub-flow
	}

	// All considered subflows have a full quota, and we considered at least one.
	if (iter && iter == full_subs) {

		// So, we restart this round by setting quota to 0 and retry to find a subflow.
		mptcp_for_each_sk(mpcb, sk_it) {
			struct tcp_sock *tp_it = tcp_sk(sk_it);
			struct wlbsched_priv *wsp = wlbsched_get_priv(tp_it);

			if (!mptcp_wlb_is_available(sk_it, skb, false, cwnd_limited))
				continue;

			wsp->quota = 0;
		}

		goto retry;
	}

found:
	if (choose_sk) {
		unsigned int mss_now;
		struct tcp_sock *choose_tp = tcp_sk(choose_sk);
		struct wlbsched_priv *wsp = wlbsched_get_priv(choose_tp);

		if (!mptcp_wlb_is_available(choose_sk, skb, false, true))
			return NULL;

		*subsk = choose_sk;
		// @y5er: the subsk pointer is updated, point to selected subflow choose_sk
		// mptcp_wlb_next_segment() not only decides the next segment to be sent
		// but also deciding which subflow send that segment

		mss_now = tcp_current_mss(*subsk);
		*limit = split * mss_now;
		// @y5er: split = rsp->weight - rsp->quota; or rsp->weight in case the subflow have not been used before
		// split determine the max number of segments that the selected subflow can be allocated
		// so limit = split * mss_now therefore defines the max number of bytes can be allocated to selected subflow

		//mptcp_debug(" Subflow %d from %pI4 with weight %d is selected, quota = %d \n", choose_tp->mptcp->path_index,&((struct inet_sock *)choose_tp)->inet_saddr,wsp->weight,wsp->quota);
		mptcp_debug(" Subflow %d weight = %d is selected, init weight = %d \n", choose_tp->mptcp->path_index,weight,wsp->weight);

		// update the quota
		if (skb->len > mss_now)
			wsp->quota += DIV_ROUND_UP(skb->len, mss_now);
			// skb->len / mss_now = number of segments to be allocated
			// update the subflow's quota with the number of segments to be sent
		else
			wsp->quota++;

		return skb;
	}

	return NULL;
}

//TODO: y5er: add a new init function to initialize the weight for each subflow
// Q: Need to go through all the sub-sockets and init the weight ? -> NO
// A: Since the init function will be called once a new socket is created

// Q: How to ensure that the input of init function will be a correct meta_sk ?
// A: The input of init function is a sub-flow socket not the meta_sk

// Q: How to identify the subflow ? and init the corresponding weight
static void wlbsched_init(struct sock *sk)
{
	// @y5er: update for demo
	// setting weight according to path index
	/*
	struct tcp_sock *tp	= tcp_sk(sk);
	struct wlbsched_priv *wsp = wlbsched_get_priv(tp);

	if (tp->mptcp->path_index == 1)
		wsp->weight = wlb_weight1;
	else if (tp->mptcp->path_index == 2)
		wsp->weight = wlb_weight2;
	*/
	mptcp_debug("scheduler init \n");
}

static struct mptcp_sched_ops mptcp_sched_wlb = {
	.get_subflow = wlb_get_available_subflow,
	.next_segment = mptcp_wlb_next_segment,
	.init = wlbsched_init,
	.name = "weightedlb",
	.owner = THIS_MODULE,
};


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
