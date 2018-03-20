/* MPTCP Scheduler module selector. Highly inspired by tcp_cong.c */

#include <linux/module.h>
#include <net/mptcp.h>

static unsigned char num_segments __read_mostly = 1;
module_param(num_segments, byte, 0644);
MODULE_PARM_DESC(num_segments, "The number of consecutive segments that are part of a burst");

static bool cwnd_limited __read_mostly = 1;
module_param(cwnd_limited, bool, 0644);
MODULE_PARM_DESC(cwnd_limited, "if set to 1, the scheduler tries to fill the congestion-window on all subflows");

static char *subflows_weight="ipadd:weight";
module_param(subflows_weight, charp, 0644);
MODULE_PARM_DESC(subflows_weight, "weight configuration string");

static bool conf_parse __read_mostly = 1;
module_param(conf_parse, bool, 0644);
MODULE_PARM_DESC(conf_parse, "if set to 0, the scheduler bypass configuration parsing");

static char last_conf[160]="init";
// last read weight configuration
static char emp[]="\0";

// private variables used for weighted loadbalancing scheduler
struct iwlbsched_priv {
	unsigned char quota;
	// count the number of segments that are already allocated subflow
	unsigned char weight;
	// the configured weight, quota must always <= weight
};

// getting the private variables
static struct iwlbsched_priv *iwlbsched_get_priv(const struct tcp_sock *tp)
{
	return (struct iwlbsched_priv *)&tp->mptcp->mptcp_sched[0];
}

// separating the mptcp_iwlb_is_available into 2 different functions

// mptcp_is_def_unavailable: subflows that are definitely unavailable, i.e. un established subflows
bool mptcp_iwlb_is_def_unavailable(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	/* Set of states for which we are allowed to send data */
	if (!mptcp_sk_can_send(sk))
		return true;

	/* We do not send data on this subflow unless it is
	 * fully established, i.e. the 4th ack has been received.
	 */
	if (tp->mptcp->pre_established)
		return true;

	if (tp->pf)
		return true;

	return false;
}

// mptcp_is_def_unavailable: subflows that are just temporarily unavailable for sending data
// avoid sending on that kind of subflows for performance reasons
static bool mptcp_iwlb_is_temp_unavailable(struct sock *sk,
				      const struct sk_buff *skb,
				      bool zero_wnd_test)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	unsigned int mss_now, space, in_flight;

	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Loss) {
		/* If SACK is disabled, and we got a loss, TCP does not exit
		 * the loss-state until something above high_seq has been
		 * acked. (see tcp_try_undo_recovery)
		 *
		 * high_seq is the snd_nxt at the moment of the RTO. As soon
		 * as we have an RTO, we won't push data on the subflow.
		 * Thus, snd_una can never go beyond high_seq.
		 */
		if (!tcp_is_reno(tp))
			return true;
		else if (tp->snd_una != tp->high_seq)
			return true;
	}

	if (!tp->mptcp->fully_established) {
		/* Make sure that we send in-order data */
		if (skb && tp->mptcp->second_packet &&
		    tp->mptcp->last_end_data_seq != TCP_SKB_CB(skb)->seq)
			return true;
	}

	/* If TSQ is already throttling us, do not send on this subflow. When
	 * TSQ gets cleared the subflow becomes eligible again.
	 */
	if (test_bit(TSQ_THROTTLED, &tp->tsq_flags))
		return true;

	in_flight = tcp_packets_in_flight(tp);
	/* Not even a single spot in the cwnd */
	if (in_flight >= tp->snd_cwnd)
		return true;

	/* Now, check if what is queued in the subflow's send-queue
	 * already fills the cwnd.
	 */
	space = (tp->snd_cwnd - in_flight) * tp->mss_cache;

	if (tp->write_seq - tp->snd_nxt > space)
		return true;

	if (zero_wnd_test && !before(tp->write_seq, tcp_wnd_end(tp)))
		return true;

	mss_now = tcp_current_mss(sk);

	/* Don't send on this subflow if we bypass the allowed send-window at
	 * the per-subflow level. Similar to tcp_snd_wnd_test, but manually
	 * calculated end_seq (because here at this point end_seq is still at
	 * the meta-level).
	 */
	if (skb && !zero_wnd_test &&
	    after(tp->write_seq + min(skb->len, mss_now), tcp_wnd_end(tp)))
		return true;

	return false;
}

/* Is the sub-socket sk available to send the skb? */
bool mptcp_iwlb_is_available(struct sock *sk, const struct sk_buff *skb,
			bool zero_wnd_test)
{
	return !mptcp_iwlb_is_def_unavailable(sk) &&
	       !mptcp_iwlb_is_temp_unavailable(sk, skb, zero_wnd_test);
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

/* We just look for any subflows that is available */
static struct sock *iwlb_get_available_subflow(struct sock *meta_sk,
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
			    mptcp_iwlb_is_available(sk, skb, zero_wnd_test))
				return sk;
		}
	}

	/* First, find the best subflow */
	mptcp_for_each_sk(mpcb, sk) {
		struct tcp_sock *tp = tcp_sk(sk);

		if (!mptcp_iwlb_is_available(sk, skb, zero_wnd_test))
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
static struct sk_buff *__mptcp_iwlb_next_segment(const struct sock *meta_sk, int *reinject)
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

// improve the scheduling algorithm for better performance
static struct sk_buff *mptcp_iwlb_next_segment(struct sock *meta_sk,
					     int *reinject,
					     struct sock **subsk,
					     unsigned int *limit)
{
	const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *sk_it, *choose_sk = NULL;
	struct sk_buff *skb = __mptcp_iwlb_next_segment(meta_sk, reinject);

	//@y5er: init weight
	unsigned char weight = 1;
	unsigned char quota = 0;
	unsigned char split = weight;
	// split: the max number of segments to be allocated to a subflow
	// limit: the max number of bytes to be allocated to a subflow
	unsigned char iter = 0, full_subs = 0;
	unsigned char nconf = 0, ntok =0, conf_update=0;
	char *conf, *tok, *stok;
	char subflow_saddr[20];

	u32 rank = 0;
	u32 minRank = 0xffffffff;
	unsigned int space, in_flight;

	/* As we set it, we have to reset it as well. */
	*limit = 0;

	if (!skb)
		return NULL;

	if (*reinject) {
		*subsk = iwlb_get_available_subflow(meta_sk, skb, false);
		if (!*subsk)
			return NULL;

		return skb;
	}

	/*
	if (mpcb->cnt_subflows == 1) {
		sk = (struct sock *)mpcb->connection_list;
		if (!mptcp_iwlb_is_available(sk, skb, false))
			sk = NULL;
		*subsk = sk;
		return skb;
	}
	*/

	// check for updates in the weight configuration file
	conf_update = strncmp(subflows_weight,last_conf,strlen(subflows_weight));

	if ( conf_update && conf_parse)
	{
		//mptcp_debug(" weight update , conf_update = %d \n", conf_update);
		strcpy(last_conf,subflows_weight);
		conf = last_conf;

		//mptcp_debug(" last_conf %s \n", last_conf);

		tok = strsep(&conf,"|");

		while (tok != NULL)
		{
			ntok++;
			stok = strsep(&tok,":");

			mptcp_for_each_sk(mpcb, sk_it) {
				struct tcp_sock *tp_it = tcp_sk(sk_it);
				struct iwlbsched_priv *wsp = iwlbsched_get_priv(tp_it);

				snprintf(subflow_saddr,16,"%pI4",&((struct inet_sock *)tp_it)->inet_saddr);

				if ( strcmp(subflow_saddr,stok) )
					continue;

				stok = strsep(&tok,":");
				sscanf(stok, "%hhu", &wsp->weight);

				//mptcp_debug(" subflow %d with ip %s and weight = %s \n", tp_it->mptcp->path_index,subflow_saddr,stok);
				nconf++;
			}
			tok = strsep(&conf,"|");
		}
		// mptcp_debug(" ntok %d, nconf %d, nsubflow %d ",ntok, nconf, mpcb->cnt_subflows );
		if ( (ntok > mpcb->cnt_subflows) && (nconf < mpcb->cnt_subflows) )
			strcpy(last_conf,emp);
	}

retry:

	iter = 0;
	full_subs = 0;
	/* First, we look for a subflow which is currently being used */
	mptcp_for_each_sk(mpcb, sk_it) {
		struct tcp_sock *tp_it = tcp_sk(sk_it);
		struct iwlbsched_priv *wsp = iwlbsched_get_priv(tp_it);

		if (mptcp_iwlb_is_def_unavailable(sk_it))
			continue;

		iter++;

		// this will cause the iter > full_sub when there are subflow is temporary unavailable
		// not considering sending packet on temporary unavailable subflows
		// but waiting for them -not reset quota - to respect the configured weight

		// how about the case that subflow tmp unavailable and also full quota
		if (mptcp_iwlb_is_temp_unavailable(sk_it, skb, false))
		{
			mptcp_debug(" temp_unavailable \n");
			continue;
		}

		weight = wsp->weight;
		quota = wsp->quota;
		rank = 0xffffffff;

		in_flight = tcp_packets_in_flight(tp_it);
		space = tp_it->snd_cwnd - in_flight;

		// flow ranking, select subflow with min rank

		/* Is this subflow currently being used? */
		if (quota > 0 && quota < weight) {
			split = weight - quota;

			if ( split > space )
				rank = 0 + 1/tp_it->srtt_us;
			else if ( split <= space )
				rank = 1 + 1/tp_it->srtt_us;
		}

		/* Or, it's totally unused */
		if (quota == 0 && weight) {
			split = weight;
			if ( split > space )
				rank = 2 + 1/tp_it->srtt_us;
			else if ( split <= space )
				rank = 3 + 1/tp_it->srtt_us;
		}

		if (rank < minRank )
		{
			minRank = rank;
			choose_sk = sk_it;
		}

		/* Or, it must then be fully used  */
		if (quota >= weight)
			full_subs++;

	}

	// there is subflow that is not fully used and temporarily unavailable
	// go to retry and wait for that subflow to be available again
	// sacrifice performance to respect the configured weight
	if (iter && iter > full_subs && !choose_sk)
	{
		mptcp_debug(" waiting for temp unavailable subflow  \n");
		goto retry;
	}

	// all considered subflows have full quota, and we considered at least one.
	if (iter && iter == full_subs) {
		// reset quota to 0 for all available subflows
		mptcp_for_each_sk(mpcb, sk_it) {
			struct tcp_sock *tp_it = tcp_sk(sk_it);
			struct iwlbsched_priv *wsp = iwlbsched_get_priv(tp_it);

			if (mptcp_iwlb_is_def_unavailable(sk_it))
				continue;

			wsp->quota = 0;
		}
		goto retry;
	}

	if (choose_sk) {

		unsigned int mss_now;
		struct tcp_sock *choose_tp = tcp_sk(choose_sk);
		struct iwlbsched_priv *wsp = iwlbsched_get_priv(choose_tp);

		if (!mptcp_iwlb_is_available(choose_sk, skb, false))
			return NULL;

		*subsk = choose_sk;

		mss_now = tcp_current_mss(*subsk);
		*limit = split * mss_now;

		mptcp_debug(" rank %d, minRank %d, quota %d , weight %d \n",rank, minRank, wsp->quota, wsp->weight );

		// update the quota
		if (skb->len > mss_now)
			wsp->quota += DIV_ROUND_UP(skb->len, mss_now);
		else
			wsp->quota++;

		return skb;
	}
	return NULL;
}

static void iwlbsched_init(struct sock *sk)
{
	struct tcp_sock *tp	= tcp_sk(sk);
	struct iwlbsched_priv *wsp = iwlbsched_get_priv(tp);
	mptcp_debug("scheduler init, subflow source address:%pI4 \n",&((struct inet_sock *)tp)->inet_saddr);
}

static struct mptcp_sched_ops mptcp_sched_iwlb = {
	.get_subflow = iwlb_get_available_subflow,
	.next_segment = mptcp_iwlb_next_segment,
	.init = iwlbsched_init,
	.name = "iweightedlb",
	.owner = THIS_MODULE,
};


static int __init iwlb_register(void)
{
	BUILD_BUG_ON(sizeof(struct iwlbsched_priv) > MPTCP_SCHED_SIZE);
	if (mptcp_register_scheduler(&mptcp_sched_iwlb))
		return -1;

	return 0;
}

static void iwlb_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_sched_iwlb);
}

module_init(iwlb_register);
module_exit(iwlb_unregister);

MODULE_AUTHOR("Duy Nguyen");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("IWEIGHTEDLB MPTCP");
MODULE_VERSION("0.91");
