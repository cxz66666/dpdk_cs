/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#include "config.h"

static volatile bool force_quit;

#define OBJECT_TEST Object_256

#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

#define MAX_PKT_BURST 256
/*
 * Configurable number of RX/TX ring descriptors
 */

static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

#define nb_rx_queue RX_QUEUE
#define nb_tx_queue TX_QUEUE

/* ethernet addresses of ports */
static struct rte_ether_addr l2fwd_ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
static uint32_t l2fwd_enabled_port_mask = 1;

struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.split_hdr_size = 0,
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
		.offloads = DEV_RX_OFFLOAD_RSS_HASH | DEV_RX_OFFLOAD_CHECKSUM,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = rss_key,
			.rss_key_len = 40,
			.rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP,
		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
		.offloads = DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM,
	},
};

struct rte_mempool *bandwidth_pktmbuf_pool = NULL;

/* Per-port statistics struct */
struct bandwidth_port_statistics
{
	uint64_t tx[nb_tx_queue];
	uint64_t rx[nb_rx_queue];
	uint64_t tx_dropped[nb_tx_queue];
} __rte_cache_aligned;
struct bandwidth_port_statistics port_statistics[RTE_MAX_ETHPORTS];
struct bandwidth_port_statistics port_statistics_period[RTE_MAX_ETHPORTS];

/* A tsc-based timer responsible for triggering statistics printout */
static uint64_t timer_period = 1; /* default period is 1 seconds */

/* Print out statistics on packets tx_dropped */
static void
print_stats(void)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	uint64_t period_packets_dropped, period_packets_tx, period_packets_rx;

	unsigned portid, queueid;
	uint64_t period = timer_period / rte_get_timer_hz();

	const char clr[] = {27, '[', '2', 'J', '\0'};
	const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};

	/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\nPort statistics ====================================");

	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
	{
		total_packets_dropped = 0;
		total_packets_tx = 0;
		total_packets_rx = 0;
		period_packets_dropped = 0;
		period_packets_tx = 0;
		period_packets_rx = 0;
		/* skip disabled ports */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("\nStatistics for port %u ------------------------------", portid);
		for (queueid = 0; queueid < nb_rx_queue; queueid++)
		{
			printf("\n     Queue %u --------------------------------------"
				   "\n     Packets sent: %24" PRIu64
				   "\n     Packets received: %20" PRIu64
				   "\n     Packets tx_dropped: %18" PRIu64,
				   queueid,
				   port_statistics[portid].tx[queueid],
				   port_statistics[portid].rx[queueid],
				   port_statistics[portid].tx_dropped[queueid]);
			total_packets_dropped += port_statistics[portid].tx_dropped[queueid];
			total_packets_tx += port_statistics[portid].tx[queueid];
			total_packets_rx += port_statistics[portid].rx[queueid];

			period_packets_dropped += port_statistics[portid].tx_dropped[queueid] - port_statistics_period[portid].tx_dropped[queueid];
			period_packets_tx += port_statistics[portid].tx[queueid] - port_statistics_period[portid].tx[queueid];
			period_packets_rx += port_statistics[portid].rx[queueid] - port_statistics_period[portid].rx[queueid];
		}

		printf("\nTotal for port %u ------------------------------"
			   "\nPackets sent: %24" PRIu64
			   "\nPackets received: %20" PRIu64
			   "\nPackets tx_dropped: %18" PRIu64,
			   portid,
			   total_packets_tx,
			   total_packets_rx,
			   total_packets_dropped);

		printf("\nPeriod statistics ==============================="
			   "\nPackets sent speed: %18" PRIu64
			   "\nPackets received speed: %14" PRIu64
			   "\nPackets tx_dropped speed: %12" PRIu64,
			   period_packets_tx / period,
			   period_packets_rx / period,
			   period_packets_dropped / period);
		printf("\n====================================================\n");
		memcpy(&port_statistics_period[portid], &port_statistics[portid], sizeof(port_statistics[portid]));
	}

	fflush(stdout);
}

static void
l2fwd_main_lcore_show_status(void)
{
	uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
	unsigned lcore_id;

	prev_tsc = 0;
	timer_tsc = 0;
	lcore_id = rte_lcore_id();
	if (lcore_id != rte_get_main_lcore())
	{
		RTE_LOG(INFO, L2FWD, "lcore %u don't be main lcore\n", lcore_id);
		return;
	}

	while (!force_quit)
	{
		cur_tsc = rte_rdtsc();

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		/* if timer is enabled */
		if (timer_period > 0)
		{

			/* advance the timer */
			timer_tsc += diff_tsc;

			/* if timer has reached its timeout */
			if (unlikely(timer_tsc >= timer_period))
			{

				print_stats();
				/* reset the timer */
				timer_tsc = 0;
			}
		}

		prev_tsc = cur_tsc;
	}
}

static void
bandwidth_send_package(unsigned portid, struct lcore_queue_conf *qconf)
{
	unsigned i, j, queueid;
	struct rte_mbuf *pkt[MAX_PKT_BURST];
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ip_hdr;
	struct rte_udp_hdr *udp_hdr;
	struct OBJECT_TEST *msg;
	struct OBJECT_TEST object_test;
	rte_be16_t package_id = 0;
	while (!force_quit)
	{
		for (i = 0; i < qconf->n_tx_queue; i++)
		{
			queueid = qconf->tx_queue_list[i];
			for (j = 0; j < MAX_PKT_BURST; j++)
			{
				pkt[j] = rte_pktmbuf_alloc(bandwidth_pktmbuf_pool);
				pkt[j]->l2_len = sizeof(struct rte_ether_hdr);
				pkt[j]->l3_len = sizeof(struct rte_ipv4_hdr);
				pkt[j]->l4_len = sizeof(struct rte_udp_hdr);
				pkt[j]->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;

				eth_hdr = rte_pktmbuf_mtod(pkt[j], struct rte_ether_hdr *);
				eth_hdr->d_addr = DST_ADDR;
				eth_hdr->s_addr = l2fwd_ports_eth_addr[portid];
				eth_hdr->ether_type = RTE_BE16(0x0800);

				ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
				ip_hdr->version_ihl = 0x45;
				ip_hdr->type_of_service = 0;
				ip_hdr->total_length = RTE_BE16(sizeof(struct OBJECT_TEST) + sizeof(struct rte_udp_hdr) + sizeof(struct rte_ether_hdr));
				ip_hdr->packet_id = RTE_BE16(package_id++);
				ip_hdr->fragment_offset = RTE_BE16(0);
				ip_hdr->time_to_live = 64;
				ip_hdr->next_proto_id = IPPROTO_UDP;
				ip_hdr->src_addr = RTE_BE16(rte_rand_max(UINT32_MAX));
				ip_hdr->dst_addr = RTE_BE16(rte_rand_max(UINT32_MAX));

				udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
				udp_hdr->dgram_len = RTE_BE16(sizeof(struct OBJECT_TEST) + sizeof(struct rte_udp_hdr));
				udp_hdr->src_port = RTE_BE16(rte_rand_max(UINT16_MAX));
				udp_hdr->dst_port = RTE_BE16(rte_rand_max(UINT16_MAX));
				udp_hdr->dgram_cksum = rte_ipv4_phdr_cksum(ip_hdr, pkt[j]->ol_flags);
				ip_hdr->hdr_checksum = 0;

				msg = (struct OBJECT_TEST *)(udp_hdr + 1);
				memcpy(msg, &object_test, sizeof(object_test));

				int pkt_size = sizeof(struct OBJECT_TEST) + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr);
				pkt[j]->data_len = pkt_size;
				pkt[j]->pkt_len = pkt_size;
			}
			uint16_t nb_tx = rte_eth_tx_burst(portid, queueid, pkt, MAX_PKT_BURST);
			port_statistics[portid].tx[queueid] += nb_tx;
			port_statistics[portid].tx_dropped[queueid] += MAX_PKT_BURST - nb_tx;
			for (j = 0; j < MAX_PKT_BURST; j++)
			{
				rte_pktmbuf_free(pkt[j]);
			}
		}
	}
}

static void bandwidth_receive_package(unsigned portid, struct lcore_queue_conf *qconf)
{
	unsigned i, j, queueid, nb_rx;
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];

	while (!force_quit)
	{
		/*
		 * Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_queue; i++)
		{

			queueid = qconf->rx_queue_list[i];
			nb_rx = rte_eth_rx_burst(portid, queueid,
									 pkts_burst, MAX_PKT_BURST);

			port_statistics[portid].rx[queueid] += nb_rx;

			for (j = 0; j < nb_rx; j++)
			{
				rte_pktmbuf_free(pkts_burst[j]);
			}
		}
	}
}

/* main processing loop */
static void
l2fwd_main_loop(void)
{
	unsigned lcore_id;
	struct lcore_queue_conf *qconf;

	lcore_id = rte_lcore_id();
	qconf = &lcore_queue_conf[lcore_id];

	if (qconf->n_rx_queue + qconf->n_tx_queue == 0)
	{
		RTE_LOG(INFO, L2FWD, "lcore %u has nothing to do\n", lcore_id);
		return;
	}

	switch (qconf->type)
	{
	case RECEIVE_TYPE:
		bandwidth_receive_package(0, qconf);
		break;
	case TRANSMIT_TYPE:
		bandwidth_send_package(0, qconf);
		break;

	default:
		RTE_LOG(INFO, L2FWD, "illegal type %d\n", qconf->type);
	}
}

static int
l2fwd_launch_one_lcore(__rte_unused void *dummy)
{

	if (rte_lcore_id() == rte_get_main_lcore())
	{
		l2fwd_main_lcore_show_status();
	}
	else
	{
		l2fwd_main_loop();
	}
	return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */
	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	int ret;
	char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++)
	{
		if (force_quit)
			return;
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid)
		{
			if (force_quit)
				return;
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0)
			{
				all_ports_up = 0;
				if (print_flag == 1)
					printf("Port %u link get failed: %s\n",
						   portid, rte_strerror(-ret));
				continue;
			}
			/* print link status if flag set */
			if (print_flag == 1)
			{
				rte_eth_link_to_str(link_status_text,
									sizeof(link_status_text), &link);
				printf("Port %d %s\n", portid,
					   link_status_text);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN)
			{
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0)
		{
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1))
		{
			print_flag = 1;
			printf("done\n");
		}
	}
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM)
	{
		printf("\n\nSignal %d received, preparing to exit...\n",
			   signum);
		force_quit = true;
	}
}

int main(int argc, char **argv)
{
	struct lcore_queue_conf *qconf;
	int ret;
	uint16_t nb_ports;
	uint16_t nb_ports_available = 0;
	uint16_t portid;
	unsigned lcore_id, rx_lcore_id;
	unsigned nb_ports_in_mask = 0;
	unsigned int nb_lcores = 0;
	unsigned int nb_mbufs;
	int tx_queue_count = 0, rx_queue_count = 0;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* convert to number of cycles */
	timer_period *= rte_get_timer_hz();

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	/* check port mask to possible port mask */
	if (l2fwd_enabled_port_mask & ~((1 << nb_ports) - 1))
		rte_exit(EXIT_FAILURE, "Invalid portmask; possible (0x%x)\n",
				 (1 << nb_ports) - 1);

	rx_lcore_id = 0;
	qconf = NULL;

	/* Initialize the port/queue configuration of each logical core */
	RTE_ETH_FOREACH_DEV(portid)
	{
		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		while (rx_queue_count < nb_rx_queue || tx_queue_count < nb_tx_queue)
		{
			/* get the lcore_id for this port */
			while (rte_lcore_is_enabled(rx_lcore_id) == 0 || rx_lcore_id == rte_get_main_lcore() ||
				   lcore_queue_conf[rx_lcore_id].n_rx_queue + lcore_queue_conf[rx_lcore_id].n_tx_queue ==
					   MAX_QUEUE_PER_LCORE)
			{
				rx_lcore_id++;
				if (rx_lcore_id >= RTE_MAX_LCORE)
					rte_exit(EXIT_FAILURE, "Not enough cores\n");
			}

			if (qconf != &lcore_queue_conf[rx_lcore_id])
			{
				/* Assigned a new logical core in the loop above. */
				qconf = &lcore_queue_conf[rx_lcore_id];
				nb_lcores++;
			}
			if (rx_queue_count == nb_rx_queue && tx_queue_count == nb_tx_queue)
			{
				continue;
			}
			if (rx_queue_count < nb_rx_queue)
			{
				qconf->type = RECEIVE_TYPE;
				for (int i = 0; rx_queue_count < nb_rx_queue && i < MAX_QUEUE_PER_LCORE; i++)
				{
					qconf->rx_queue_list[i] = rx_queue_count;
					qconf->n_rx_queue++;
					rx_queue_count++;
				}
				printf("Lcore %u: [Receive], queue from %d to %d\n", rx_lcore_id, qconf->rx_queue_list[0], qconf->rx_queue_list[qconf->n_rx_queue - 1]);
			}
			else
			{
				qconf->type = TRANSMIT_TYPE;
				for (int i = 0; tx_queue_count < nb_tx_queue && i < MAX_QUEUE_PER_LCORE; i++)
				{
					qconf->tx_queue_list[i] = tx_queue_count;
					qconf->n_tx_queue++;
					tx_queue_count++;
				}
				printf("Lcore %u: [Transmit], queue from %d to %d\n", rx_lcore_id, qconf->tx_queue_list[0], qconf->tx_queue_list[qconf->n_tx_queue - 1]);
			}
		}
	}

	nb_mbufs = RTE_MAX(nb_ports * (nb_rxd + nb_txd + MAX_PKT_BURST +
								   nb_lcores * MEMPOOL_CACHE_SIZE),
					   131072);
	/* create the mbuf pool */
	bandwidth_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
													 MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
													 rte_socket_id());
	if (bandwidth_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	/* Initialise each port */
	RTE_ETH_FOREACH_DEV(portid)
	{
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_txconf txq_conf;
		struct rte_eth_conf local_port_conf = port_conf;
		struct rte_eth_dev_info dev_info;

		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
		{
			printf("Skipping disabled port %u\n", portid);
			continue;
		}
		nb_ports_available++;

		/* init port */
		printf("Initializing port %u... ", portid);
		fflush(stdout);

		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
					 "Error during getting device (port %u) info: %s\n",
					 portid, strerror(-ret));

		if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |=
				DEV_TX_OFFLOAD_MBUF_FAST_FREE;
		ret = rte_eth_dev_configure(portid, nb_rx_queue, nb_tx_queue, &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
					 ret, portid);

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
											   &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
					 "Cannot adjust number of descriptors: err=%d, port=%u\n",
					 ret, portid);

		ret = rte_eth_macaddr_get(portid,
								  &l2fwd_ports_eth_addr[portid]);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
					 "Cannot get MAC address: err=%d, port=%u\n",
					 ret, portid);

		/* init RX queue */
		fflush(stdout);
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;

		for (int i = 0; i < nb_rx_queue; i++)
		{
			ret = rte_eth_rx_queue_setup(portid, i, nb_rxd,
										 rte_eth_dev_socket_id(portid),
										 &rxq_conf,
										 bandwidth_pktmbuf_pool);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
						 ret, portid);
		}

		/* init TX queue*/
		fflush(stdout);
		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;

		for (int i = 0; i < nb_tx_queue; i++)
		{
			ret = rte_eth_tx_queue_setup(portid, i, nb_txd,
										 rte_eth_dev_socket_id(portid),
										 &txq_conf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
						 ret, portid);
		}

		ret = rte_eth_dev_set_ptypes(portid, RTE_PTYPE_UNKNOWN, NULL,
									 0);
		if (ret < 0)
			printf("Port %u, Failed to disable Ptype parsing\n",
				   portid);
		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
					 ret, portid);

		printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
			   portid,
			   l2fwd_ports_eth_addr[portid].addr_bytes[0],
			   l2fwd_ports_eth_addr[portid].addr_bytes[1],
			   l2fwd_ports_eth_addr[portid].addr_bytes[2],
			   l2fwd_ports_eth_addr[portid].addr_bytes[3],
			   l2fwd_ports_eth_addr[portid].addr_bytes[4],
			   l2fwd_ports_eth_addr[portid].addr_bytes[5]);

		/* initialize port stats */
	}
	memset(&port_statistics, 0, sizeof(port_statistics));
	memset(&port_statistics_period, 0, sizeof(port_statistics_period));

	if (!nb_ports_available)
	{
		rte_exit(EXIT_FAILURE,
				 "All available ports are disabled. Please set portmask.\n");
	}

	check_all_ports_link_status(l2fwd_enabled_port_mask);

	ret = 0;
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(l2fwd_launch_one_lcore, NULL, CALL_MAIN);
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		if (rte_eal_wait_lcore(lcore_id) < 0)
		{
			ret = -1;
			break;
		}
	}

	RTE_ETH_FOREACH_DEV(portid)
	{
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("Closing port %d...", portid);
		ret = rte_eth_dev_stop(portid);
		if (ret != 0)
			printf("rte_eth_dev_stop: err=%d, port=%d\n",
				   ret, portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}

	/* clean up the EAL */
	rte_eal_cleanup();
	printf("Bye...\n");

	return ret;
}
