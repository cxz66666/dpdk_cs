#include "config.h"


static volatile bool force_quit;

static uint32_t NUM_MBUFS = 1024 * 8;
static uint16_t nb_rxd = 1024;
static uint16_t nb_txd = 1024;
static struct rte_eth_conf port_conf = {
    .rxmode = {
        .mtu = RTE_ETHER_MTU,
        .mq_mode = RTE_ETH_MQ_RX_RSS,
        .offloads = RTE_ETH_RX_OFFLOAD_RSS_HASH | RTE_ETH_RX_OFFLOAD_CHECKSUM,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = rss_key,
            .rss_key_len = 40,
            .rss_hf = RTE_ETH_RSS_UDP,
        },
    },

    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,
        .offloads = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_UDP_CKSUM,
    },
};
struct rte_mempool *delay_pktmbuf_pool = NULL;

#define nb_tx_queue 14
#define nb_rx_queue 1
static void
signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n",
            signum);
        force_quit = true;
    }
}

int main() {
    assert(!getuid());

    const char *rte_argv[] = {
       "-m",          "1024", // Max memory in megabytes
       "--proc-type", "primary",
       "--log-level",  "0",
       "-a", "40:00.0",
       NULL };

    int ret = rte_eal_init(8, (char **)rte_argv);

    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");

    unsigned int nb_mbufs;
    uint16_t nb_ports_available = 1;
    uint16_t portid;


    force_quit = false;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);


    nb_mbufs = nb_ports_available * (nb_tx_queue + nb_rx_queue) * NUM_MBUFS;

    /* create the mbuf pool */
    delay_pktmbuf_pool = rte_pktmbuf_pool_create(MEMPOOL_NAME, nb_mbufs,
        MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id());
    if (delay_pktmbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

    RTE_ETH_FOREACH_DEV(portid) {
        struct rte_eth_rxconf rxq_conf;
        struct rte_eth_txconf txq_conf;
        struct rte_eth_conf local_port_conf = port_conf;
        struct rte_eth_dev_info dev_info;

        /* skip ports that are not enabled */
        if (portid != 0) {
            printf("Skipping disabled port %u\n", portid);
            continue;
        }

        /* init port */
        printf("Initializing port %u... ", portid);
        fflush(stdout);

        ret = rte_eth_dev_info_get(portid, &dev_info);
        if (ret != 0)
            rte_exit(EXIT_FAILURE,
                "Error during getting device (port %u) info: %s\n",
                portid, strerror(-ret));

        if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
            local_port_conf.txmode.offloads |=
            RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
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

        ret = rte_eth_promiscuous_disable(portid);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                "Can't set promiscuous: err=%d, port=%u\n",
                ret, portid);

        /* init RX queue */
        fflush(stdout);
        rxq_conf = dev_info.default_rxconf;
        rxq_conf.offloads = local_port_conf.rxmode.offloads;

        for (int i = 0; i < nb_rx_queue; i++) {
            ret = rte_eth_rx_queue_setup(portid, i, nb_rxd,
                rte_eth_dev_socket_id(portid),
                &rxq_conf,
                delay_pktmbuf_pool);
            if (ret < 0)
                rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
                    ret, portid);
        }

        /* init TX queue*/
        fflush(stdout);
        txq_conf = dev_info.default_txconf;
        txq_conf.offloads = local_port_conf.txmode.offloads;

        for (int i = 0; i < nb_tx_queue; i++) {
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

        printf("Start port %u success\n", portid);

        /* initialize port stats */
    }
    while (!force_quit) {
        sleep(1);
    }

    RTE_ETH_FOREACH_DEV(portid) {
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

}