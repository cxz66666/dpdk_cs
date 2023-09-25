#ifndef CLIENT_CONFIG
#define CLIENT_CONFIG

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>

#define RTE_TEST_RX_DESC_DEFAULT 8192
#define RTE_TEST_TX_DESC_DEFAULT 8192

#define RX_QUEUE 1
#define TX_QUEUE 1

#define MAX_QUEUE_PER_LCORE 1

#define RECEIVE_TYPE 0
#define TRANSMIT_TYPE 1

#define MEMPOOL_CACHE_SIZE 256

// bf2 mac addr
struct rte_ether_addr DST_ADDR = {{0x02, 0xe3, 0xc3, 0xe8, 0xba, 0x3c}};

// host2 mac addr
// struct rte_ether_addr DST_ADDR = {{0xa0, 0x88, 0xc2, 0x31, 0xf7, 0xde}};

static uint8_t rss_key[40] = {0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
                              0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
                              0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
                              0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
                              0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa};

struct lcore_queue_conf
{
    uint8_t type; // 0 is rx and 1 is tx
    unsigned n_rx_queue;
    unsigned rx_queue_list[MAX_QUEUE_PER_LCORE];
    unsigned n_tx_queue;
    unsigned tx_queue_list[MAX_QUEUE_PER_LCORE];
} __rte_cache_aligned;

struct Object_0 {
    uint8_t data[0];
};

struct Object_8
{
    uint8_t data[8];
    /* data */
};

struct Object_16
{
    uint8_t data[16];
    /* data */
};

struct Object_32
{
    uint8_t data[32];
    /* data */
};

struct Object_64
{
    uint8_t data[64];
    /* data */
} __rte_cache_aligned;

struct Object_128
{
    uint8_t data[128];
    /* data */
} __rte_cache_aligned;

struct Object_256
{
    uint8_t data[256];
    /* data */
} __rte_cache_aligned;

struct Object_512
{
    uint8_t data[512];
    /* data */
} __rte_cache_aligned;

struct Object_1024
{
    uint8_t data[1024];
    /* data */
} __rte_cache_aligned;

#endif