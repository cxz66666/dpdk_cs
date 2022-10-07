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

#define RTE_TEST_RX_DESC_DEFAULT 16384
#define RTE_TEST_TX_DESC_DEFAULT 16384

#define RX_QUEUE 4
#define TX_QUEUE 4

#define MAX_QUEUE_PER_LCORE 1

#define RECEIVE_TYPE 0
#define TRANSMIT_TYPE 1

#define MEMPOOL_CACHE_SIZE 256

struct rte_ether_addr DST_ADDR = {{0x04, 0x3f, 0x72, 0xde, 0xba, 0x44}};

struct lcore_queue_conf
{
    uint8_t type; // 0 is rx and 1 is tx
    unsigned n_rx_queue;
    unsigned rx_queue_list[MAX_QUEUE_PER_LCORE];
    unsigned n_tx_queue;
    unsigned tx_queue_list[MAX_QUEUE_PER_LCORE];
} __rte_cache_aligned;

struct Object_32
{
    uint8_t data[32];
    /* data */
} __rte_cache_aligned;

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