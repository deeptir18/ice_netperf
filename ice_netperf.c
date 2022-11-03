#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <ethdev_driver.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_udp.h>

#include "ice/ice_rxtx.h"

#define BURST_SIZE 32
#define MBUF_BUF_SIZE RTE_ETHER_MAX_JUMBO_FRAME_LEN + RTE_PKTMBUF_HEADROOM
#define NUM_MBUFS 8000
#define MBUF_CACHE_SIZE 250
#define RX_RING_SIZE 2048
#define TX_RING_SIZE 2048
#define RX_PACKET_LEN 1024
#define RX_PTHRESH 8
#define RX_HTHRESH 8
#define RX_WTHRESH 0
#define TX_PTHRESH 0
#define TX_HTHRESH 0
#define TX_WTHRESH 0

uint32_t kMagic = 0x6e626368; // 'nbch'

struct nbench_req {
  uint32_t magic;
  int nports;
};

struct nbench_resp {
  uint32_t magic;
  int nports;
  uint16_t ports[];
};

enum {
	MODE_UDP_CLIENT = 0,
	MODE_UDP_SERVER,
};

#define MAKE_IP_ADDR(a, b, c, d)			\
	(((uint32_t) a << 24) | ((uint32_t) b << 16) |	\
	 ((uint32_t) c << 8) | (uint32_t) d)

static unsigned int dpdk_port = 0;
static uint8_t mode;
static struct rte_ether_addr my_eth;
static uint32_t my_ip;
static size_t payload_len;
static unsigned int num_queues = 1;
uint16_t next_port = 50000;
struct rte_mempool *mbuf_pool;

// struct rte_eth_dev_data *data = (struct rte_eth_dev_data *) 0x1100bb0440;
// struct rte_eth_dev_data *data = (struct rte_eth_dev_data *) 0x01003b0440;
struct rte_eth_dev_data *data;

/* ice_netperf.c: simple implementation of netperf server for ice-compatible NICs */

static int str_to_ip(const char *str, uint32_t *addr)
{
	uint8_t a, b, c, d;
	if(sscanf(str, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) != 4) {
		return -EINVAL;
	}

	*addr = MAKE_IP_ADDR(a, b, c, d);
	return 0;
}

/*
 * Validate this ethernet header. Return true if this packet is for higher
 * layers, false otherwise.
 */
static bool check_eth_hdr(struct rte_mbuf *buf)
{
	struct rte_ether_hdr *ptr_mac_hdr;

	ptr_mac_hdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
	if (!rte_is_same_ether_addr(&ptr_mac_hdr->dst_addr, &my_eth) &&
			!rte_is_broadcast_ether_addr(&ptr_mac_hdr->dst_addr)) {
		/* packet not to our ethernet addr */
		return false;
	}

	if (ptr_mac_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
		/* packet not IPv4 */
		return false;

	return true;
}

/*
 * Return true if this IP packet is to us and contains a UDP packet,
 * false otherwise.
 */
static bool check_ip_hdr(struct rte_mbuf *buf)
{
	struct rte_ipv4_hdr *ipv4_hdr;

	ipv4_hdr = rte_pktmbuf_mtod_offset(buf, struct rte_ipv4_hdr *,
			RTE_ETHER_HDR_LEN);
	if (ipv4_hdr->dst_addr != rte_cpu_to_be_32(my_ip)
			|| ipv4_hdr->next_proto_id != IPPROTO_UDP)
		return false;

	return true;
}

/*
 * Run a netperf server
 */
static int do_server(void)
{
	uint8_t port = dpdk_port;
	struct rte_mbuf *rx_bufs[BURST_SIZE];
	struct rte_mbuf *tx_bufs[BURST_SIZE];
	struct rte_mbuf *buf;
	uint16_t nb_rx, n_to_tx, nb_tx, i, j, q;
	struct ice_rx_queue *rxq;
	struct ice_tx_queue *txq;
	struct rte_ether_hdr *ptr_mac_hdr;
	struct rte_ether_addr src_addr;
	struct rte_ipv4_hdr *ptr_ipv4_hdr;
	uint32_t src_ip_addr;
	uint16_t tmp_port;
	struct nbench_req *control_req;
	struct nbench_resp *control_resp;

	printf("on server core with num_queues: %d\n", num_queues);
	printf("\nRunning in server mode. [Ctrl+C to quit]\n");

	/* Run until the application is quit or killed. */
	for (;;) {
		for (q = 0; q < num_queues; q++) {

			/* receive packets */
			rxq = data->rx_queues[q];
			nb_rx = ice_recv_pkts(rxq, rx_bufs, BURST_SIZE);

			if (nb_rx == 0)
				continue;

			printf("Nb_rx: %d\n", nb_rx);
			n_to_tx = 0;
			for (i = 0; i < nb_rx; i++) {
				buf = rx_bufs[i];

				if (!check_eth_hdr(buf))
					goto free_buf;

				/* this packet is IPv4, check IP header */
				if (!check_ip_hdr(buf))
					goto free_buf;

				/* swap src and dst ether addresses */
				ptr_mac_hdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
				rte_ether_addr_copy(&ptr_mac_hdr->src_addr, &src_addr);
				rte_ether_addr_copy(&ptr_mac_hdr->dst_addr, &ptr_mac_hdr->src_addr);
				rte_ether_addr_copy(&src_addr, &ptr_mac_hdr->dst_addr);

				/* swap src and dst IP addresses */
				ptr_ipv4_hdr = rte_pktmbuf_mtod_offset(buf, struct rte_ipv4_hdr *,
								RTE_ETHER_HDR_LEN);
				src_ip_addr = ptr_ipv4_hdr->src_addr;
				ptr_ipv4_hdr->src_addr = ptr_ipv4_hdr->dst_addr;
				ptr_ipv4_hdr->dst_addr = src_ip_addr;

				/* swap UDP ports */
				struct rte_udp_hdr *rte_udp_hdr;
				rte_udp_hdr = rte_pktmbuf_mtod_offset(buf, struct rte_udp_hdr *,
								RTE_ETHER_HDR_LEN + sizeof(struct rte_ipv4_hdr));
				tmp_port = rte_udp_hdr->src_port;
				rte_udp_hdr->src_port = rte_udp_hdr->dst_port;
				rte_udp_hdr->dst_port = tmp_port;

				/* check if this is a control message and we need to reply with
				 * ports */
				control_req = rte_pktmbuf_mtod_offset(buf, struct nbench_req *,
								RTE_ETHER_HDR_LEN + sizeof(struct rte_ipv4_hdr) +
								sizeof(struct rte_udp_hdr));
				if (control_req->magic == kMagic) {
					rte_pktmbuf_append(buf, sizeof(struct nbench_resp) +
							sizeof(uint16_t) *
							control_req->nports -
							sizeof(struct nbench_req));
					control_resp = (struct nbench_resp *) control_req;

					/* add ports to response */
					for (j = 0; j < control_req->nports; j++) {
						/* simple port allocation */
						control_resp->ports[j] = rte_cpu_to_be_16(next_port++);
					}

					/* adjust lengths in UDP and IPv4 headers */
					payload_len = sizeof(struct nbench_resp) +
						sizeof(uint16_t) * control_req->nports;
					rte_udp_hdr->dgram_len = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) +
									payload_len);
					ptr_ipv4_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) +
										sizeof(struct rte_udp_hdr) + payload_len);

					/* enable computation of IPv4 checksum in hardware */
					ptr_ipv4_hdr->hdr_checksum = 0;
					/* lengths filled in by ice_rxtx.c */
					buf->ol_flags = RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4;
				}

				tx_bufs[n_to_tx++] = buf;
				continue;

			free_buf:
				/* packet wasn't sent, free it */
				rte_pktmbuf_free(buf);
			}

			/* transmit packets */
			nb_tx = 0;
			txq = data->tx_queues[q];
			for (j = 0; j < n_to_tx; j++)
				nb_tx += ice_xmit_pkt(txq, tx_bufs[j]);

			if (nb_tx != n_to_tx)
				printf("error: could not transmit all packets: %d %d\n",
					n_to_tx, nb_tx);
		}
	}

	return 0;
}

static int parse_netperf_args(int argc, char *argv[])
{
/*
	if (argc < 3) {
		printf("not enough arguments left: %d\n", argc);
		return -EINVAL;
	}
*/
	str_to_ip("192.168.1.11", &my_ip);
	mode = MODE_UDP_SERVER;
/*
	if (!strcmp(argv[1], "UDP_SERVER")) {
		mode = MODE_UDP_SERVER;
		argc -= 3;
		if (argc >= 1) {
			if (sscanf(argv[3], "%u", &num_queues) != 1)
				return -EINVAL;
		}
	} else {
		printf("invalid mode '%s'\n", argv[1]);
		return -EINVAL;
	}
*/
	return 0;
}

void map_page(int id, void *addr)
{
	char path[64];
	int fd;
	void *va;

	snprintf(path, sizeof(path), "/dev/hugepages/rtemap_%d", id);
	fd = open(path, O_CREAT | O_RDWR, 0600);
	va = mmap(addr, 0x200000, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_POPULATE | MAP_FIXED, fd, 0);
	if (va == MAP_FAILED) {
		printf("error, map failed\n");
		perror("mmap");
	}
	printf("path: %s, va: %p, addr: %p\n", path, va, addr);
	*(volatile int *)addr = *(volatile int *)addr;
	close(fd);
}

void map_device_memory(int id, void *addr, size_t size, int additional_flags)
{
	char path[64];
	int fd;
	void *va;

	snprintf(path, sizeof(path), "/sys/bus/pci/devices/0000:81:00.1/resource%d", id);
	fd = open(path, O_RDWR);
	printf("fd: %d\n", fd);
	va = mmap(addr, size, PROT_READ | PROT_WRITE, MAP_SHARED | additional_flags, fd, 0);
	if (va == MAP_FAILED) {
		printf("error, map failed\n");
		perror("mmap");
	}
	printf("path: %s, va: %p, addr: %p\n", path, va, addr);
	*(volatile int *)addr = *(volatile int *)addr;
	close(fd);
}

int init_port(int port_id, struct rte_mempool *mbuf_pool) {
	printf("Initializing port %u\n", (unsigned)(port_id));
	const uint16_t rx_rings = 1;
	const uint16_t tx_rings = 1;
	const uint16_t nb_rxd = RX_RING_SIZE;
	const uint16_t nb_txd = TX_RING_SIZE;
	uint16_t mtu;
    
	struct rte_eth_dev_info dev_info = {};
    	rte_eth_dev_info_get(port_id, &dev_info);
    	rte_eth_dev_set_mtu(port_id, RX_PACKET_LEN);
    	rte_eth_dev_get_mtu(port_id, &mtu);
        printf("Dev info MTU:%u\n", mtu);
   	struct rte_eth_conf port_conf = {};
    	port_conf.rxmode.max_lro_pkt_size = RX_PACKET_LEN;
            
    	// port_conf.rxmode.offloads = DEV_RX_OFFLOAD_JUMBO_FRAME | RTE_ETH_RX_OFFLOAD_TIMESTAMP;
    	// port_conf.txmode.offloads = DEV_TX_OFFLOAD_MULTI_SEGS | DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM;
   	port_conf.txmode.offloads = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
	port_conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;

    	struct rte_eth_rxconf rx_conf = {};
    	rx_conf.rx_thresh.pthresh = RX_PTHRESH;
    	rx_conf.rx_thresh.hthresh = RX_HTHRESH;
    	rx_conf.rx_thresh.wthresh = RX_WTHRESH;
    	rx_conf.rx_free_thresh = 32;

    	struct rte_eth_txconf tx_conf = {};
    	tx_conf.tx_thresh.pthresh = TX_PTHRESH;
    	tx_conf.tx_thresh.hthresh = TX_HTHRESH;
    	tx_conf.tx_thresh.wthresh = TX_WTHRESH;

    	// configure the ethernet device.
    	rte_eth_dev_configure(port_id, rx_rings, tx_rings, &port_conf);

    	int socket_id = rte_eth_dev_socket_id(port_id);

    	// allocate and set up 1 RX queue per Ethernet port.
    	for (uint16_t i = 0; i < rx_rings; ++i) {
		rte_eth_rx_queue_setup(port_id, i, nb_rxd, socket_id, &rx_conf, mbuf_pool);
	}

    	// allocate and set up 1 TX queue per Ethernet port.
    	for (uint16_t i = 0; i < tx_rings; ++i) {
       		rte_eth_tx_queue_setup(port_id, i, nb_txd, socket_id, &tx_conf);
    	}

    	// start the ethernet port.
    	int dev_start_ret = rte_eth_dev_start(port_id);
    	if (dev_start_ret != 0) {
        	printf("Failed to start ethernet for prot %u\n", (unsigned)port_id);
    	}
}

/*
 * The main function, which does initialization
 */
int
main(int argc, char *argv[])
{
	int i, args_parsed, res;
	void *addr;

	int status = rte_eal_init(argc, argv);
	if (status < 0) {
		printf("failed rte_eal_init: %d\n", status);
	}
/*	 map DPDK memory, there are two chunks
	addr = (void *) 0x100200000;
	for (i = 0; i < 64; i++) {
		map_page(i, addr);
		addr += 0x200000;
	}
	addr = (void *) 0x1100a00000;
	for (i = 32768; i < 32793; i++) {
		map_page(i, addr);
		addr += 0x200000;
	}
*/
	/* map device memory, two chunks */
//	printf("Map device memory. Chunk 1. Id 0.\n");
//	map_device_memory(0, (void *) 0x2101000000, 0x8000000);
//	map_device_memory(0, (void *) 0x555555dc1f24, 0x8000000, -10880);
//	printf("Map device memory. Chunk 2. Id 3.\n");
//	map_device_memory(3, (void *) 0x2109000000, 0x10000);
//	map_device_memory(3, (void *) 0x0, 0x10000, 0);

/*	args_parsed = 4;
	argc -= args_parsed;
	argv += args_parsed;
*/
	res = parse_netperf_args(argc, argv);
	if (res < 0)
		return 0;

	const uint16_t nbports = rte_eth_dev_count_avail();
	printf("Number of ports available: %d\n", nbports);
	if (nbports <= 0) {
		printf("No ports available\n");
		return -1;	
	}

	// get port id
	printf("is port 0 valid: %d\n", rte_eth_dev_is_valid_port(0));

	// PROGRESS: confirmed that port 0 is the port we are looking for. There is only 1 port available.
	
	// 8000 is number of mbufs in the pool. These mbufs are ref counted and 
	// added to the pool again once they are done being used for rx/tx a packet.
	// 250 is the mbuf_cache_size. 250 in testpmd and dpdk-netperf
	mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NUM_MBUFS, MBUF_CACHE_SIZE, 0, MBUF_BUF_SIZE, rte_socket_id());
	printf("socket id from rte_socket_id: %d\n", rte_socket_id());
	printf("socket id from rte_eth_dev_socket_id: %d\n", rte_eth_dev_socket_id(0));	
	
	init_port(0, mbuf_pool);
	
	data = &rte_eth_devices[0];
	rte_ether_addr_copy(&data->mac_addrs[0], &my_eth); // same as rte_eth_macaddr_get()
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			(unsigned) dpdk_port,
			my_eth.addr_bytes[0], my_eth.addr_bytes[1],
			my_eth.addr_bytes[2], my_eth.addr_bytes[3],
			my_eth.addr_bytes[4], my_eth.addr_bytes[5]);

	if (mode == MODE_UDP_CLIENT)
		printf("ERROR, only server mode is supported\n");
	else
		do_server();

	return 0;
}
