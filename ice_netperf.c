#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <getopt.h>

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
// 8000 is number of mbufs in the pool. These mbufs are ref counted and 
// added to the pool again once they are done being used for rx/tx a packet.
#define NUM_MBUFS 8000
// 250 is the mbuf_cache_size in testpmd and dpdk-netperf
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
#define IPV4_HDR_OFFSET RTE_ETHER_HDR_LEN
#define UDP_HDR_OFFSET (IPV4_HDR_OFFSET + sizeof(struct rte_ipv4_hdr))
#define PAYLOAD_OFFSET (UDP_HDR_OFFSET + sizeof(struct rte_udp_hdr))

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
	MODE_NOCOPY = 0,
	MODE_COPY,
};

#define MAKE_IP_ADDR(a, b, c, d)			\
	(((uint32_t) a << 24) | ((uint32_t) b << 16) |	\
	 ((uint32_t) c << 8) | (uint32_t) d)

static unsigned int dpdk_port = 0;
static uint8_t mode = MODE_NOCOPY;
static struct rte_ether_addr my_eth;
static uint32_t my_ip;
static size_t payload_len;
static unsigned int num_queues = 1;
static int num_segs = 1;
uint16_t next_port = 50000;
struct rte_mempool *rx_mbuf_pool;
struct rte_mempool *tx_mbuf_pool;

struct rte_eth_dev *dev;
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
    	struct rte_mbuf *tx_seg_bufs[BURST_SIZE * num_segs]; // one buf per tx seg
	struct rte_mbuf *tx_bufs[BURST_SIZE]; // only first seg's buf
	struct rte_mbuf *buf;
	struct rte_mbuf *tx_mbuf;
    	struct rte_mbuf *cur_buf, *prev_buf;
	char *rx_data, *tx_data;
	uint16_t nb_rx, n_to_tx, nb_tx, i, j, k, q;
    	size_t payload_length, payload_len_per_seg, payload_len_remainder;
	struct ice_rx_queue *rxq;
	struct ice_tx_queue *txq;
	struct rte_ether_hdr *ptr_rx_mac_hdr, *ptr_tx_mac_hdr;
	struct rte_ipv4_hdr *ptr_rx_ipv4_hdr, *ptr_tx_ipv4_hdr;
	struct rte_udp_hdr *ptr_rx_udp_hdr, *ptr_tx_udp_hdr;
	struct nbench_req *control_req;
	struct nbench_resp *control_resp;

	printf("on server core with num_queues: %d\n", num_queues);
	printf("\nRunning in server mode. [Ctrl+C to quit]\n");
    	n_to_tx = 0;
	/* Run until the application is quit or killed. */
	for (;;) {
		for (q = 0; q < num_queues; q++) {

			/* receive packets */
			rxq = data->rx_queues[q];
			//nb_rx = ice_recv_pkts(rxq, rx_bufs, BURST_SIZE);

			nb_rx = rte_eth_rx_burst(port, q, rx_bufs, BURST_SIZE);
			if (nb_rx == 0)
				continue;

//			printf("nb_rx: %d\t", nb_rx);
			for (i = 0; i < nb_rx; i++) {
				buf = rx_bufs[i];
                
				if (!check_eth_hdr(buf))
					goto free_buf;

				/* this packet is IPv4, check IP header */
				if (!check_ip_hdr(buf))
					goto free_buf;
                                
				if (mode == MODE_COPY) {

					/* allocate buf in tx mempool and copy rx_buf into it */
					//tx_mbuf = rte_pktmbuf_copy(buf, tx_mbuf_pool, 0, UINT32_MAX);
					tx_mbuf = rte_pktmbuf_alloc(tx_mbuf_pool);
					if (tx_mbuf == NULL) {
						printf("deep copy of rx_mbuf failed\n");
						return -1;
					}
	
					// Payload length is packet len minus headers
	                                payload_length = buf->pkt_len - PAYLOAD_OFFSET;
	                                payload_len_per_seg = payload_length / num_segs;
	                                payload_len_remainder = payload_length % num_segs;

	                                // The first mbuf stores how many segs make up the packet.
	                                tx_mbuf->nb_segs = num_segs;
	                                // The first mbuf contains the header and the first payload seg
	                                tx_mbuf->data_len = PAYLOAD_OFFSET + payload_len_per_seg;
					tx_mbuf->next = NULL;
	
					/* copy rx mbuf data into tx_data */
					tx_data = (char *)(rte_pktmbuf_mtod_offset(tx_mbuf, char *, 0));
					rx_data = (char *)(rte_pktmbuf_mtod_offset(buf, char*, 0));
					rte_memcpy(tx_data, rx_data, PAYLOAD_OFFSET + payload_len_per_seg);

					/* swap src and dst ether addresses -- copy */
                                        ptr_rx_mac_hdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
                                        ptr_tx_mac_hdr = rte_pktmbuf_mtod(tx_mbuf, struct rte_ether_hdr *);
                                        rte_ether_addr_copy(&ptr_rx_mac_hdr->src_addr, &ptr_tx_mac_hdr->dst_addr);
                                        rte_ether_addr_copy(&ptr_rx_mac_hdr->dst_addr, &ptr_tx_mac_hdr->src_addr);

					/* swap src and dst IP addresses -- copy */
                                        ptr_rx_ipv4_hdr = rte_pktmbuf_mtod_offset(buf, struct rte_ipv4_hdr *,
                                                                        IPV4_HDR_OFFSET);
                                        ptr_tx_ipv4_hdr = rte_pktmbuf_mtod_offset(tx_mbuf, struct rte_ipv4_hdr *,
                                                                        IPV4_HDR_OFFSET);
                                        ptr_tx_ipv4_hdr->src_addr = ptr_rx_ipv4_hdr->dst_addr;
                                        ptr_tx_ipv4_hdr->dst_addr = ptr_rx_ipv4_hdr->src_addr;

					/* swap UDP ports */
                                	ptr_rx_udp_hdr = rte_pktmbuf_mtod_offset(buf, struct rte_udp_hdr *,
                                	                                UDP_HDR_OFFSET);
                                	ptr_tx_udp_hdr = rte_pktmbuf_mtod_offset(tx_mbuf, struct rte_udp_hdr *,
                                	                                UDP_HDR_OFFSET);
                                	ptr_tx_udp_hdr->src_port = ptr_rx_udp_hdr->dst_port;
                                	ptr_tx_udp_hdr->dst_port = ptr_rx_udp_hdr->src_port;

					// tx_seg_bufs stores all mbufs for the packets to be transmitted
                                	tx_seg_bufs[n_to_tx * num_segs] = tx_mbuf;
                                	// create the rest of the mbufs for the packet (1 mbuf per seg)
                                	for (k = 1; k < num_segs; k++) {
                                	        cur_buf = rte_pktmbuf_alloc(tx_mbuf_pool);
                                	        // The last seg contains the remainder of the payload
                                	        if (k == num_segs - 1) {
                                	                cur_buf->data_len = payload_len_per_seg + payload_len_remainder;
                                	                cur_buf->next = NULL;
                                	        } else {
                                	                cur_buf->data_len = payload_len_per_seg;
                                	        }

                                	        // copy relevant data from rx mbuf into this seg
                                	        char *tx_data = (char *)(rte_pktmbuf_mtod_offset(cur_buf, char *, 0));
                                	        char *rx_data = (char *)(rte_pktmbuf_mtod_offset(buf, char*,
                                	                                PAYLOAD_OFFSET + payload_len_per_seg * k));
                                	        rte_memcpy(tx_data, rx_data, cur_buf->data_len);

                                	        tx_seg_bufs[n_to_tx * num_segs + k] = cur_buf;
                                	        // set the cur mbuf to be the next seg for the prev mbuf
                                	        prev_buf = tx_seg_bufs[n_to_tx * num_segs + k - 1];
                                	        prev_buf->next = cur_buf;
                                	}
                                	tx_bufs[n_to_tx++] = tx_seg_bufs[n_to_tx * num_segs];
                                	rte_pktmbuf_free(buf); // free rx mbuf
				} else {

					/* swap src and dst ether addresses -- no copy */
					struct rte_ether_addr src_addr;
					ptr_rx_mac_hdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
					rte_ether_addr_copy(&ptr_rx_mac_hdr->src_addr, &src_addr);
					rte_ether_addr_copy(&ptr_rx_mac_hdr->dst_addr, &ptr_rx_mac_hdr->src_addr);
					rte_ether_addr_copy(&src_addr, &ptr_rx_mac_hdr->dst_addr);

					/* swap src and dst IP addresses -- no copy */
					uint32_t src_ip_addr;
					ptr_rx_ipv4_hdr = rte_pktmbuf_mtod_offset(buf, struct rte_ipv4_hdr *,
									IPV4_HDR_OFFSET);
					src_ip_addr = ptr_rx_ipv4_hdr->src_addr;
					ptr_rx_ipv4_hdr->src_addr = ptr_rx_ipv4_hdr->dst_addr;
					ptr_rx_ipv4_hdr->dst_addr = src_ip_addr;

					/* swap UDP ports -- no copy */
					uint16_t tmp_port;
					ptr_rx_udp_hdr = rte_pktmbuf_mtod_offset(buf, struct rte_udp_hdr *,
									UDP_HDR_OFFSET);
					tmp_port = ptr_rx_udp_hdr->src_port;
					ptr_rx_udp_hdr->src_port = ptr_rx_udp_hdr->dst_port;
					ptr_rx_udp_hdr->dst_port = tmp_port;

					tx_bufs[n_to_tx++] = buf;
				}

				continue;

				free_buf:
					/* packet wasn't sent, free it */
					rte_pktmbuf_free(buf);
			}
            
			/* transmit packets */
			nb_tx = 0;
			txq = data->tx_queues[q];
            		if (n_to_tx > 0) {
                		nb_tx += ice_xmit_pkts(txq, tx_bufs, n_to_tx);
                		if (nb_tx != n_to_tx) {
                    			printf("error: could not transmit all packets: %d %d\n",
                        			n_to_tx, nb_tx);
				} else {
					n_to_tx = 0;
//					printf("nb_tx: %u\n", nb_tx);
				}
            		}
				//rte_pktmbuf_free(tx_bufs[j]); -- freeing of tx buf should be done in cleanup
				//nb_tx should be able to return 0 if failed, in which case we retry.
		}
	}
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
        	printf("Failed to start ethernet for port %u\n", (unsigned)port_id);
    	}
}

static int init_dpdk(int argc, char *argv[])
{
        dpdk_port = 0;

        int args_parsed = rte_eal_init(argc, argv);
        if (args_parsed < 0) {
                printf("failed rte_eal_init: %d\n", args_parsed);
		return -1;
        }

        str_to_ip("192.168.1.11", &my_ip);

        const uint16_t nbports = rte_eth_dev_count_avail();
        printf("Number of ports available: %d\n", nbports);
        if (nbports <= 0) {
                printf("No ports available\n");
                return -1;
        }

        if (!rte_eth_dev_is_valid_port(dpdk_port)) {
                printf("port %u is not valid\n", dpdk_port);
        }

        printf("socket id from rte_socket_id: %d\n", rte_socket_id());
        rx_mbuf_pool = rte_pktmbuf_pool_create("rx_mbuf_pool", NUM_MBUFS, MBUF_CACHE_SIZE, 0, MBUF_BUF_SIZE, rte_socket_id());
        tx_mbuf_pool = rte_pktmbuf_pool_create("tx_mbuf_pool", NUM_MBUFS, MBUF_CACHE_SIZE, 0, MBUF_BUF_SIZE, rte_socket_id());
	
	/* port initialization. set up rx/tx queues */
        init_port(dpdk_port, rx_mbuf_pool);

	dev = &rte_eth_devices[0];
//	dev->rx_pkt_burst = ice_recv_pkts;
//	struct rte_eth_fp_ops *fp = &rte_eth_fp_ops[0];
//	fp->rx_pkt_burst = ice_recv_pkts;
        data = dev->data;
        rte_ether_addr_copy(&data->mac_addrs[0], &my_eth); // same as rte_eth_macaddr_get()
        printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
                           " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
                        (unsigned) dpdk_port,
                        my_eth.addr_bytes[0], my_eth.addr_bytes[1],
                        my_eth.addr_bytes[2], my_eth.addr_bytes[3],
                        my_eth.addr_bytes[4], my_eth.addr_bytes[5]);
        return args_parsed;
}

static int parse_args(int argc, char *argv[]) {
	static struct option long_options[] = {
		{"segs", required_argument, NULL, 's'},
		{"copy", no_argument, NULL, 'c'}
	};

	int long_index = 0;
	int opt = 0;
	while ((opt = getopt_long(argc, argv, "s:c", long_options, &long_index)) != -1) {
		switch (opt) {
			case 's':
				num_segs = atoi(optarg);
				if (num_segs < 1) {
					printf("--segs %d is invalid. Number of " 
						"segments must be greater than 1.\n", num_segs);
					printf("Changing number of segments to 1.\n");
					num_segs = 1;
				}
				break;
			case 'c':
				mode = MODE_COPY;
				break;
		}
	}

	if (mode == MODE_NOCOPY && num_segs > 1) {
		printf("If number of segments is more than 1, cannot perform a "
			"no copy echo. Switching mode to MODE_COPY.\n");
		mode = MODE_COPY;
	}
	return 0;
}

/*
 * The main function, which does initialization
 */
int
main(int argc, char *argv[])
{
	int args_parsed = init_dpdk(argc, argv);
	if (args_parsed < 0) {
		return -1;
	}
	argc -= args_parsed;
	argv += args_parsed;

	parse_args(argc, argv);

	do_server();

	return 0;
}
