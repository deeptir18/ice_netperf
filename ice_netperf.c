#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <rte_ethdev.h>
#include <ethdev_driver.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_udp.h>

#include "ice/ice_rxtx.h"

#define BURST_SIZE 32

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

struct rte_eth_dev_data *data = (struct rte_eth_dev_data *) 0x1100bb0440;

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
					buf->ol_flags = PKT_TX_IP_CKSUM | PKT_TX_IPV4;
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
	long tmp;

	/* argv[0] is still the program name */
	if (argc < 3) {
		printf("not enough arguments left: %d\n", argc);
		return -EINVAL;
	}

	str_to_ip(argv[2], &my_ip);

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

void map_device_memory(int id, void *addr, size_t size)
{
	char path[64];
	int fd;
	void *va;

	snprintf(path, sizeof(path), "/sys/bus/pci/devices/0000:af:00.0/resource%d", id);
	fd = open(path, O_RDWR);
	va = mmap(addr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (va == MAP_FAILED) {
		printf("error, map failed\n");
		perror("mmap");
	}
	printf("path: %s, va: %p, addr: %p\n", path, va, addr);
	*(volatile int *)addr = *(volatile int *)addr;
	close(fd);
}

/*
 * The main function, which does initialization
 */
int
main(int argc, char *argv[])
{
	int i, args_parsed, res;
	void *addr;

	/* map DPDK memory, there are two chunks */
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

	/* map device memory, two chunks */
	map_device_memory(0, (void *) 0x2101000000, 0x8000000);
	map_device_memory(3, (void *) 0x2109000000, 0x10000);

	args_parsed = 4;

	/* initialize our arguments */
	argc -= args_parsed;
	argv += args_parsed;
	res = parse_netperf_args(argc, argv);
	if (res < 0)
		return 0;

	rte_ether_addr_copy(&data->mac_addrs[0], &my_eth);
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
