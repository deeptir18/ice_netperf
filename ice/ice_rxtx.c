/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#include <stdio.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "ice_rxtx.h"

#define ICE_TX_CKSUM_OFFLOAD_MASK (		 \
		PKT_TX_IP_CKSUM |		 \
		PKT_TX_L4_MASK |		 \
		PKT_TX_TCP_SEG |		 \
		PKT_TX_OUTER_IP_CKSUM)

#define ICE_RX_FLEX_ERR0_BITS	\
	((1 << ICE_RX_FLEX_DESC_STATUS0_HBO_S) |	\
	 (1 << ICE_RX_FLEX_DESC_STATUS0_XSUM_IPE_S) |	\
	 (1 << ICE_RX_FLEX_DESC_STATUS0_XSUM_L4E_S) |	\
	 (1 << ICE_RX_FLEX_DESC_STATUS0_XSUM_EIPE_S) |	\
	 (1 << ICE_RX_FLEX_DESC_STATUS0_XSUM_EUDPE_S) |	\
	 (1 << ICE_RX_FLEX_DESC_STATUS0_RXE_S))

/* Rx L3/L4 checksum */
static inline uint64_t
ice_rxd_error_to_pkt_flags(uint16_t stat_err0)
{
	uint64_t flags = 0;

	/* check if HW has decoded the packet and checksum */
	if (unlikely(!(stat_err0 & (1 << ICE_RX_FLEX_DESC_STATUS0_L3L4P_S))))
		return 0;

	if (likely(!(stat_err0 & ICE_RX_FLEX_ERR0_BITS))) {
		flags |= (PKT_RX_IP_CKSUM_GOOD | PKT_RX_L4_CKSUM_GOOD);
		return flags;
	}

	if (unlikely(stat_err0 & (1 << ICE_RX_FLEX_DESC_STATUS0_XSUM_IPE_S)))
		flags |= PKT_RX_IP_CKSUM_BAD;
	else
		flags |= PKT_RX_IP_CKSUM_GOOD;

	if (unlikely(stat_err0 & (1 << ICE_RX_FLEX_DESC_STATUS0_XSUM_L4E_S)))
		flags |= PKT_RX_L4_CKSUM_BAD;
	else
		flags |= PKT_RX_L4_CKSUM_GOOD;

	return flags;
}

static inline void
ice_rxd_to_pkt_fields(struct rte_mbuf *mb,
		      volatile union ice_rx_flex_desc *rxdp)
{
	volatile struct ice_32b_rx_flex_desc_comms *desc =
			(volatile struct ice_32b_rx_flex_desc_comms *)rxdp;
	uint16_t stat_err;

	stat_err = rte_le_to_cpu_16(desc->status_error0);
	if (likely(stat_err & (1 << ICE_RX_FLEX_DESC_STATUS0_RSS_VALID_S))) {
		mb->ol_flags |= PKT_RX_RSS_HASH;
		mb->hash.rss = rte_le_to_cpu_32(desc->rss_hash);
	}
}

uint16_t
ice_recv_pkts(void *rx_queue,
	      struct rte_mbuf **rx_pkts,
	      uint16_t nb_pkts)
{
	struct ice_rx_queue *rxq = rx_queue;
	volatile union ice_rx_flex_desc *rx_ring = rxq->rx_ring;
	volatile union ice_rx_flex_desc *rxdp;
	union ice_rx_flex_desc rxd;
	struct ice_rx_entry *sw_ring = rxq->sw_ring;
	struct ice_rx_entry *rxe;
	struct rte_mbuf *nmb; /* new allocated mbuf */
	struct rte_mbuf *rxm; /* pointer to store old mbuf in SW ring */
	uint16_t rx_id = rxq->rx_tail;
	uint16_t nb_rx = 0;
	uint16_t nb_hold = 0;
	uint16_t rx_packet_len;
	uint16_t rx_stat_err0;
	uint64_t dma_addr;
	uint64_t pkt_flags;

	while (nb_rx < nb_pkts) {
		rxdp = &rx_ring[rx_id];
		rx_stat_err0 = rte_le_to_cpu_16(rxdp->wb.status_error0);

		/* Check the DD bit first */
		if (!(rx_stat_err0 & (1 << ICE_RX_FLEX_DESC_STATUS0_DD_S)))
			break;

		/* allocate mbuf */
		nmb = rte_mbuf_raw_alloc(rxq->mp);
		if (unlikely(!nmb)) {
			printf("ERROR: RX MBUF ALLOC FAILED\n"); // TODO: log instead
			break;
		}
		rxd = *rxdp; /* copy descriptor in ring to temp variable*/

		nb_hold++;
		rxe = &sw_ring[rx_id]; /* get corresponding mbuf in SW ring */
		rx_id++;
		if (unlikely(rx_id == rxq->nb_rx_desc))
			rx_id = 0;
		rxm = rxe->mbuf;
		rxe->mbuf = nmb;
		dma_addr =
			rte_cpu_to_le_64(rte_mbuf_data_iova_default(nmb));

		/**
		 * fill the read format of descriptor with physic address in
		 * new allocated mbuf: nmb
		 */
		rxdp->read.hdr_addr = 0;
		rxdp->read.pkt_addr = dma_addr;

		/* calculate rx_packet_len of the received pkt */
		rx_packet_len = (rte_le_to_cpu_16(rxd.wb.pkt_len) &
				 ICE_RX_FLX_DESC_PKT_LEN_M) - rxq->crc_len;

		/* fill old mbuf with received descriptor: rxd */
		rxm->data_off = RTE_PKTMBUF_HEADROOM;
		rte_prefetch0(RTE_PTR_ADD(rxm->buf_addr, RTE_PKTMBUF_HEADROOM));
		rxm->nb_segs = 1;
		rxm->next = NULL;
		rxm->pkt_len = rx_packet_len;
		rxm->data_len = rx_packet_len;
		rxm->port = rxq->port_id;
		ice_rxd_to_pkt_fields(rxm, &rxd);
		pkt_flags = ice_rxd_error_to_pkt_flags(rx_stat_err0);
		rxm->ol_flags |= pkt_flags;
		/* copy old mbuf to rx_pkts */
		rx_pkts[nb_rx++] = rxm;
	}
	rxq->rx_tail = rx_id;
	/**
	 * If the number of free RX descriptors is greater than the RX free
	 * threshold of the queue, advance the receive tail register of queue.
	 * Update that register with the value of the last processed RX
	 * descriptor minus 1.
	 */
	nb_hold = (uint16_t)(nb_hold + rxq->nb_rx_hold);
	if (nb_hold > rxq->rx_free_thresh) {
		rx_id = (uint16_t)(rx_id == 0 ?
				   (rxq->nb_rx_desc - 1) : (rx_id - 1));
		/* write TAIL register */
		ICE_PCI_REG_WRITE(rxq->qrx_tail, rx_id);
		nb_hold = 0;
	}
	rxq->nb_rx_hold = nb_hold;

	/* return received packet in the burst */
	return nb_rx;
}

static inline void
ice_txd_enable_checksum(uint64_t ol_flags,
			uint32_t *td_cmd,
			uint32_t *td_offset)
{
	/* Set MACLEN */
	*td_offset |= (RTE_ETHER_HDR_LEN >> 1)
		<< ICE_TX_DESC_LEN_MACLEN_S;

	/* Enable L3 checksum offloads */
	if (ol_flags & PKT_TX_IP_CKSUM) {
		*td_cmd |= ICE_TX_DESC_CMD_IIPT_IPV4_CSUM;
		*td_offset |= (sizeof(struct rte_ipv4_hdr) >> 2) <<
			      ICE_TX_DESC_LEN_IPLEN_S;
	} else if (ol_flags & PKT_TX_IPV4) {
		*td_cmd |= ICE_TX_DESC_CMD_IIPT_IPV4;
		*td_offset |= (sizeof(struct rte_ipv4_hdr) >> 2) <<
			      ICE_TX_DESC_LEN_IPLEN_S;
	}

	/* Enable L4 checksum offloads */
	switch (ol_flags & PKT_TX_L4_MASK) {
	case PKT_TX_TCP_CKSUM:
		*td_cmd |= ICE_TX_DESC_CMD_L4T_EOFT_TCP;
		*td_offset |= (sizeof(struct rte_tcp_hdr) >> 2) <<
			      ICE_TX_DESC_LEN_L4_LEN_S;
		break;
	case PKT_TX_UDP_CKSUM:
		*td_cmd |= ICE_TX_DESC_CMD_L4T_EOFT_UDP;
		*td_offset |= (sizeof(struct rte_udp_hdr) >> 2) <<
			      ICE_TX_DESC_LEN_L4_LEN_S;
		break;
	default:
		break;
	}
}

static inline int
ice_xmit_cleanup(struct ice_tx_queue *txq)
{
	struct ice_tx_entry *sw_ring = txq->sw_ring;
	volatile struct ice_tx_desc *txd = txq->tx_ring;
	uint16_t last_desc_cleaned = txq->last_desc_cleaned;
	uint16_t nb_tx_desc = txq->nb_tx_desc;
	uint16_t desc_to_clean_to;
	uint16_t nb_tx_to_clean;

	/* Determine the last descriptor needing to be cleaned */
	desc_to_clean_to = (uint16_t)(last_desc_cleaned + txq->tx_rs_thresh);
	if (desc_to_clean_to >= nb_tx_desc)
		desc_to_clean_to = (uint16_t)(desc_to_clean_to - nb_tx_desc);

	/* Check to make sure the last descriptor to clean is done */
	desc_to_clean_to = sw_ring[desc_to_clean_to].last_id;
	if (!(txd[desc_to_clean_to].cmd_type_offset_bsz &
	    rte_cpu_to_le_64(ICE_TX_DESC_DTYPE_DESC_DONE))) {
		printf("TX descriptor %4u is not done "
				"(port=%d queue=%d) value=0x%"PRIx64"\n",
				desc_to_clean_to,
				txq->port_id, txq->queue_id,
				txd[desc_to_clean_to].cmd_type_offset_bsz);
		/* Failed to clean any descriptors */
		return -1;
	}

	/* Figure out how many descriptors will be cleaned */
	if (last_desc_cleaned > desc_to_clean_to)
		nb_tx_to_clean = (uint16_t)((nb_tx_desc - last_desc_cleaned) +
					    desc_to_clean_to);
	else
		nb_tx_to_clean = (uint16_t)(desc_to_clean_to -
					    last_desc_cleaned);

	/* The last descriptor to clean is done, so that means all the
	 * descriptors from the last descriptor that was cleaned
	 * up to the last descriptor with the RS bit set
	 * are done. Only reset the threshold descriptor.
	 */
	txd[desc_to_clean_to].cmd_type_offset_bsz = 0;

	/* Update the txq to reflect the last descriptor that was cleaned */
	txq->last_desc_cleaned = desc_to_clean_to;
	txq->nb_tx_free = (uint16_t)(txq->nb_tx_free + nb_tx_to_clean);

	return 0;
}

uint16_t
ice_xmit_pkt(void *tx_queue, struct rte_mbuf *tx_pkt)
{
	struct ice_tx_queue *txq;
	volatile struct ice_tx_desc *tx_ring;
	volatile struct ice_tx_desc *txd;
	struct ice_tx_entry *sw_ring;
	struct ice_tx_entry *txe, *txn;
	uint16_t tx_id;
	uint32_t td_cmd = 0;
	uint32_t td_offset = 0;
	uint32_t td_tag = 0;
	uint16_t tx_last;
	uint64_t buf_dma_addr;
	uint64_t ol_flags;

	txq = tx_queue;
	sw_ring = txq->sw_ring;
	tx_ring = txq->tx_ring;
	tx_id = txq->tx_tail;
	txe = &sw_ring[tx_id];

	/* Check if the descriptor ring needs to be cleaned. */
	if (txq->nb_tx_free < txq->tx_free_thresh)
		ice_xmit_cleanup(txq);
	if (txq->nb_tx_free == 0 && ice_xmit_cleanup(txq) != 0)
		return 0;

	td_cmd = 0;
	ol_flags = tx_pkt->ol_flags;

	if (tx_pkt->nb_segs != 1)
		printf("ERROR assumed only one segment but got %d\n",
			tx_pkt->nb_segs);
	tx_last = (uint16_t) tx_id;

	/* Circular ring */
	if (tx_last >= txq->nb_tx_desc)
		tx_last = (uint16_t)(tx_last - txq->nb_tx_desc);

	/* Enable checksum offloading */
	if (ol_flags & ICE_TX_CKSUM_OFFLOAD_MASK)
		ice_txd_enable_checksum(ol_flags, &td_cmd,
					&td_offset);

	txd = &tx_ring[tx_id];
	txn = &sw_ring[txe->next_id];

	/* Free old mbuf if present */
	if (txe->mbuf)
		rte_pktmbuf_free_seg(txe->mbuf);
	txe->mbuf = tx_pkt;

	/* Setup TX Descriptor */
	buf_dma_addr = rte_mbuf_data_iova(tx_pkt);
	txd->buf_addr = rte_cpu_to_le_64(buf_dma_addr);
	txd->cmd_type_offset_bsz =
		rte_cpu_to_le_64(ICE_TX_DESC_DTYPE_DATA |
		((uint64_t)td_cmd  << ICE_TXD_QW1_CMD_S) |
		((uint64_t)td_offset << ICE_TXD_QW1_OFFSET_S) |
		((uint64_t)tx_pkt->data_len  <<
		 ICE_TXD_QW1_TX_BUF_SZ_S) |
		((uint64_t)td_tag  << ICE_TXD_QW1_L2TAG1_S));

	txe->last_id = tx_last;
	tx_id = txe->next_id;
	txe = txn;

	/* fill the last descriptor with End of Packet (EOP) bit */
	td_cmd |= ICE_TX_DESC_CMD_EOP;
	txq->nb_tx_used++;
	txq->nb_tx_free--;

	/* set RS bit on the last descriptor of one packet */
	if (txq->nb_tx_used >= txq->tx_rs_thresh) {
		td_cmd |= ICE_TX_DESC_CMD_RS;

		/* Update txq RS bit counters */
		txq->nb_tx_used = 0;
	}
	txd->cmd_type_offset_bsz |=
		rte_cpu_to_le_64(((uint64_t)td_cmd) <<
				 ICE_TXD_QW1_CMD_S);

	/* update Tail register */
	ICE_PCI_REG_WRITE(txq->qtx_tail, tx_id);
	txq->tx_tail = tx_id;

	return 1;
}