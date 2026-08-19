/*
 * QEMU System Emulator Solaris VNIC support
 *
 * Copyright 2016 Joyent, Inc.
 * Copyright 2026 OmniOS Community Edition (OmniOSce) Association.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "tap_int.h"
#include "qemu/ctype.h"
#include "qemu/cutils.h"

#include <fcntl.h>
#include <libdlpi.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <sys/dlpi.h>
#include <sys/ethernet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stropts.h>

#include "net/net.h"
#include "clients.h"
#include "qemu/option.h"
#include "qemu/main-loop.h"
#include "qemu/error-report.h"

#define	VNIC_BUFSIZE	65536
#define	VNIC_MAX_QUEUES	16

typedef struct VNICState VNICState;

/*
 * State that is shared between all of the queues on a VNIC netdev. There is
 * a single DLPI stream to the underlying VNIC; inbound packets are steered
 * to a queue based on a hash of the flow, and every queue transmits through
 * the same stream.
 */
typedef struct VNICShared {
	dlpi_handle_t	vsh_hdl;
	int		vsh_fd;
	uint_t		vsh_sap;
	int		vsh_nqueues;
	int		vsh_refcnt;
	bool		vsh_rpoll;
	bool		vsh_wpoll;
	uint8_t		vsh_buf[VNIC_BUFSIZE];
	VNICState	*vsh_queues[VNIC_MAX_QUEUES];
} VNICShared;

struct VNICState {
	NetClientState	vns_nc;
	VNICShared	*vns_shared;
};

static void vnic_update_fd_handler(VNICShared *);

static void
vnic_read_poll(VNICShared *vsh, bool enable)
{
	vsh->vsh_rpoll = enable;
	vnic_update_fd_handler(vsh);
}

static void
vnic_write_poll(VNICShared *vsh, bool enable)
{
	vsh->vsh_wpoll = enable;
	vnic_update_fd_handler(vsh);
}

static void
vnic_poll(NetClientState *ncp, bool enable)
{
	VNICState *vsp = DO_UPCAST(VNICState, vns_nc, ncp);
	vnic_read_poll(vsp->vns_shared, true);
	vnic_write_poll(vsp->vns_shared, true);
}

static int
vnic_read_packet(VNICShared *vsh, uint8_t *buf, int len)
{
	struct strbuf sbuf;
	int flags, ret;

	flags = 0;
	sbuf.maxlen = len;
	sbuf.buf = (char *)buf;

	do {
		ret = getmsg(vsh->vsh_fd, NULL, &sbuf, &flags);
	} while (ret == -1 && errno == EINTR);

	if (ret == -1 && errno == EAGAIN) {
		vnic_write_poll(vsh, true);
		return (0);
	}

	if (ret == -1)
		return (-1);

	return (sbuf.len);
}

static int
vnic_write_packet(VNICShared *vsh, const uint8_t *buf, int len)
{
	struct strbuf sbuf;
	int flags, ret;

	flags = 0;
	sbuf.len = len;
	sbuf.buf = (char *)buf;

	do {
		ret = putmsg(vsh->vsh_fd, NULL, &sbuf, flags);
	} while (ret == -1 && errno == EINTR);

	if (ret == -1 && errno == EAGAIN) {
		vnic_write_poll(vsh, true);
		return (0);
	}

	if (ret == -1)
		return (-1);

	return (len);
}

static void
vnic_send_completed(NetClientState *nc, ssize_t len)
{
	VNICState *vsp = DO_UPCAST(VNICState, vns_nc, nc);

	vnic_read_poll(vsp->vns_shared, true);
}

static uint32_t
vnic_hash(uint32_t hash, const uint8_t *buf, size_t len)
{
	while (len-- > 0) {
		hash += *buf++;
		hash += hash << 10;
		hash ^= hash >> 6;
	}

	return (hash);
}

/*
 * Select the queue that should receive an inbound packet. The packet is
 * hashed on the IP flow (addresses and, for TCP and UDP, ports) so that a
 * flow always maps to the same queue, in the same spirit as the steering
 * done by a multi-queue-aware NIC. Non-IP traffic hashes on the MAC
 * addresses. Only queues that the guest has started are candidates; if
 * none have been started yet, queue 0 is used and the packet is left to
 * QEMU's queuing machinery, matching the single-queue behaviour during
 * boot.
 */
static VNICState *
vnic_select_queue(VNICShared *vsh, const uint8_t *buf, size_t len)
{
	VNICState *cand[VNIC_MAX_QUEUES];
	uint32_t hash = 0;
	size_t l3 = 2 * ETHERADDRL + 2;
	uint16_t etype;
	int i, ncand;

	if (vsh->vsh_nqueues == 1)
		return (vsh->vsh_queues[0]);

	ncand = 0;
	for (i = 0; i < vsh->vsh_nqueues; i++) {
		if (qemu_can_send_packet(&vsh->vsh_queues[i]->vns_nc))
			cand[ncand++] = vsh->vsh_queues[i];
	}
	if (ncand == 0)
		return (vsh->vsh_queues[0]);
	if (ncand == 1)
		return (cand[0]);

	if (len < l3)
		return (cand[0]);

	etype = (buf[l3 - 2] << 8) | buf[l3 - 1];
	if (etype == ETHERTYPE_VLAN && len >= l3 + 4) {
		etype = (buf[l3 + 2] << 8) | buf[l3 + 3];
		l3 += 4;
	}

	switch (etype) {
	case ETHERTYPE_IP:
		if (len < l3 + 20)
			goto nonip;
		/* Source and destination IPv4 addresses. */
		hash = vnic_hash(hash, buf + l3 + 12, 8);
		if (buf[l3 + 9] == IPPROTO_TCP ||
		    buf[l3 + 9] == IPPROTO_UDP) {
			size_t l4 = l3 + ((buf[l3] & 0xf) << 2);

			if (len >= l4 + 4)
				hash = vnic_hash(hash, buf + l4, 4);
		}
		break;
	case ETHERTYPE_IPV6:
		if (len < l3 + 40)
			goto nonip;
		/* Source and destination IPv6 addresses. */
		hash = vnic_hash(hash, buf + l3 + 8, 32);
		if (buf[l3 + 6] == IPPROTO_TCP ||
		    buf[l3 + 6] == IPPROTO_UDP) {
			if (len >= l3 + 44)
				hash = vnic_hash(hash, buf + l3 + 40, 4);
		}
		break;
	default:
nonip:
		hash = vnic_hash(hash, buf, 2 * ETHERADDRL);
		break;
	}

	hash += hash << 3;
	hash ^= hash >> 11;
	hash += hash << 15;

	return (cand[hash % ncand]);
}

/* outside world -> VM */
static void
vnic_send(void *opaque)
{
	VNICShared *vsh = opaque;
	int ret;

	do {
		VNICState *vsp;

		ret = vnic_read_packet(vsh, vsh->vsh_buf,
		    sizeof (vsh->vsh_buf));
		if (ret <= 0)
			break;

		vsp = vnic_select_queue(vsh, vsh->vsh_buf, ret);
		ret = qemu_send_packet_async(&vsp->vns_nc, vsh->vsh_buf, ret,
		    vnic_send_completed);

		if (ret == 0)
			vnic_read_poll(vsh, false);

	} while (ret > 0);
}

static void
vnic_writable(void *opaque)
{
	VNICShared *vsh = opaque;
	int i;

	vnic_write_poll(vsh, false);
	for (i = 0; i < vsh->vsh_nqueues; i++)
		qemu_flush_queued_packets(&vsh->vsh_queues[i]->vns_nc);
}

/* VM -> outside world */
static ssize_t
vnic_receive(NetClientState *ncp, const uint8_t *buf, size_t size)
{
	VNICState *vsp = DO_UPCAST(VNICState, vns_nc, ncp);

	return (vnic_write_packet(vsp->vns_shared, buf, size));
}


static void
vnic_cleanup(NetClientState *ncp)
{
	VNICState *vsp = DO_UPCAST(VNICState, vns_nc, ncp);
	VNICShared *vsh = vsp->vns_shared;

	qemu_purge_queued_packets(ncp);

	if (--vsh->vsh_refcnt > 0)
		return;

	qemu_set_fd_handler(vsh->vsh_fd, NULL, NULL, NULL);
	dlpi_close(vsh->vsh_hdl);
	g_free(vsh);
}

static void
vnic_update_fd_handler(VNICShared *vsh)
{
	qemu_set_fd_handler(vsh->vsh_fd,
	    vsh->vsh_rpoll ? vnic_send : NULL,
	    vsh->vsh_wpoll ? vnic_writable : NULL,
	    vsh);
}

static NetClientInfo net_vnic_info = {
	.type = NET_CLIENT_DRIVER_VNIC,
	.size = sizeof(VNICState),
	.receive = vnic_receive,
	.poll = vnic_poll,
	.cleanup = vnic_cleanup,
};

int net_init_vnic(const Netdev *netdev, const char *name,
    NetClientState *peer, Error **errp)
{
	const NetdevVNICOptions *vnic;
	NetClientState *ncp;
	VNICShared *vsh;
	VNICState *vsp;
	int64_t queues;
	int i, fd, ret;

	assert(netdev->type == NET_CLIENT_DRIVER_VNIC);
	vnic = &netdev->u.vnic;

	queues = vnic->has_queues ? vnic->queues : 1;
	if (queues < 1 || queues > VNIC_MAX_QUEUES) {
		error_report("vnic: invalid number of queues %" PRId64
		    " for interface %s (must be 1-%d)",
		    queues, vnic->ifname, VNIC_MAX_QUEUES);
		return (-1);
	}

	vsh = g_new0(VNICShared, 1);
	vsh->vsh_nqueues = queues;

	ret = dlpi_open(vnic->ifname, &vsh->vsh_hdl, DLPI_RAW);
	if (ret != DLPI_SUCCESS) {
		error_report("vnic: failed to open interface %s, err %d",
		    vnic->ifname, ret);
		g_free(vsh);
		return (-1);
	}

	ret = dlpi_bind(vsh->vsh_hdl, DLPI_ANY_SAP, &vsh->vsh_sap);
	if (ret != DLPI_SUCCESS) {
		error_report("vnic: failed to bind interface %s, err %d",
		    vnic->ifname, ret);
		goto fail;
	}

	/*
	 * We are enabling support for two different kinds of promiscuous modes.
	 * The first is getting us the basics of the unicast traffic that we
	 * care about. The latter is going to ensure that we also get other
	 * types of physical traffic such as multicast and broadcast.
	 */
	ret = dlpi_promiscon(vsh->vsh_hdl, DL_PROMISC_SAP);
	if (ret != DLPI_SUCCESS) {
		error_report(
		    "vnic: failed to be promiscous with interface %s, err %d",
		    vnic->ifname, ret);
		goto fail;
	}

	ret = dlpi_promiscon(vsh->vsh_hdl, DL_PROMISC_PHYS);
	if (ret != DLPI_SUCCESS) {
		error_report(
		    "vnic: failed to be promiscous with interface %s, err %d",
		    vnic->ifname, ret);
		goto fail;
	}

	fd = dlpi_fd(vsh->vsh_hdl);

	if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
		error_report("vnic: failed to set fd on interface %s to "
		    "non-blocking: %s", vnic->ifname, strerror(errno));
		goto fail;
	}

	vsh->vsh_fd = fd;

	for (i = 0; i < queues; i++) {
		ncp = qemu_new_net_client(&net_vnic_info, peer, "vnic", name);
		vsp = DO_UPCAST(VNICState, vns_nc, ncp);
		vsp->vns_shared = vsh;
		vsh->vsh_queues[i] = vsp;
		vsh->vsh_refcnt++;

		snprintf(vsp->vns_nc.info_str, sizeof (vsp->vns_nc.info_str),
		    "ifname=%s,queue=%d", vnic->ifname, i);
	}

	/* We have to manually intialize the polling for read */
	vnic_read_poll(vsh, true);

	return (0);

fail:
	dlpi_close(vsh->vsh_hdl);
	g_free(vsh);
	return (-1);
}
