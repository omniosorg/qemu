/*
 * QEMU System Emulator Solaris VNIC support
 *
 * Copyright 2016 Joyent, Inc.
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

typedef struct VNICState {
	NetClientState	vns_nc;
	int		vns_fd;
	bool		vns_rpoll;
	bool		vns_wpoll;
	uint8_t		vns_buf[VNIC_BUFSIZE];
	uint_t		vns_sap;
	dlpi_handle_t	vns_hdl;
} VNICState;

static void vnic_update_fd_handler(VNICState *);

static void
vnic_read_poll(VNICState *vsp, bool enable)
{
	vsp->vns_rpoll = enable;
	vnic_update_fd_handler(vsp);
}

static void
vnic_write_poll(VNICState *vsp, bool enable)
{
	vsp->vns_wpoll = enable;
	vnic_update_fd_handler(vsp);
}

static void
vnic_poll(NetClientState *ncp, bool enable)
{
	VNICState *vsp = DO_UPCAST(VNICState, vns_nc, ncp);
	vnic_read_poll(vsp, true);
	vnic_write_poll(vsp, true);
}

static int
vnic_read_packet(VNICState *vsp, uint8_t *buf, int len)
{
	struct strbuf sbuf;
	int flags, ret;

	flags = 0;
	sbuf.maxlen = len;
	sbuf.buf = (char *)buf;

	do {
		ret = getmsg(vsp->vns_fd, NULL, &sbuf, &flags);
	} while (ret == -1 && errno == EINTR);

	if (ret == -1 && errno == EAGAIN) {
		vnic_write_poll(vsp, true);
		return (0);
	}

	if (ret == -1)
		return (-1);

	return (sbuf.len);
}

static int
vnic_write_packet(VNICState *vsp, const uint8_t *buf, int len)
{
	struct strbuf sbuf;
	int flags, ret;

	flags = 0;
	sbuf.len = len;
	sbuf.buf = (char *)buf;

	do {
		ret = putmsg(vsp->vns_fd, NULL, &sbuf, flags);
	} while (ret == -1 && errno == EINTR);

	if (ret == -1 && errno == EAGAIN) {
		vnic_write_poll(vsp, true);
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

	vnic_read_poll(vsp, true);
}

/* outside world -> VM */
static void
vnic_send(void *opaque)
{
	VNICState *vsp = opaque;
	int ret;

	do {
		ret = vnic_read_packet(vsp, vsp->vns_buf,
		    sizeof (vsp->vns_buf));
		if (ret <= 0)
			break;

		ret = qemu_send_packet_async(&vsp->vns_nc, vsp->vns_buf, ret,
		    vnic_send_completed);

		if (ret == 0)
			vnic_read_poll(vsp, false);

	} while (ret > 0 && qemu_can_send_packet(&vsp->vns_nc));
}

static void
vnic_writable(void *opaque)
{
	VNICState *vsp = opaque;
	vnic_write_poll(vsp, false);
	qemu_flush_queued_packets(&vsp->vns_nc);
}

/* VM -> outside world */
static ssize_t
vnic_receive(NetClientState *ncp, const uint8_t *buf, size_t size)
{
	VNICState *vsp = DO_UPCAST(VNICState, vns_nc, ncp);

	return (vnic_write_packet(vsp, buf, size));
}


static void
vnic_cleanup(NetClientState *ncp)
{
	VNICState *vsp = DO_UPCAST(VNICState, vns_nc, ncp);

	qemu_purge_queued_packets(ncp);

	dlpi_close(vsp->vns_hdl);
}

static void
vnic_update_fd_handler(VNICState *vsp)
{
	qemu_set_fd_handler(vsp->vns_fd,
	    vsp->vns_rpoll ? vnic_send : NULL,
	    vsp->vns_wpoll ? vnic_writable : NULL,
	    vsp);
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
	VNICState *vsp;
	int fd, ret;

	assert(netdev->type == NET_CLIENT_DRIVER_VNIC);
	vnic = &netdev->u.vnic;

	ncp = qemu_new_net_client(&net_vnic_info, peer, "vnic", name);
	vsp = DO_UPCAST(VNICState, vns_nc, ncp);

	ret = dlpi_open(vnic->ifname, &vsp->vns_hdl, DLPI_RAW);
	if (ret != DLPI_SUCCESS) {
		error_report("vnic: failed to open interface %s, err %d",
		    vnic->ifname, ret);
		return (-1);
	}

	ret = dlpi_bind(vsp->vns_hdl, DLPI_ANY_SAP, &vsp->vns_sap);
	if (ret != DLPI_SUCCESS) {
		error_report("vnic: failed to bind interface %s, err %d",
		    vnic->ifname, ret);
		return (-1);
	}

	/*
	 * We are enabling support for two different kinds of promiscuous modes.
	 * The first is getting us the basics of the unicast traffic that we
	 * care about. The latter is going to ensure that we also get other
	 * types of physical traffic such as multicast and broadcast.
	 */
	ret = dlpi_promiscon(vsp->vns_hdl, DL_PROMISC_SAP);
	if (ret != DLPI_SUCCESS) {
		error_report(
		    "vnic: failed to be promiscous with interface %s, err %d",
		    vnic->ifname, ret);
		return (-1);
	}

	ret = dlpi_promiscon(vsp->vns_hdl, DL_PROMISC_PHYS);
	if (ret != DLPI_SUCCESS) {
		error_report(
		    "vnic: failed to be promiscous with interface %s, err %d",
		   vnic-> ifname, ret);
		return (-1);
	}

	fd = dlpi_fd(vsp->vns_hdl);

	if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
		error_report("vnic: failed to set fd on interface %s to "
		    "non-blocking: %s", vnic->ifname, strerror(errno));
		return (-1);
	}

	vsp->vns_fd = fd;

	snprintf(vsp->vns_nc.info_str, sizeof (vsp->vns_nc.info_str),
	    "ifname=%s", vnic->ifname);

	/* We have to manually intialize the polling for read */
	vnic_read_poll(vsp, true);

	return (0);
}
