/*
   Copyright 2012 Pontus Fuchs <pontus.fuchs@gmail.com>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <net/if.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include <linux/nl80211.h>

static struct nl_sock *nl_sock;
static int nl80211_id;

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
			 void *arg)
{
	int *ret = arg;
	*ret = err->error;
	return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_SKIP;
}

static int ack_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_STOP;
}

static int nl80211_init(void)
{
	int err;

	nl_sock = nl_socket_alloc();
	if (!nl_sock) {
		fprintf(stderr, "Failed to allocate netlink socket.\n");
		return -ENOMEM;
	}

	if (genl_connect(nl_sock)) {
		fprintf(stderr, "Failed to connect to generic netlink.\n");
		err = -ENOLINK;
		goto out_handle_destroy;
	}

	nl80211_id = genl_ctrl_resolve(nl_sock, "nl80211");
	if (nl80211_id < 0) {
		fprintf(stderr, "nl80211 not found.\n");
		err = -ENOENT;
		goto out_handle_destroy;
	}

	return 0;

 out_handle_destroy:
	nl_socket_free(nl_sock);
	return err;
}

static int do_cmd(struct nl_msg *msg)
{
	struct nl_cb *cb;
	int err;

	if (!nl_sock)
		return -ENOLINK;

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	err = nl_send_auto_complete(nl_sock, msg);
	if (err < 0)
		goto out;

	err = 1;

	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

	while (err > 0)
		nl_recvmsgs(nl_sock, cb);
 out:
	nl_cb_put(cb);

	return err;
}

int del_monitor(const char *iface)
{
	int devidx;
	struct nl_msg *msg;

	nl80211_init();
	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		return 2;
	}

	devidx = if_nametoindex(iface);
	genlmsg_put(msg, 0, 0, nl80211_id, 0,
		    0, NL80211_CMD_DEL_INTERFACE, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);

	return do_cmd(msg);

nla_put_failure:
	fprintf(stderr, "building message failed\n");
	return 2;
}

int add_monitor(int phyidx, const char *name, int freq, enum nl80211_channel_type chan_type)
{
	int ret, devidx;
	struct nl_msg *msg;

	printf("%s %d %d\n", name, freq, chan_type);
	nl80211_init();
	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		return 2;
	}

	genlmsg_put(msg, 0, 0, nl80211_id, 0,
		    0, NL80211_CMD_NEW_INTERFACE, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, phyidx);

	NLA_PUT_STRING(msg, NL80211_ATTR_IFNAME, name);
	NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);

	ret = do_cmd(msg);

	if (ret) {
		fprintf(stderr, "failed to create monitor interface for phy%d\n", phyidx);
		return ret;
	}

	if (freq == -1)
		return 0;


	msg = nlmsg_alloc();
	devidx = if_nametoindex(name);
	genlmsg_put(msg, 0, 0, nl80211_id, 0,
		    0, NL80211_CMD_SET_CHANNEL, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, freq);

	if (chan_type != -1)
		NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, chan_type);

	ret = do_cmd(msg);
	if (ret)
		del_monitor(name);
	return ret;

nla_put_failure:
	fprintf(stderr, "building message failed\n");
	return 2;

}

int interface_up(const char *ifname)
{
	int sock;
	struct ifreq ifreq;

	sock = socket(AF_PACKET, SOCK_RAW, 0);
	if (sock == -1)
		return -1;

	strncpy(ifreq.ifr_name, ifname, sizeof(ifreq.ifr_name));

 	if (ioctl(sock, SIOCGIFFLAGS, &ifreq))
		goto out_err;

	ifreq.ifr_flags |= IFF_UP;

	if (ioctl(sock, SIOCSIFFLAGS, &ifreq))
		goto out_err;

	close(sock);
	return 0;

out_err:
	close(sock);
	return -1;

}
