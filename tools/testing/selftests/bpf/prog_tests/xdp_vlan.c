// SPDX-License-Identifier: GPL-2.0

/*
 * Network topology:
 *  -----------        -----------
 *  |  NS1    |        |   NS2   |
 *  | veth0  -|--------|- veth0  |
 *  -----------        -----------
 *
 */

#define _GNU_SOURCE
#include <net/if.h>
#include "network_helpers.h"
#include "test_progs.h"
#include "test_xdp_vlan.skel.h"
#include <uapi/linux/if_link.h>


#define VETH_NAME	"veth0"
#define NS1_NAME	"ns-xdp-vlan-1"
#define NS1_IP_ADDR	"100.64.10.1"
#define NS2_NAME	"ns-xdp-vlan-2"
#define NS2_IP_ADDR	"100.64.10.2"
#define VLAN_ID		4011

static int setup_network(struct netns_obj *ns[2])
{
	ns[0] = netns_new(NS1_NAME, false);
	ns[1] = netns_new(NS2_NAME, false);
	if (!ns[0] || !ns[1])
		goto fail;

	SYS(fail, "ip -n %s link add %s type veth peer name %s netns %s",
	    NS1_NAME, VETH_NAME, VETH_NAME, NS2_NAME);

	/* NOTICE: XDP require VLAN header inside packet payload
	 *  - Thus, disable VLAN offloading driver features
	 */
	SYS(fail, "ip netns exec %s ethtool -K %s rxvlan off txvlan off", NS1_NAME, VETH_NAME);
	SYS(fail, "ip netns exec %s ethtool -K %s rxvlan off txvlan off", NS2_NAME, VETH_NAME);

	/* NS1 configuration */
	SYS(fail, "ip -n %s addr add %s/24 dev %s", NS1_NAME, NS1_IP_ADDR, VETH_NAME);
	SYS(fail, "ip -n %s link set %s up", NS1_NAME, VETH_NAME);

	/* NS2 configuration */
	SYS(fail, "ip -n %s link add link %s name %s.%d type vlan id %d",
	    NS2_NAME, VETH_NAME, VETH_NAME, VLAN_ID, VLAN_ID);
	SYS(fail, "ip -n %s addr add %s/24 dev %s.%d", NS2_NAME, NS2_IP_ADDR, VETH_NAME, VLAN_ID);
	SYS(fail, "ip -n %s link set %s up", NS2_NAME, VETH_NAME);
	SYS(fail, "ip -n %s link set %s.%d up", NS2_NAME, VETH_NAME, VLAN_ID);

	return 0;

fail:
	return -1;
}

static void cleanup_network(struct netns_obj *ns[2])
{
	int i;

	for (i = 0; i < 2; i++)
		netns_free(ns[i]);
}

static void xdp_vlan(struct bpf_program *xdp, struct bpf_program *tc, u32 flags)
{
	LIBBPF_OPTS(bpf_tc_hook, tc_hook, .attach_point = BPF_TC_EGRESS);
	LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);
	struct nstoken *nstoken = NULL;
	struct netns_obj *ns[2] = {};
	int interface;
	int ret;

	if (!ASSERT_OK(setup_network(ns), "setup network"))
		return;

	nstoken = open_netns(NS1_NAME);
	if (!ASSERT_OK_PTR(nstoken, "open NS1"))
		goto cleanup;

	interface = if_nametoindex(VETH_NAME);
	if (!ASSERT_NEQ(interface, 0, "get interface index"))
		goto cleanup;

	ret = bpf_xdp_attach(interface, bpf_program__fd(xdp), flags, NULL);
	if (!ASSERT_OK(ret, "attach xdp_vlan_change"))
		goto cleanup;

	tc_hook.ifindex = interface;
	ret = bpf_tc_hook_create(&tc_hook);
	if (!ASSERT_OK(ret, "bpf_tc_hook_create"))
		goto detach_xdp;

	tc_opts.prog_fd = bpf_program__fd(tc);
	ret = bpf_tc_attach(&tc_hook, &tc_opts);
	if (!ASSERT_OK(ret, "bpf_tc_attach"))
		goto detach_xdp;

	close_netns(nstoken);
	nstoken = NULL;

	/* Now the namespaces can reach each-other, test with pings */
	ASSERT_OK(SYS_NOFAIL("ip netns exec %s ping -i 0.2 -W 2 -c 2 %s", NS1_NAME, NS2_IP_ADDR),
		  "ping NS1 -> NS2");
	ASSERT_OK(SYS_NOFAIL("ip netns exec %s ping -i 0.2 -W 2 -c 2 %s", NS2_NAME, NS1_IP_ADDR),
		  "ping NS2 -> NS1");


	bpf_tc_detach(&tc_hook, &tc_opts);
detach_xdp:
	bpf_xdp_detach(interface, flags, NULL);
cleanup:
	close_netns(nstoken);
	cleanup_network(ns);
}

void test_xdp_vlan(void)
{
	struct test_xdp_vlan *skel;

	skel = test_xdp_vlan__open_and_load();
	if (!ASSERT_OK_PTR(skel, "xdp_vlan__open_and_load"))
		return;

	/* First test: Remove VLAN by setting VLAN ID 0, using "xdp_vlan_change"
	 * egress use TC to add back VLAN tag 4011
	 */
	if (test__start_subtest("VLAN_ID=0/0"))
		xdp_vlan(skel->progs.xdp_vlan_change, skel->progs.tc_vlan_push, 0);

	if (test__start_subtest("VLAN_ID=0/DRV_MODE"))
		xdp_vlan(skel->progs.xdp_vlan_change, skel->progs.tc_vlan_push,
			 XDP_FLAGS_DRV_MODE);

	if (test__start_subtest("VLAN_ID=0/SKB_MODE"))
		xdp_vlan(skel->progs.xdp_vlan_change, skel->progs.tc_vlan_push,
			 XDP_FLAGS_SKB_MODE);

	/* Second test: Replace xdp prog, that fully remove vlan header
	 *
	 * Catch kernel bug for generic-XDP, that does didn't allow us to
	 * remove a VLAN header, because skb->protocol still contain VLAN
	 * ETH_P_8021Q indication, and this cause overwriting of our changes.
	 */
	if (test__start_subtest("Remove VLAN header/0"))
		xdp_vlan(skel->progs.xdp_vlan_remove_outer2, skel->progs.tc_vlan_push, 0);

	if (test__start_subtest("Remove VLAN header/DRV_MODE"))
		xdp_vlan(skel->progs.xdp_vlan_remove_outer2, skel->progs.tc_vlan_push,
			 XDP_FLAGS_DRV_MODE);

	if (test__start_subtest("Remove VLAN header/SKB_MODE"))
		xdp_vlan(skel->progs.xdp_vlan_remove_outer2, skel->progs.tc_vlan_push,
			 XDP_FLAGS_SKB_MODE);

	test_xdp_vlan__destroy(skel);
}
