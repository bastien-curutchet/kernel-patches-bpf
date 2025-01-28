/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 Isovalent */
#ifndef TC_HELPERS
#define TC_HELPERS
#include <test_progs.h>
#include "network_helpers.h"

#ifndef loopback
# define loopback 1
#endif

static inline __u32 id_from_prog_fd(int fd)
{
	struct bpf_prog_info prog_info = {};
	__u32 prog_info_len = sizeof(prog_info);
	int err;

	err = bpf_obj_get_info_by_fd(fd, &prog_info, &prog_info_len);
	if (!ASSERT_OK(err, "id_from_prog_fd"))
		return 0;

	ASSERT_NEQ(prog_info.id, 0, "prog_info.id");
	return prog_info.id;
}

static inline __u32 id_from_link_fd(int fd)
{
	struct bpf_link_info link_info = {};
	__u32 link_info_len = sizeof(link_info);
	int err;

	err = bpf_link_get_info_by_fd(fd, &link_info, &link_info_len);
	if (!ASSERT_OK(err, "id_from_link_fd"))
		return 0;

	ASSERT_NEQ(link_info.id, 0, "link_info.id");
	return link_info.id;
}

static inline __u32 ifindex_from_link_fd(int fd)
{
	struct bpf_link_info link_info = {};
	__u32 link_info_len = sizeof(link_info);
	int err;

	err = bpf_link_get_info_by_fd(fd, &link_info, &link_info_len);
	if (!ASSERT_OK(err, "id_from_link_fd"))
		return 0;

	return link_info.tcx.ifindex;
}

static inline void __assert_mprog_count(int target, int expected, int ifindex)
{
	__u32 count = 0, attach_flags = 0;
	int err;

	err = bpf_prog_query(ifindex, target, 0, &attach_flags,
			     NULL, &count);
	ASSERT_EQ(count, expected, "count");
	ASSERT_EQ(err, 0, "prog_query");
}

static inline void assert_mprog_count(int target, int expected)
{
	__assert_mprog_count(target, expected, loopback);
}

static inline void assert_mprog_count_ifindex(int ifindex, int target, int expected)
{
	__assert_mprog_count(target, expected, ifindex);
}

static inline void tc_skel_reset_all_seen(struct test_tc_link *skel)
{
	memset(skel->bss, 0, sizeof(*skel->bss));
}

static inline struct netns_obj *create_tid_ns(const char * ns_name)
{
	struct netns_obj *ns;
	char name[32];
	
	if (!ASSERT_OK_PTR(ns_name, "check ns name ptr"))
		return NULL;

	memcpy(name, ns_name, sizeof(name));

	/* append_tid() needs 8 characters to append the thread ID */
	if (!ASSERT_OK(strlen(name) + 8 > sizeof(name), "check ns name size"))
		return NULL;

	if (!ASSERT_OK(append_tid(name, strlen(name)), "append TID to ns name"))
		return NULL;

	ns = netns_new(name, true);
	ASSERT_OK_PTR(ns, "netns new");

	return ns;
}

#endif /* TC_HELPERS */
