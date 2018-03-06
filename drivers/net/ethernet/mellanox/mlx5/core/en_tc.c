/*
 * Copyright (c) 2016, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <net/sch_generic.h>
#include <net/pkt_cls.h>
#include <net/tc_act/tc_gact.h>
#include <net/tc_act/tc_skbedit.h>
#include <linux/mlx5/fs.h>
#include <linux/mlx5/device.h>
#ifdef CONFIG_NET_SWITCHDEV
#include <net/switchdev.h>
#endif
#include <net/tc_act/tc_mirred.h>
#include <net/tc_act/tc_vlan.h>
#include <linux/tc_act/tc_pedit.h>
#include <net/tc_act/tc_pedit.h>
#include <net/arp.h>
#include "en.h"
#include "en_rep.h"
#include "en_tc.h"
#include "eswitch.h"
#include "vxlan.h"

struct mlx5_nic_flow_attr {
	u32 action;
	u32 flow_tag;
};

enum {
	MLX5E_TC_FLOW_ESWITCH	= BIT(0),
	MLX5E_TC_FLOW_NIC	= BIT(1),
	MLX5E_TC_FLOW_OFFLOADED	= BIT(2),
};


int mlx5e_tc_init(struct mlx5e_priv *priv)
{
	return 0;
}


void mlx5e_tc_cleanup(struct mlx5e_priv *priv)
{
}
