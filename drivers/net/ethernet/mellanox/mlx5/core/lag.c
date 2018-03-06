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

#include <linux/netdevice.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/vport.h>
#include "mlx5_core.h"


int mlx5_cmd_create_vport_lag(struct mlx5_core_dev *dev)
{
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(mlx5_cmd_create_vport_lag);

int mlx5_cmd_destroy_vport_lag(struct mlx5_core_dev *dev)
{
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(mlx5_cmd_destroy_vport_lag);

static int mlx5_cmd_query_cong_counter(struct mlx5_core_dev *dev,
				       bool reset, void *out, int out_size)
{
	u32 in[MLX5_ST_SZ_DW(query_cong_statistics_in)] = { };

	MLX5_SET(query_cong_statistics_in, in, opcode,
		 MLX5_CMD_OP_QUERY_CONG_STATISTICS);
	MLX5_SET(query_cong_statistics_in, in, clear, reset);
	return mlx5_cmd_exec(dev, in, sizeof(in), out, out_size);
}


/* Must be called with intf_mutex held */
void mlx5_lag_add(struct mlx5_core_dev *dev, struct net_device *netdev)
{
}

/* Must be called with intf_mutex held */
void mlx5_lag_remove(struct mlx5_core_dev *dev)
{
}

bool mlx5_lag_is_active(struct mlx5_core_dev *dev)
{
	return false;
}
EXPORT_SYMBOL(mlx5_lag_is_active);

static int mlx5_lag_set_state(struct mlx5_core_dev *dev, bool allow)
{
	return 0;
}

int mlx5_lag_forbid(struct mlx5_core_dev *dev)
{
	return mlx5_lag_set_state(dev, false);
}

int mlx5_lag_allow(struct mlx5_core_dev *dev)
{
	return mlx5_lag_set_state(dev, true);
}

struct net_device *mlx5_lag_get_roce_netdev(struct mlx5_core_dev *dev)
{
	return NULL;
}
EXPORT_SYMBOL(mlx5_lag_get_roce_netdev);

bool mlx5_lag_intf_add(struct mlx5_interface *intf, struct mlx5_priv *priv)
{
	return false;
}

int mlx5_lag_query_cong_counters(struct mlx5_core_dev *dev,
				 u64 *values,
				 int num_counters,
				 size_t *offsets)
{
	int outlen = MLX5_ST_SZ_BYTES(query_cong_statistics_out);
	struct mlx5_core_dev *mdev[MLX5_MAX_PORTS];
	int num_ports;
	int ret, i, j;
	void *out;

	out = kvzalloc(outlen, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	memset(values, 0, sizeof(*values) * num_counters);

	num_ports = 1;
	mdev[0] = dev;

	for (i = 0; i < num_ports; ++i) {
		ret = mlx5_cmd_query_cong_counter(mdev[i], false, out, outlen);
		if (ret)
			goto unlock;

		for (j = 0; j < num_counters; ++j)
			values[j] += be64_to_cpup((__be64 *)(out + offsets[j]));
	}

unlock:
	kvfree(out);
	return ret;
}
EXPORT_SYMBOL(mlx5_lag_query_cong_counters);
