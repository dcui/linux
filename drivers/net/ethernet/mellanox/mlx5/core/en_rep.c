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

#include <generated/utsrelease.h>
#include <linux/mlx5/fs.h>
#ifdef CONFIG_NET_SWITCHDEV
#include <net/switchdev.h>
#endif
#include <net/pkt_cls.h>
#include <net/netevent.h>
#include <net/arp.h>
#include <net/addrconf.h>

#include "eswitch.h"
#include "en.h"
#include "en_rep.h"
#include "en_tc.h"
#include "fs_core.h"

static const char mlx5e_rep_driver_name[] = "mlx5e_rep";

static void mlx5e_rep_get_drvinfo(struct net_device *dev,
				  struct ethtool_drvinfo *drvinfo)
{
	strlcpy(drvinfo->driver, mlx5e_rep_driver_name,
		sizeof(drvinfo->driver));
	strlcpy(drvinfo->version, UTS_RELEASE, sizeof(drvinfo->version));
}

static const struct counter_desc sw_rep_stats_desc[] = {
	{ MLX5E_DECLARE_STAT(struct mlx5e_sw_stats, rx_packets) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_sw_stats, rx_bytes) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_sw_stats, tx_packets) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_sw_stats, tx_bytes) },
};

#define NUM_VPORT_REP_COUNTERS	ARRAY_SIZE(sw_rep_stats_desc)

static void mlx5e_rep_get_strings(struct net_device *dev,
				  u32 stringset, uint8_t *data)
{
	int i;

	switch (stringset) {
	case ETH_SS_STATS:
		for (i = 0; i < NUM_VPORT_REP_COUNTERS; i++)
			strcpy(data + (i * ETH_GSTRING_LEN),
			       sw_rep_stats_desc[i].format);
		break;
	}
}

static void mlx5e_rep_update_hw_counters(struct mlx5e_priv *priv)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5e_rep_priv *rpriv = priv->ppriv;
	struct mlx5_eswitch_rep *rep = rpriv->rep;
	struct rtnl_link_stats64 *vport_stats;
	struct ifla_vf_stats vf_stats;
	int err;

	err = mlx5_eswitch_get_vport_stats(esw, rep->vport, &vf_stats);
	if (err) {
		pr_warn("vport %d error %d reading stats\n", rep->vport, err);
		return;
	}

	vport_stats = &priv->stats.vf_vport;
	/* flip tx/rx as we are reporting the counters for the switch vport */
	vport_stats->rx_packets = vf_stats.tx_packets;
	vport_stats->rx_bytes   = vf_stats.tx_bytes;
	vport_stats->tx_packets = vf_stats.rx_packets;
	vport_stats->tx_bytes   = vf_stats.rx_bytes;
}

static void mlx5e_rep_update_sw_counters(struct mlx5e_priv *priv)
{
	struct mlx5e_sw_stats *s = &priv->stats.sw;
	struct mlx5e_rq_stats *rq_stats;
	struct mlx5e_sq_stats *sq_stats;
	int i, j;

	memset(s, 0, sizeof(*s));
	for (i = 0; i < priv->channels.num; i++) {
		struct mlx5e_channel *c = priv->channels.c[i];

		rq_stats = &c->rq.stats;

		s->rx_packets	+= rq_stats->packets;
		s->rx_bytes	+= rq_stats->bytes;

		for (j = 0; j < priv->channels.params.num_tc; j++) {
			sq_stats = &c->sq[j].stats;

			s->tx_packets		+= sq_stats->packets;
			s->tx_bytes		+= sq_stats->bytes;
		}
	}
}

static void mlx5e_rep_update_stats(struct mlx5e_priv *priv)
{
	mlx5e_rep_update_sw_counters(priv);
	mlx5e_rep_update_hw_counters(priv);
}

static void mlx5e_rep_get_ethtool_stats(struct net_device *dev,
					struct ethtool_stats *stats, u64 *data)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	int i;

	if (!data)
		return;

	mutex_lock(&priv->state_lock);
	if (test_bit(MLX5E_STATE_OPENED, &priv->state))
		mlx5e_rep_update_sw_counters(priv);
	mutex_unlock(&priv->state_lock);

	for (i = 0; i < NUM_VPORT_REP_COUNTERS; i++)
		data[i] = MLX5E_READ_CTR64_CPU(&priv->stats.sw,
					       sw_rep_stats_desc, i);
}

static int mlx5e_rep_get_sset_count(struct net_device *dev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return NUM_VPORT_REP_COUNTERS;
	default:
		return -EOPNOTSUPP;
	}
}

static const struct ethtool_ops mlx5e_rep_ethtool_ops = {
	.get_drvinfo	   = mlx5e_rep_get_drvinfo,
	.get_link	   = ethtool_op_get_link,
	.get_strings       = mlx5e_rep_get_strings,
	.get_sset_count    = mlx5e_rep_get_sset_count,
	.get_ethtool_stats = mlx5e_rep_get_ethtool_stats,
};

#ifdef CONFIG_NET_SWITCHDEV
int mlx5e_attr_get(struct net_device *dev, struct switchdev_attr *attr)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5e_rep_priv *rpriv = priv->ppriv;
	struct mlx5_eswitch_rep *rep = rpriv->rep;
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;

	if (esw->mode == SRIOV_NONE)
		return -EOPNOTSUPP;

	switch (attr->id) {
	case SWITCHDEV_ATTR_ID_PORT_PARENT_ID:
		attr->u.ppid.id_len = ETH_ALEN;
		ether_addr_copy(attr->u.ppid.id, rep->hw_id);
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}
#endif

int mlx5e_add_sqs_fwd_rules(struct mlx5e_priv *priv)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5e_rep_priv *rpriv = priv->ppriv;
	struct mlx5_eswitch_rep *rep = rpriv->rep;
	struct mlx5e_channel *c;
	int n, tc, num_sqs = 0;
	int err = -ENOMEM;
	u16 *sqs;
	int num_txqs = priv->channels.params.num_channels * priv->channels.params.num_tc;

#ifdef CONFIG_MLX5_EN_SPECIAL_SQ
	num_txqs += priv->channels.params.num_rl_txqs;
#endif
	sqs = kcalloc(num_txqs, sizeof(u16), GFP_KERNEL);
	if (!sqs)
		goto out;

	for (n = 0; n < priv->channels.num; n++) {
		c = priv->channels.c[n];
		for (tc = 0; tc < c->num_tc; tc++)
			sqs[num_sqs++] = c->sq[tc].sqn;
#ifdef CONFIG_MLX5_EN_SPECIAL_SQ
		for (tc = 0; tc < c->num_special_sq; tc++)
			sqs[num_sqs++] = c->special_sq[tc].sqn;
#endif
	}

	err = mlx5_eswitch_sqs2vport_start(esw, rep, sqs, num_sqs);
	kfree(sqs);

out:
	if (err)
		netdev_warn(priv->netdev, "Failed to add SQs FWD rules %d\n", err);
	return err;
}

void mlx5e_remove_sqs_fwd_rules(struct mlx5e_priv *priv)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5e_rep_priv *rpriv = priv->ppriv;
	struct mlx5_eswitch_rep *rep = rpriv->rep;

	mlx5_eswitch_sqs2vport_stop(esw, rep);
}

#define rep_netdev(rep) mlx5e_rep_to_context(rep)->netdev
#define rep_priv(rep) netdev_priv(rep_netdev(rep))
#define rpriv_priv(rpriv) rep_priv((rpriv)->rep)

static const struct rhashtable_params mlx5e_neigh_ht_params = {
	.head_offset = offsetof(struct mlx5e_neigh_hash_entry, rhash_node),
	.key_offset = offsetof(struct mlx5e_neigh_hash_entry, m_neigh),
	.key_len = sizeof(struct mlx5e_neigh),
	.automatic_shrinking = true,
};

static int mlx5e_rep_neigh_init(struct mlx5e_rep_priv *rpriv)
{
	struct mlx5e_neigh_update_table *neigh_update = &rpriv->neigh_update;
	int err;

	err = rhashtable_init(&neigh_update->neigh_ht, &mlx5e_neigh_ht_params);
	if (err)
		return err;

	INIT_LIST_HEAD(&neigh_update->neigh_list);
	return err;
}

static void mlx5e_rep_neigh_cleanup(struct mlx5e_rep_priv *rpriv)
{
	struct mlx5e_neigh_update_table *neigh_update = &rpriv->neigh_update;

	rhashtable_destroy(&neigh_update->neigh_ht);
}


static int mlx5e_rep_open(struct net_device *dev)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5e_rep_priv *rpriv = priv->ppriv;
	struct mlx5_eswitch_rep *rep = rpriv->rep;
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	int err;

	mutex_lock(&priv->state_lock);
	err = mlx5e_open_locked(dev);
	if (err)
		goto unlock;

	if (!mlx5_eswitch_set_vport_state(esw, rep->vport,
					  MLX5_ESW_VPORT_ADMIN_STATE_UP))
		netif_carrier_on(dev);

unlock:
	mutex_unlock(&priv->state_lock);
	return err;
}

static int mlx5e_rep_close(struct net_device *dev)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5e_rep_priv *rpriv = priv->ppriv;
	struct mlx5_eswitch_rep *rep = rpriv->rep;
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	int ret;

	mutex_lock(&priv->state_lock);
	(void)mlx5_eswitch_set_vport_state(esw, rep->vport, MLX5_ESW_VPORT_ADMIN_STATE_DOWN);
	ret = mlx5e_close_locked(dev);
	mutex_unlock(&priv->state_lock);
	return ret;
}

static int mlx5e_rep_get_phys_port_name(struct net_device *dev,
					char *buf, size_t len)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5e_rep_priv *rpriv = priv->ppriv;
	struct mlx5_eswitch_rep *rep = rpriv->rep;
	int ret;

	ret = snprintf(buf, len, "%d", rep->vport - 1);
	if (ret >= len)
		return -EOPNOTSUPP;

	return 0;
}


bool mlx5e_is_uplink_rep(struct mlx5e_priv *priv)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5e_rep_priv *rpriv = priv->ppriv;
	struct mlx5_eswitch_rep *rep;

	if (!MLX5_CAP_GEN(priv->mdev, vport_group_manager))
		return false;

	rep = rpriv->rep;
	if (esw->mode == SRIOV_OFFLOADS &&
	    rep && rep->vport == FDB_UPLINK_VPORT)
		return true;

	return false;
}



static
struct rtnl_link_stats64 * mlx5e_rep_get_stats(struct net_device *dev, struct rtnl_link_stats64 *stats)
{
	struct mlx5e_priv *priv = netdev_priv(dev);

	memcpy(stats, &priv->stats.vf_vport, sizeof(*stats));

	return stats;
}

#ifdef CONFIG_NET_SWITCHDEV
static const struct switchdev_ops mlx5e_rep_switchdev_ops = {
	.switchdev_port_attr_get	= mlx5e_attr_get,
};
#endif

static const struct net_device_ops mlx5e_netdev_ops_rep = {
	.ndo_open                = mlx5e_rep_open,
	.ndo_stop                = mlx5e_rep_close,
	.ndo_start_xmit          = mlx5e_xmit,
	.ndo_get_phys_port_name  = mlx5e_rep_get_phys_port_name,
	.ndo_get_stats64         = mlx5e_rep_get_stats,
};

static void mlx5e_build_rep_params(struct mlx5_core_dev *mdev,
				   struct mlx5e_params *params)
{
	u8 cq_period_mode = MLX5_CAP_GEN(mdev, cq_period_start_from_cqe) ?
					 MLX5_CQ_PERIOD_MODE_START_FROM_CQE :
					 MLX5_CQ_PERIOD_MODE_START_FROM_EQE;

	params->log_sq_size = MLX5E_PARAMS_MINIMUM_LOG_SQ_SIZE;
	params->rq_wq_type  = MLX5_WQ_TYPE_LINKED_LIST;
	params->log_rq_size = MLX5E_PARAMS_MINIMUM_LOG_RQ_SIZE;

	params->rx_am_enabled = MLX5_CAP_GEN(mdev, cq_moderation);
	mlx5e_set_rx_cq_mode_params(params, cq_period_mode);

	params->tx_max_inline         = mlx5e_get_max_inline_cap(mdev);
	params->num_tc                = 1;
	params->lro_wqe_sz            = MLX5E_PARAMS_DEFAULT_LRO_WQE_SZ;

	mlx5_query_min_inline(mdev, &params->tx_min_inline_mode);
}

static void mlx5e_build_rep_netdev(struct net_device *netdev)
{
	netdev->netdev_ops = &mlx5e_netdev_ops_rep;

	netdev->watchdog_timeo    = 15 * HZ;

	netdev->ethtool_ops	  = &mlx5e_rep_ethtool_ops;

#ifdef CONFIG_NET_SWITCHDEV
	netdev->switchdev_ops = &mlx5e_rep_switchdev_ops;
#endif

	netdev->features	 |= NETIF_F_VLAN_CHALLENGED;

	eth_hw_addr_random(netdev);
}

static void mlx5e_init_rep(struct mlx5_core_dev *mdev,
			   struct net_device *netdev,
			   const struct mlx5e_profile *profile,
			   void *ppriv)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);

	priv->mdev                         = mdev;
	priv->netdev                       = netdev;
	priv->profile                      = profile;
	priv->ppriv                        = ppriv;

	mutex_init(&priv->state_lock);

	INIT_DELAYED_WORK(&priv->update_stats_work, mlx5e_update_stats_work);

	priv->channels.params.num_channels = profile->max_nch(mdev);

	priv->hard_mtu = MLX5E_ETH_HARD_MTU;

	mlx5e_build_rep_params(mdev, &priv->channels.params);
	mlx5e_build_rep_netdev(netdev);
}

static int mlx5e_init_rep_rx(struct mlx5e_priv *priv)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5e_rep_priv *rpriv = priv->ppriv;
	struct mlx5_eswitch_rep *rep = rpriv->rep;
	struct mlx5e_rep_context *context;
	struct mlx5_flow_handle *flow_rule;
	int err;

	mlx5e_init_l2_addr(priv);

	err = mlx5e_create_direct_rqts(priv);
	if (err)
		return err;

	err = mlx5e_create_direct_tirs(priv);
	if (err)
		goto err_destroy_direct_rqts;

	flow_rule = mlx5_eswitch_create_vport_rx_rule(esw,
						      rep->vport,
						      priv->direct_tir[0].tirn);
	if (IS_ERR(flow_rule)) {
		err = PTR_ERR(flow_rule);
		goto err_destroy_direct_tirs;
	}
	context = mlx5e_rep_to_context(rep);
	context->vport_rx_rule = flow_rule;

	err = mlx5e_tc_init(priv);
	if (err)
		goto err_del_flow_rule;

	return 0;

err_del_flow_rule:
	mlx5_del_flow_rules(context->vport_rx_rule);
err_destroy_direct_tirs:
	mlx5e_destroy_direct_tirs(priv);
err_destroy_direct_rqts:
	mlx5e_destroy_direct_rqts(priv);
	return err;
}

static void mlx5e_cleanup_rep_rx(struct mlx5e_priv *priv)
{
	struct mlx5e_rep_priv *rpriv = priv->ppriv;
	struct mlx5_eswitch_rep *rep = rpriv->rep;
	struct mlx5e_rep_context *context;

	mlx5e_tc_cleanup(priv);
	context = mlx5e_rep_to_context(rep);
	mlx5_del_flow_rules(context->vport_rx_rule);
	mlx5e_destroy_direct_tirs(priv);
	mlx5e_destroy_direct_rqts(priv);
}

static int mlx5e_init_rep_tx(struct mlx5e_priv *priv)
{
	int err;

	err = mlx5e_create_tises(priv);
	if (err) {
		mlx5_core_warn(priv->mdev, "create tises failed, %d\n", err);
		return err;
	}
	return 0;
}

static int mlx5e_get_rep_max_num_channels(struct mlx5_core_dev *mdev)
{
#define	MLX5E_PORT_REPRESENTOR_NCH 1
	return MLX5E_PORT_REPRESENTOR_NCH;
}

static struct mlx5e_profile mlx5e_rep_profile = {
	.init			= mlx5e_init_rep,
	.init_rx		= mlx5e_init_rep_rx,
	.cleanup_rx		= mlx5e_cleanup_rep_rx,
	.init_tx		= mlx5e_init_rep_tx,
	.cleanup_tx		= mlx5e_cleanup_nic_tx,
	.update_stats           = mlx5e_rep_update_stats,
	.max_nch		= mlx5e_get_rep_max_num_channels,
	.update_carrier		= NULL,
	.rx_handlers.handle_rx_cqe       = mlx5e_handle_rx_cqe_rep,
	.rx_handlers.handle_rx_cqe_mpwqe = NULL /* Not supported */,
	.max_tc			= 1,
};

/* e-Switch vport representors */

static int
mlx5e_nic_rep_load(struct mlx5_core_dev *dev, struct mlx5_eswitch_rep *rep)
{
	struct mlx5e_priv *priv = rep_priv(rep);
	struct mlx5e_rep_priv *rpriv = priv->ppriv;

	int err;

	if (test_bit(MLX5E_STATE_OPENED, &priv->state)) {
		err = mlx5e_add_sqs_fwd_rules(priv);
		if (err)
			return err;
	}

	err = mlx5e_rep_neigh_init(rpriv);
	if (err)
		goto err_remove_sqs;

	return 0;

err_remove_sqs:
	mlx5e_remove_sqs_fwd_rules(priv);
	return err;
}

static void
mlx5e_nic_rep_unload(struct mlx5_eswitch_rep *rep)
{
	struct mlx5e_priv *priv = rep_priv(rep);
	struct mlx5e_rep_priv *rpriv = priv->ppriv;

	if (test_bit(MLX5E_STATE_OPENED, &priv->state))
		mlx5e_remove_sqs_fwd_rules(priv);

	/* clean (and re-init) existing uplink offloaded TC rules */
	mlx5e_tc_cleanup(priv);
	mlx5e_tc_init(priv);

	mlx5e_rep_neigh_cleanup(rpriv);
}

static int
mlx5e_vport_rep_load(struct mlx5_core_dev *dev, struct mlx5_eswitch_rep *rep)
{
	struct mlx5e_rep_context *context;
	struct mlx5e_rep_priv *rpriv;
	struct net_device *netdev;
	int err;

	rpriv = kzalloc(sizeof(*rpriv), GFP_KERNEL);
	if (!rpriv)
		return -ENOMEM;

	netdev = mlx5e_create_netdev(dev, &mlx5e_rep_profile, rpriv);
	if (!netdev) {
		pr_warn("Failed to create representor netdev for vport %d\n",
			rep->vport);
		kfree(rpriv);
		return -EINVAL;
	}

	context = mlx5e_rep_to_context(rep);
	context->netdev = netdev;
	rpriv->rep = rep;

	err = mlx5e_attach_netdev(netdev_priv(netdev));
	if (err) {
		pr_warn("Failed to attach representor netdev for vport %d\n",
			rep->vport);
		goto err_destroy_netdev;
	}

	err = mlx5e_rep_neigh_init(rpriv);
	if (err) {
		pr_warn("Failed to initialized neighbours handling for vport %d\n",
			rep->vport);
		goto err_detach_netdev;
	}

	err = register_netdev(netdev);
	if (err) {
		pr_warn("Failed to register representor netdev for vport %d\n",
			rep->vport);
		goto err_neigh_cleanup;
	}

	return 0;

err_neigh_cleanup:
	mlx5e_rep_neigh_cleanup(rpriv);

err_detach_netdev:
	mlx5e_detach_netdev(netdev_priv(netdev));

err_destroy_netdev:
	mlx5e_destroy_netdev(netdev_priv(netdev));
	kfree(rpriv);
	return err;
}

static void
mlx5e_vport_rep_unload(struct mlx5_eswitch_rep *rep)
{
	struct net_device *netdev = mlx5e_rep_to_context(rep)->netdev;
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5e_rep_priv *rpriv = priv->ppriv;
	void *ppriv = priv->ppriv;

	unregister_netdev(netdev);

	mlx5e_rep_neigh_cleanup(rpriv);
	mlx5e_detach_netdev(priv);
	mlx5e_destroy_netdev(priv);
	kfree(ppriv); /* mlx5e_rep_priv */
}

static void mlx5e_rep_register_vf_vports(struct mlx5e_priv *priv,
					 struct mlx5e_rep_context *context)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5_eswitch *esw   = mdev->priv.eswitch;
	int total_vfs = MLX5_TOTAL_VPORTS(mdev);
	int vport;

	for (vport = 1; vport < total_vfs; vport++) {
		struct mlx5_eswitch_rep_if rep_if;

		rep_if.load = mlx5e_vport_rep_load;
		rep_if.unload = mlx5e_vport_rep_unload;
		INIT_LIST_HEAD(&context[vport].vport_sqs_list);
		rep_if.ptr = &context[vport];
		mlx5_eswitch_register_vport_rep(esw, vport, &rep_if, REP_ETH);
	}
}

static void mlx5e_rep_unregister_vf_vports(struct mlx5e_priv *priv)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5_eswitch *esw = mdev->priv.eswitch;
	int total_vfs = MLX5_TOTAL_VPORTS(mdev);
	int vport;

	for (vport = 1; vport < total_vfs; vport++)
		mlx5_eswitch_unregister_vport_rep(esw, vport, REP_ETH);
}

int mlx5e_register_vport_reps(struct mlx5e_priv *priv)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5_eswitch *esw   = mdev->priv.eswitch;
	struct mlx5e_rep_context *context;
	struct mlx5_eswitch_rep_if rep_if;

	context = kcalloc(MLX5_TOTAL_VPORTS(mdev), sizeof(*context),
			  GFP_KERNEL);
	if (!context)
		return -ENOMEM;
	rep_if.load = mlx5e_nic_rep_load;
	rep_if.unload = mlx5e_nic_rep_unload;
	context[0].netdev = priv->netdev;
	INIT_LIST_HEAD(&context[0].vport_sqs_list);
	rep_if.ptr = &context[0];
	mlx5_eswitch_register_vport_rep(esw, 0, &rep_if, REP_ETH); /* PF vport*/

	mlx5e_rep_register_vf_vports(priv, context); /* VFs vports */
	return 0;
}

void mlx5e_unregister_vport_reps(struct mlx5e_priv *priv)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5_eswitch *esw   = mdev->priv.eswitch;

	mlx5e_rep_unregister_vf_vports(priv); /* VFs vports */
	mlx5_eswitch_unregister_vport_rep(esw, 0, REP_ETH); /* UPLINK PF*/
	kfree(mlx5e_rep_to_context(&esw->offloads.vport_reps[0]));
}

void *mlx5e_alloc_nic_rep_priv(struct mlx5_core_dev *mdev)
{
	struct mlx5_eswitch *esw = mdev->priv.eswitch;
	struct mlx5e_rep_priv *rpriv;

	rpriv = kzalloc(sizeof(*rpriv), GFP_KERNEL);
	if (!rpriv)
		return NULL;

	rpriv->rep = &esw->offloads.vport_reps[0];
	return rpriv;
}
