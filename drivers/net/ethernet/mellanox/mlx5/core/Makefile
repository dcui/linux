obj-$(CONFIG_MLX5_CORE)		+= mlx5_core.o
subdir-ccflags-y += -I$(src)

mlx5_core-y :=	main.o cmd.o debugfs.o fw.o eq.o uar.o pagealloc.o \
		health.o mcg.o cq.o srq.o srq_exp.o alloc.o qp.o port.o mr.o pd.o \
		mad.o transobj.o vport.o sriov.o fs_cmd.o fs_core.o \
		fs_counters.o rl.o lag.o dev.o wq.o lib/gid.o qp_exp.o fw_exp.o \
		sriov_sysfs.o mst_dump.o en_diag.o params.o fs_debugfs.o crdump.o \
		nvmf.o lib/clock.o

mlx5_core-$(CONFIG_MLX5_ACCEL) += accel/ipsec.o

mlx5_core-$(CONFIG_MLX5_FPGA) += fpga/cmd.o fpga/core.o fpga/conn.o fpga/sdk.o \
		fpga/ipsec.o fpga/trans.o fpga/xfer.o

mlx5_core-$(CONFIG_MLX5_CORE_EN) += en_main.o en_common.o en_fs.o en_ethtool.o \
		en_tx.o en_rx.o en_rx_am.o en_txrx.o vxlan.o en_sysfs.o en_ecn.o \
		en_arfs.o en_fs_ethtool.o en_selftest.o en_debugfs.o en_sniffer.o

mlx5_core-$(CONFIG_MLX5_MPFS) += lib/mpfs.o

mlx5_core-$(CONFIG_MLX5_ESWITCH) += eswitch.o eswitch_offloads.o en_rep.o en_tc.o \
		eswitch_devlink_compat.o

mlx5_core-$(CONFIG_MLX5_CORE_EN_DCB) +=  en_dcbnl.o en_port_buffer.o

mlx5_core-$(CONFIG_MLX5_CORE_IPOIB) += ipoib/ipoib.o ipoib/ethtool.o ipoib/ipoib_vlan.o

mlx5_core-$(CONFIG_MLX5_EN_IPSEC) += en_accel/ipsec.o en_accel/ipsec_rxtx.o \
		en_accel/ipsec_stats.o
