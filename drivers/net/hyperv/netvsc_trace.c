#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/vmalloc.h>
#include <linux/rtnetlink.h>
#include <linux/prefetch.h>

#include <asm/sync_bitops.h>

#include "hyperv_net.h"

#define CREATE_TRACE_POINTS
#include "netvsc_trace.h"
