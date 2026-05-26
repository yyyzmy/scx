/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __INTF_H
#define __INTF_H

#define CACHELINE_SIZE		64

#define TRAE_CPU_ID_MAX		512
#define TRAE_CPDOM_MAX_NR	128
#define TRAE_NUMA_MAX_NR	32
#define TRAE_CPDOM_MAX_DIST	3
#define TRAE_CPDOM_MAX_NR_PER_DIST 16

#define TRAE_SHIFT		10
#define TRAE_SCALE		(1ULL << TRAE_SHIFT)

#define TRAE_TIME_ONE_SEC	(1000ULL * 1000 * 1000)

#define TRAE_SLICE_MIN_NS	(500ULL * 1000)
#define TRAE_SLICE_MAX_NS	(5ULL * 1000 * 1000)

#define TRAE_DSQ_TYPE_SHFT	48
#define TRAE_DSQ_TYPE_DOM	2

#endif /* __INTF_H */
