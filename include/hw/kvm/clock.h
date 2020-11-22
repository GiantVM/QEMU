/*
 * QEMU KVM support, paravirtual clock device
 *
 * Copyright (C) 2011 Siemens AG
 * Copyright (c) 2018 Trusted Cloud Group, Shanghai Jiao Tong University
 *
 * Authors:
 *  Jan Kiszka        <jan.kiszka@siemens.com>
 *  Jin Zhang 	    <jzhang3002@sjtu.edu.cn>
 *  Yubin Chen 	<binsschen@sjtu.edu.cn>
 *  Zhuocheng Ding <tcbbd@sjtu.edu.cn>
 *
 * This work is licensed under the terms of the GNU GPL version 2.
 * See the COPYING file in the top-level directory.
 *
 */

#ifdef CONFIG_KVM

void kvmclock_create(void);

uint64_t kvmclock_getclock(void);

#else /* CONFIG_KVM */

static inline void kvmclock_create(void)
{
}

uint64_t kvmclock_getclock(void);

#endif /* !CONFIG_KVM */
