#ifndef APIC_H
#define APIC_H
/*
 * Copyright (C) 2017, Trusted Cloud Group, Shanghai Jiao Tong University.
 * 
 * Authors:
 *   Jin Zhang 	    <jzhang3002@sjtu.edu.cn>
 *   Yubin Chen 	<binsschen@sjtu.edu.cn>
 *   Zhuocheng Ding <tcbbd@sjtu.edu.cn>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */
#include "qemu-common.h"

/* apic.c */
void apic_deliver_irq(uint8_t dest, uint8_t dest_mode, uint8_t delivery_mode,
                      uint8_t vector_num, uint8_t trigger_mode);
int apic_accept_pic_intr(DeviceState *s);
void apic_deliver_pic_intr(DeviceState *s, int level);
void apic_deliver_nmi(DeviceState *d);
int apic_get_interrupt(DeviceState *s);
void apic_reset_irq_delivered(void);
int apic_get_irq_delivered(void);
void cpu_set_apic_base(DeviceState *s, uint64_t val);
uint64_t cpu_get_apic_base(DeviceState *s);
void cpu_set_apic_tpr(DeviceState *s, uint8_t val);
uint8_t cpu_get_apic_tpr(DeviceState *s);
void apic_init_reset(DeviceState *s);
void apic_sipi(DeviceState *s);
void apic_poll_irq(DeviceState *d);
void apic_designate_bsp(DeviceState *d, bool bsp);

/* pc.c */
DeviceState *cpu_get_current_apic(void);

void apic_init_level_deassert(CPUState *cpu);
void apic_lapic_write(CPUState *cpu, hwaddr addr, uint32_t val);
void apic_mem_writel(void *opaque, hwaddr addr, uint32_t val);
void apic_set_irq_detour(CPUState *cpu, int vector_num, int trigger_mode);
void apic_startup(CPUState *cpu, int vector_num);
#endif
