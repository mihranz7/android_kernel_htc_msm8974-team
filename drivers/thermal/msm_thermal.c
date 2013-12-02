/* Copyright (c) 2012, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/msm_tsens.h>
#include <linux/workqueue.h>
#include <linux/cpu.h>
#include <linux/reboot.h>
#include <linux/cpufreq.h>
#include <linux/msm_tsens.h>
#include <linux/msm_thermal.h>
#include <linux/platform_device.h>
#include <linux/of.h>
<<<<<<< HEAD
#include <linux/hrtimer.h>
#include <mach/cpufreq.h>
#ifdef CONFIG_MSM_MPDEC_INPUTBOOST_CPUMIN
#include "../../arch/arm/mach-msm/msm_mpdecision.h"
#endif

static DEFINE_MUTEX(emergency_shutdown_mutex);
=======
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/sysfs.h>
#include <linux/types.h>
#include <linux/io.h>
#include <linux/thermal.h>
#include <mach/rpm-regulator.h>
#include <mach/rpm-regulator-smd.h>
#include <linux/regulator/consumer.h>
#include <linux/msm_thermal_ioctl.h>
#include <mach/rpm-smd.h>
#include <mach/scm.h>
#include <linux/sched.h>

#define MAX_CURRENT_UA 1000000
#define MAX_RAILS 5
#define MAX_THRESHOLD 2
#define MONITOR_ALL_TSENS -1
#define BYTES_PER_FUSE_ROW  8
#define MAX_EFUSE_VALUE  16
#define THERM_SECURE_BITE_CMD 8

static struct msm_thermal_data msm_thermal_info;
static struct delayed_work check_temp_work;
static bool core_control_enabled;
static uint32_t cpus_offlined;
static DEFINE_MUTEX(core_control_mutex);
static struct kobject *cc_kobj;
static struct task_struct *hotplug_task;
static struct task_struct *freq_mitigation_task;
static struct task_struct *thermal_monitor_task;
static struct completion hotplug_notify_complete;
static struct completion freq_mitigation_complete;
static struct completion thermal_monitor_complete;
>>>>>>> df2159f0784... msm: thermal: Remove alarm support in KTM

static int enabled;

//Throttling indicator, 0=not throttled, 1=low, 2=mid, 3=max
int bricked_thermal_throttled = 0;
EXPORT_SYMBOL_GPL(bricked_thermal_throttled);

//Save the cpu max freq before throttling
static int pre_throttled_max = 0;

static struct msm_thermal_data msm_thermal_info;

static struct msm_thermal_stat msm_thermal_stats = {
    .time_low_start = 0,
    .time_mid_start = 0,
    .time_max_start = 0,
    .time_low = 0,
    .time_mid = 0,
    .time_max = 0,
};

static struct delayed_work check_temp_work;
static struct workqueue_struct *check_temp_workq;

static void update_stats(void)
{
    if (msm_thermal_stats.time_low_start > 0) {
        msm_thermal_stats.time_low += (ktime_to_ms(ktime_get()) - msm_thermal_stats.time_low_start);
        msm_thermal_stats.time_low_start = 0;
    }
    if (msm_thermal_stats.time_mid_start > 0) {
        msm_thermal_stats.time_mid += (ktime_to_ms(ktime_get()) - msm_thermal_stats.time_mid_start);
        msm_thermal_stats.time_mid_start = 0;
    }
    if (msm_thermal_stats.time_max_start > 0) {
        msm_thermal_stats.time_max += (ktime_to_ms(ktime_get()) - msm_thermal_stats.time_max_start);
        msm_thermal_stats.time_max_start = 0;
    }
}

static void start_stats(int status)
{
    switch (bricked_thermal_throttled) {
        case 1:
            msm_thermal_stats.time_low_start = ktime_to_ms(ktime_get());
            break;
        case 2:
            msm_thermal_stats.time_mid_start = ktime_to_ms(ktime_get());
            break;
        case 3:
            msm_thermal_stats.time_max_start = ktime_to_ms(ktime_get());
            break;
    }
}

static int update_cpu_max_freq(struct cpufreq_policy *cpu_policy,
                   int cpu, int max_freq)
{
    int ret = 0;

    if (!cpu_policy)
        return -EINVAL;

    cpufreq_verify_within_limits(cpu_policy, cpu_policy->min, max_freq);
    cpu_policy->user_policy.max = max_freq;

    ret = cpufreq_update_policy(cpu);
    if (!ret)
        pr_debug("msm_thermal: Setting CPU%d max frequency to %d\n",
                 cpu, max_freq);
    return ret;
}

#ifdef CONFIG_MSM_MPDEC_INPUTBOOST_CPUMIN
static int update_cpu_min_freq(struct cpufreq_policy *cpu_policy,
                               int cpu, int new_freq)
{
    int ret = 0;

    if (!cpu_policy)
        return -EINVAL;

    cpufreq_verify_within_limits(cpu_policy, new_freq, cpu_policy->max);
    cpu_policy->user_policy.min = new_freq;

    ret = cpufreq_update_policy(cpu);
    if (!ret) {
        pr_debug("msm_thermal: Setting CPU%d min frequency to %d\n",
            cpu, new_freq);
    }
    return ret;
}

DECLARE_PER_CPU(struct msm_mpdec_cpudata_t, msm_mpdec_cpudata);
#endif
static void check_temp(struct work_struct *work)
{
    struct cpufreq_policy *cpu_policy = NULL;
    struct tsens_device tsens_dev;
    unsigned long temp = 0;
    uint32_t max_freq = 0;
    bool update_policy = false;
    int i = 0, cpu = 0, ret = 0;

    tsens_dev.sensor_num = msm_thermal_info.sensor_id;
    ret = tsens_get_temp(&tsens_dev, &temp);
    if (ret) {
        pr_err("msm_thermal: FATAL: Unable to read TSENS sensor %d\n",
               tsens_dev.sensor_num);
        goto reschedule;
    }

    if (temp >= msm_thermal_info.shutdown_temp) {
        mutex_lock(&emergency_shutdown_mutex);
        pr_warn("################################\n");
        pr_warn("################################\n");
        pr_warn("- %u OVERTEMP! SHUTTING DOWN! -\n", msm_thermal_info.shutdown_temp);
        pr_warn("- cur temp:%lu measured by:%u -\n", temp, msm_thermal_info.sensor_id);
        pr_warn("################################\n");
        pr_warn("################################\n");
        /* orderly poweroff tries to power down gracefully
           if it fails it will force it. */
        orderly_poweroff(true);
        for_each_possible_cpu(cpu) {
            update_policy = true;
            max_freq = msm_thermal_info.allowed_max_freq;
            bricked_thermal_throttled = 3;
            pr_warn("msm_thermal: Emergency throttled CPU%i to %u! temp:%lu\n",
                    cpu, msm_thermal_info.allowed_max_freq, temp);
        }
        mutex_unlock(&emergency_shutdown_mutex);
    }

    for_each_possible_cpu(cpu) {
        update_policy = false;
        cpu_policy = cpufreq_cpu_get(cpu);
        if (!cpu_policy) {
            pr_debug("msm_thermal: NULL policy on cpu %d\n", cpu);
            continue;
        }

        /* save pre-throttled max freq value */
        if ((bricked_thermal_throttled == 0) && (cpu == 0))
            pre_throttled_max = cpu_policy->max;

        //low trip point
        if ((temp >= msm_thermal_info.allowed_low_high) &&
            (temp < msm_thermal_info.allowed_mid_high) &&
            (bricked_thermal_throttled < 1)) {
            update_policy = true;
            max_freq = msm_thermal_info.allowed_low_freq;
            if (cpu == (CONFIG_NR_CPUS-1)) {
                bricked_thermal_throttled = 1;
                pr_warn("msm_thermal: Thermal Throttled (low)! temp:%lu by:%u\n",
                        temp, msm_thermal_info.sensor_id);
            }
        //low clr point
        } else if ((temp < msm_thermal_info.allowed_low_low) &&
               (bricked_thermal_throttled > 0)) {
            if (pre_throttled_max != 0)
                max_freq = pre_throttled_max;
            else {
                max_freq = CONFIG_MSM_CPU_FREQ_MAX;
                pr_warn("msm_thermal: ERROR! pre_throttled_max=0, falling back to %u\n", max_freq);
            }
            update_policy = true;
            for (i = 1; i < CONFIG_NR_CPUS; i++) {
                if (cpu_online(i))
                        continue;
                cpu_up(i);
            }
            if (cpu == (CONFIG_NR_CPUS-1)) {
                bricked_thermal_throttled = 0;
                pr_warn("msm_thermal: Low thermal throttle ended! temp:%lu by:%u\n",
                        temp, msm_thermal_info.sensor_id);
            }

#ifdef CONFIG_MSM_MPDEC_INPUTBOOST_CPUMIN
            if (cpu_online(cpu)) {
                if (mutex_trylock(&per_cpu(msm_mpdec_cpudata, cpu).unboost_mutex)) {
                    per_cpu(msm_mpdec_cpudata, cpu).is_boosted = false;
                    update_cpu_min_freq(cpu_policy, cpu, per_cpu(msm_mpdec_cpudata, cpu).norm_min_freq);
                    mutex_unlock(&per_cpu(msm_mpdec_cpudata, cpu).unboost_mutex);
                }
            }
#endif

        //mid trip point
        } else if ((temp >= msm_thermal_info.allowed_mid_high) &&
               (temp < msm_thermal_info.allowed_max_high) &&
               (bricked_thermal_throttled < 2)) {
            update_policy = true;
            max_freq = msm_thermal_info.allowed_mid_freq;
            if (cpu == (CONFIG_NR_CPUS-1)) {
                bricked_thermal_throttled = 2;
                pr_warn("msm_thermal: Thermal Throttled (mid)! temp:%lu by:%u\n",
                        temp, msm_thermal_info.sensor_id);
            }
        //mid clr point
        } else if ((temp < msm_thermal_info.allowed_mid_low) &&
               (bricked_thermal_throttled > 1)) {
            max_freq = msm_thermal_info.allowed_low_freq;
            update_policy = true;
            if (cpu == (CONFIG_NR_CPUS-1)) {
                bricked_thermal_throttled = 1;
                pr_warn("msm_thermal: Mid thermal throttle ended! temp:%lu by:%u\n",
                        temp, msm_thermal_info.sensor_id);
            }
        //max trip point
        } else if (temp >= msm_thermal_info.allowed_max_high) {
            update_policy = true;
            max_freq = msm_thermal_info.allowed_max_freq;
            if (cpu == (CONFIG_NR_CPUS-1)) {
                bricked_thermal_throttled = 3;
                pr_warn("msm_thermal: Thermal Throttled (max)! temp:%lu by:%u\n",
                        temp, msm_thermal_info.sensor_id);
            }
        //max clr point
        } else if ((temp < msm_thermal_info.allowed_max_low) &&
               (bricked_thermal_throttled > 2)) {
            max_freq = msm_thermal_info.allowed_mid_freq;
            update_policy = true;
            if (cpu == (CONFIG_NR_CPUS-1)) {
                bricked_thermal_throttled = 2;
                pr_warn("msm_thermal: Max thermal throttle ended! temp:%lu by:%u\n",
                        temp, msm_thermal_info.sensor_id);
            }
        }
        update_stats();
        start_stats(bricked_thermal_throttled);
        if (update_policy)
            update_cpu_max_freq(cpu_policy, cpu, max_freq);

        cpufreq_cpu_put(cpu_policy);
    }

reschedule:
    if (enabled)
        queue_delayed_work(check_temp_workq, &check_temp_work,
                           msecs_to_jiffies(msm_thermal_info.poll_ms));

    return;
}

static void disable_msm_thermal(void)
{
    int cpu = 0;
    struct cpufreq_policy *cpu_policy = NULL;

     enabled = 0;
    /* make sure check_temp is no longer running */
    cancel_delayed_work(&check_temp_work);
    flush_scheduled_work();

    if (pre_throttled_max != 0) {
        for_each_possible_cpu(cpu) {
            cpu_policy = cpufreq_cpu_get(cpu);
            if (cpu_policy) {
                if (cpu_policy->max < cpu_policy->cpuinfo.max_freq)
                    update_cpu_max_freq(cpu_policy, cpu, pre_throttled_max);
                cpufreq_cpu_put(cpu_policy);
            }
        }
    }

   pr_warn("msm_thermal: Warning! Thermal guard disabled!");
}

static void enable_msm_thermal(void)
{
    enabled = 1;
    /* make sure check_temp is running */
    queue_delayed_work(check_temp_workq, &check_temp_work,
                       msecs_to_jiffies(msm_thermal_info.poll_ms));

    pr_info("msm_thermal: Thermal guard enabled.");
}

static int set_enabled(const char *val, const struct kernel_param *kp)
{
    int ret = 0;

    ret = param_set_bool(val, kp);
    if (!enabled)
        disable_msm_thermal();
    else if (enabled == 1)
        enable_msm_thermal();
    else
        pr_info("msm_thermal: no action for enabled = %d\n", enabled);

    pr_info("msm_thermal: enabled = %d\n", enabled);

    return ret;
}

static struct kernel_param_ops module_ops = {
    .set = set_enabled,
    .get = param_get_bool,
};

module_param_cb(enabled, &module_ops, &enabled, 0644);
MODULE_PARM_DESC(enabled, "enforce thermal limit on cpu");

/**************************** SYSFS START ****************************/
struct kobject *msm_thermal_kobject;

#define show_one(file_name, object)                             \
static ssize_t show_##file_name                                 \
(struct kobject *kobj, struct attribute *attr, char *buf)       \
{                                                               \
    return sprintf(buf, "%u\n", msm_thermal_info.object);       \
}

show_one(shutdown_temp, shutdown_temp);
show_one(allowed_max_high, allowed_max_high);
show_one(allowed_max_low, allowed_max_low);
show_one(allowed_max_freq, allowed_max_freq);
show_one(allowed_mid_high, allowed_mid_high);
show_one(allowed_mid_low, allowed_mid_low);
show_one(allowed_mid_freq, allowed_mid_freq);
show_one(allowed_low_high, allowed_low_high);
show_one(allowed_low_low, allowed_low_low);
show_one(allowed_low_freq, allowed_low_freq);
show_one(poll_ms, poll_ms);

static ssize_t store_shutdown_temp(struct kobject *a, struct attribute *b,
                                   const char *buf, size_t count)
{
    unsigned int input;
    int ret;
    ret = sscanf(buf, "%u", &input);
    if (ret != 1)
        return -EINVAL;

    msm_thermal_info.shutdown_temp = input;

    return count;
}

static ssize_t store_allowed_max_high(struct kobject *a, struct attribute *b,
                                      const char *buf, size_t count)
{
    unsigned int input;
    int ret;
    ret = sscanf(buf, "%u", &input);
    if (ret != 1)
        return -EINVAL;

    msm_thermal_info.allowed_max_high = input;

    return count;
}

static ssize_t store_allowed_max_low(struct kobject *a, struct attribute *b,
                                     const char *buf, size_t count)
{
    unsigned int input;
    int ret;
    ret = sscanf(buf, "%u", &input);
    if (ret != 1)
        return -EINVAL;

    msm_thermal_info.allowed_max_low = input;

    return count;
}

<<<<<<< HEAD
static ssize_t store_allowed_max_freq(struct kobject *a, struct attribute *b,
                                      const char *buf, size_t count)
{
    unsigned int input;
    int ret;
    ret = sscanf(buf, "%u", &input);
    if (ret != 1)
        return -EINVAL;

    msm_thermal_info.allowed_max_freq = input;

    return count;
}

static ssize_t store_allowed_mid_high(struct kobject *a, struct attribute *b,
                                      const char *buf, size_t count)
{
    unsigned int input;
    int ret;
    ret = sscanf(buf, "%u", &input);
    if (ret != 1)
        return -EINVAL;

    msm_thermal_info.allowed_mid_high = input;
=======
static struct notifier_block __refdata msm_thermal_cpu_notifier = {
	.notifier_call = msm_thermal_cpu_callback,
};

static int hotplug_notify(enum thermal_trip_type type, int temp, void *data)
{
	struct cpu_info *cpu_node = (struct cpu_info *)data;

	pr_info("%s reach temp threshold: %d\n", cpu_node->sensor_type, temp);

	if (!(msm_thermal_info.core_control_mask & BIT(cpu_node->cpu)))
		return 0;
	switch (type) {
	case THERMAL_TRIP_CONFIGURABLE_HI:
		if (!(cpu_node->offline))
			cpu_node->offline = 1;
		break;
	case THERMAL_TRIP_CONFIGURABLE_LOW:
		if (cpu_node->offline)
			cpu_node->offline = 0;
		break;
	default:
		break;
	}
	if (hotplug_task) {
		cpu_node->hotplug_thresh_clear = true;
		complete(&hotplug_notify_complete);
	} else {
		pr_err("Hotplug task is not initialized\n");
	}
	return 0;
}
/* Adjust cpus offlined bit based on temperature reading. */
static int hotplug_init_cpu_offlined(void)
{
	long temp = 0;
	uint32_t cpu = 0;

	if (!hotplug_enabled)
		return 0;

	mutex_lock(&core_control_mutex);
	for_each_possible_cpu(cpu) {
		if (!(msm_thermal_info.core_control_mask & BIT(cpus[cpu].cpu)))
			continue;
		if (therm_get_temp(cpus[cpu].sensor_id, cpus[cpu].id_type,
					&temp)) {
			pr_err("Unable to read TSENS sensor:%d.\n",
				cpus[cpu].sensor_id);
			mutex_unlock(&core_control_mutex);
			return -EINVAL;
		}

		if (temp >= msm_thermal_info.hotplug_temp_degC)
			cpus[cpu].offline = 1;
		else if (temp <= (msm_thermal_info.hotplug_temp_degC -
			msm_thermal_info.hotplug_temp_hysteresis_degC))
			cpus[cpu].offline = 0;
	}
	mutex_unlock(&core_control_mutex);

	if (hotplug_task)
		complete(&hotplug_notify_complete);
	else {
		pr_err("Hotplug task is not initialized\n");
		return -EINVAL;
	}
	return 0;
}
>>>>>>> df2159f0784... msm: thermal: Remove alarm support in KTM

    return count;
}

static ssize_t store_allowed_mid_low(struct kobject *a, struct attribute *b,
                                     const char *buf, size_t count)
{
    unsigned int input;
    int ret;
    ret = sscanf(buf, "%u", &input);
    if (ret != 1)
        return -EINVAL;

    msm_thermal_info.allowed_mid_low = input;

    return count;
}

static ssize_t store_allowed_mid_freq(struct kobject *a, struct attribute *b,
                                      const char *buf, size_t count)
{
    unsigned int input;
    int ret;
    ret = sscanf(buf, "%u", &input);
    if (ret != 1)
        return -EINVAL;

    msm_thermal_info.allowed_mid_freq = input;

    return count;
}

static ssize_t store_allowed_low_high(struct kobject *a, struct attribute *b,
                                      const char *buf, size_t count)
{
    unsigned int input;
    int ret;
    ret = sscanf(buf, "%u", &input);
    if (ret != 1)
        return -EINVAL;

    msm_thermal_info.allowed_low_high = input;

    return count;
}

static ssize_t store_allowed_low_low(struct kobject *a, struct attribute *b,
                                     const char *buf, size_t count)
{
    unsigned int input;
    int ret;
    ret = sscanf(buf, "%u", &input);
    if (ret != 1)
        return -EINVAL;

    msm_thermal_info.allowed_low_low = input;

    return count;
}

static ssize_t store_allowed_low_freq(struct kobject *a, struct attribute *b,
                                      const char *buf, size_t count)
{
    unsigned int input;
    int ret;
    ret = sscanf(buf, "%u", &input);
    if (ret != 1)
        return -EINVAL;

    msm_thermal_info.allowed_low_freq = input;

    return count;
}

static ssize_t store_poll_ms(struct kobject *a, struct attribute *b,
                             const char *buf, size_t count)
{
    unsigned int input;
    int ret;
    ret = sscanf(buf, "%u", &input);
    if (ret != 1)
        return -EINVAL;

    msm_thermal_info.poll_ms = input;

    return count;
}

define_one_global_rw(shutdown_temp);
define_one_global_rw(allowed_max_high);
define_one_global_rw(allowed_max_low);
define_one_global_rw(allowed_max_freq);
define_one_global_rw(allowed_mid_high);
define_one_global_rw(allowed_mid_low);
define_one_global_rw(allowed_mid_freq);
define_one_global_rw(allowed_low_high);
define_one_global_rw(allowed_low_low);
define_one_global_rw(allowed_low_freq);
define_one_global_rw(poll_ms);

static struct attribute *msm_thermal_attributes[] = {
    &shutdown_temp.attr,
    &allowed_max_high.attr,
    &allowed_max_low.attr,
    &allowed_max_freq.attr,
    &allowed_mid_high.attr,
    &allowed_mid_low.attr,
    &allowed_mid_freq.attr,
    &allowed_low_high.attr,
    &allowed_low_low.attr,
    &allowed_low_freq.attr,
    &poll_ms.attr,
    NULL
};

<<<<<<< HEAD

static struct attribute_group msm_thermal_attr_group = {
    .attrs = msm_thermal_attributes,
    .name = "conf",
};

/********* STATS START *********/

static ssize_t show_throttle_times(struct kobject *a, struct attribute *b,
                                 char *buf)
=======
static __refdata struct attribute_group cc_attr_group = {
	.attrs = cc_attrs,
};
static __init int msm_thermal_add_cc_nodes(void)
>>>>>>> df2159f0784... msm: thermal: Remove alarm support in KTM
{
    ssize_t len = 0;

<<<<<<< HEAD
    if (bricked_thermal_throttled == 1) {
        len += sprintf(buf + len, "%s %llu\n", "low",
                       (msm_thermal_stats.time_low +
                        (ktime_to_ms(ktime_get()) -
                         msm_thermal_stats.time_low_start)));
    } else
        len += sprintf(buf + len, "%s %llu\n", "low", msm_thermal_stats.time_low);

    if (bricked_thermal_throttled == 2) {
        len += sprintf(buf + len, "%s %llu\n", "mid",
                       (msm_thermal_stats.time_mid +
                        (ktime_to_ms(ktime_get()) -
                         msm_thermal_stats.time_mid_start)));
    } else
        len += sprintf(buf + len, "%s %llu\n", "mid", msm_thermal_stats.time_mid);
=======
int msm_thermal_pre_init(void)
{
	int ret = 0;

	tsens_get_max_sensor_num(&max_tsens_num);
	if (create_sensor_id_map()) {
		pr_err("Creating sensor id map failed\n");
		ret = -EINVAL;
		goto pre_init_exit;
	}

	if (!thresh) {
		thresh = kzalloc(
				sizeof(struct threshold_info) * MSM_LIST_MAX_NR,
				GFP_KERNEL);
		if (!thresh) {
			pr_err("kzalloc failed\n");
			ret = -ENOMEM;
			goto pre_init_exit;
		}
		memset(thresh, 0, sizeof(struct threshold_info) *
			MSM_LIST_MAX_NR);
	}
pre_init_exit:
	return ret;
}

int msm_thermal_init(struct msm_thermal_data *pdata)
{
	int ret = 0;
	uint32_t cpu;

	for_each_possible_cpu(cpu) {
		cpus[cpu].cpu = cpu;
		cpus[cpu].offline = 0;
		cpus[cpu].user_offline = 0;
		cpus[cpu].hotplug_thresh_clear = false;
		cpus[cpu].max_freq = false;
		cpus[cpu].user_max_freq = UINT_MAX;
		cpus[cpu].user_min_freq = 0;
		cpus[cpu].limited_max_freq = UINT_MAX;
		cpus[cpu].limited_min_freq = 0;
		cpus[cpu].freq_thresh_clear = false;
	}
	BUG_ON(!pdata);
	memcpy(&msm_thermal_info, pdata, sizeof(struct msm_thermal_data));

	if (check_sensor_id(msm_thermal_info.sensor_id)) {
		pr_err("Invalid sensor:%d for polling\n",
				msm_thermal_info.sensor_id);
		return -EINVAL;
	}

	enabled = 1;
	polling_enabled = 1;
	ret = cpufreq_register_notifier(&msm_thermal_cpufreq_notifier,
			CPUFREQ_POLICY_NOTIFIER);
	if (ret)
		pr_err("cannot register cpufreq notifier. err:%d\n", ret);

	INIT_DELAYED_WORK(&check_temp_work, check_temp);
	schedule_delayed_work(&check_temp_work, 0);

	if (num_possible_cpus() > 1)
		register_cpu_notifier(&msm_thermal_cpu_notifier);

	return ret;
}

static int ocr_reg_init(struct platform_device *pdev)
{
	int ret = 0;
	int i, j;

	for (i = 0; i < ocr_rail_cnt; i++) {
		/* Check if vdd_restriction has already initialized any
		 * regualtor handle. If so use the same handle.*/
		for (j = 0; j < rails_cnt; j++) {
			if (!strcmp(ocr_rails[i].name, rails[j].name)) {
				if (rails[j].reg == NULL)
					break;
				ocr_rails[i].phase_reg = rails[j].reg;
				goto reg_init;
			}

		}
		ocr_rails[i].phase_reg = devm_regulator_get(&pdev->dev,
					ocr_rails[i].name);
		if (IS_ERR_OR_NULL(ocr_rails[i].phase_reg)) {
			ret = PTR_ERR(ocr_rails[i].phase_reg);
			if (ret != -EPROBE_DEFER) {
				pr_err("%s, could not get regulator: %s\n",
					__func__, ocr_rails[i].name);
				ocr_rails[i].phase_reg = NULL;
				ocr_rails[i].mode = 0;
				ocr_rails[i].init = 0;
			}
			return ret;
		}
reg_init:
		ocr_rails[i].mode = OPTIMUM_CURRENT_MIN;
	}
	return ret;
}

static int vdd_restriction_reg_init(struct platform_device *pdev)
{
	int ret = 0;
	int i;

	for (i = 0; i < rails_cnt; i++) {
		if (rails[i].freq_req == 1) {
			usefreq |= BIT(i);
			check_freq_table();
			/*
			 * Restrict frequency by default until we have made
			 * our first temp reading
			 */
			if (freq_table_get)
				ret = vdd_restriction_apply_freq(&rails[i], 0);
			else
				pr_info("Defer vdd rstr freq init.\n");
		} else {
			rails[i].reg = devm_regulator_get(&pdev->dev,
					rails[i].name);
			if (IS_ERR_OR_NULL(rails[i].reg)) {
				ret = PTR_ERR(rails[i].reg);
				if (ret != -EPROBE_DEFER) {
					pr_err( \
					"could not get regulator: %s. err:%d\n",
					rails[i].name, ret);
					rails[i].reg = NULL;
					rails[i].curr_level = -2;
					return ret;
				}
				pr_info("Defer regulator %s probe\n",
					rails[i].name);
				return ret;
			}
			/*
			 * Restrict votlage by default until we have made
			 * our first temp reading
			 */
			ret = vdd_restriction_apply_voltage(&rails[i], 0);
		}
	}

	return ret;
}

static int psm_reg_init(struct platform_device *pdev)
{
	int ret = 0;
	int i = 0;
	int j = 0;

	for (i = 0; i < psm_rails_cnt; i++) {
		psm_rails[i].reg = rpm_regulator_get(&pdev->dev,
				psm_rails[i].name);
		if (IS_ERR_OR_NULL(psm_rails[i].reg)) {
			ret = PTR_ERR(psm_rails[i].reg);
			if (ret != -EPROBE_DEFER) {
				pr_err("couldn't get rpm regulator %s. err%d\n",
					psm_rails[i].name, ret);
				psm_rails[i].reg = NULL;
				goto psm_reg_exit;
			}
			pr_info("Defer regulator %s probe\n",
					psm_rails[i].name);
			return ret;
		}
		/* Apps default vote for PWM mode */
		psm_rails[i].init = PMIC_PWM_MODE;
		ret = rpm_regulator_set_mode(psm_rails[i].reg,
				psm_rails[i].init);
		if (ret) {
			pr_err("Cannot set PMIC PWM mode. err:%d\n", ret);
			return ret;
		} else
			psm_rails[i].mode = PMIC_PWM_MODE;
	}

	return ret;

psm_reg_exit:
	if (ret) {
		for (j = 0; j < i; j++) {
			if (psm_rails[j].reg != NULL)
				rpm_regulator_put(psm_rails[j].reg);
		}
	}

	return ret;
}

static struct kobj_attribute default_cpu_temp_limit_attr =
		__ATTR_RO(default_cpu_temp_limit);

static int msm_thermal_add_default_temp_limit_nodes(void)
{
	struct kobject *module_kobj = NULL;
	int ret = 0;

	if (!default_temp_limit_probed) {
		default_temp_limit_nodes_called = true;
		return ret;
	}
	if (!default_temp_limit_enabled)
		return ret;

	module_kobj = kset_find_obj(module_kset, KBUILD_MODNAME);
	if (!module_kobj) {
		pr_err("cannot find kobject\n");
		return -ENOENT;
	}

	sysfs_attr_init(&default_cpu_temp_limit_attr.attr);
	ret = sysfs_create_file(module_kobj, &default_cpu_temp_limit_attr.attr);
	if (ret) {
		pr_err(
		"cannot create default_cpu_temp_limit attribute. err:%d\n",
		ret);
		return ret;
	}
	return ret;
}

static int msm_thermal_add_vdd_rstr_nodes(void)
{
	struct kobject *module_kobj = NULL;
	struct kobject *vdd_rstr_kobj = NULL;
	struct kobject *vdd_rstr_reg_kobj[MAX_RAILS] = {0};
	int rc = 0;
	int i = 0;

	if (!vdd_rstr_probed) {
		vdd_rstr_nodes_called = true;
		return rc;
	}

	if (vdd_rstr_probed && rails_cnt == 0)
		return rc;

	module_kobj = kset_find_obj(module_kset, KBUILD_MODNAME);
	if (!module_kobj) {
		pr_err("cannot find kobject\n");
		rc = -ENOENT;
		goto thermal_sysfs_add_exit;
	}

	vdd_rstr_kobj = kobject_create_and_add("vdd_restriction", module_kobj);
	if (!vdd_rstr_kobj) {
		pr_err("cannot create vdd_restriction kobject\n");
		rc = -ENOMEM;
		goto thermal_sysfs_add_exit;
	}

	rc = sysfs_create_group(vdd_rstr_kobj, &vdd_rstr_en_attribs_gp);
	if (rc) {
		pr_err("cannot create kobject attribute group. err:%d\n", rc);
		rc = -ENOMEM;
		goto thermal_sysfs_add_exit;
	}

	for (i = 0; i < rails_cnt; i++) {
		vdd_rstr_reg_kobj[i] = kobject_create_and_add(rails[i].name,
					vdd_rstr_kobj);
		if (!vdd_rstr_reg_kobj[i]) {
			pr_err("cannot create kobject for %s\n",
					rails[i].name);
			rc = -ENOMEM;
			goto thermal_sysfs_add_exit;
		}

		rails[i].attr_gp.attrs = kzalloc(sizeof(struct attribute *) * 3,
					GFP_KERNEL);
		if (!rails[i].attr_gp.attrs) {
			pr_err("kzalloc failed\n");
			rc = -ENOMEM;
			goto thermal_sysfs_add_exit;
		}

		VDD_RES_RW_ATTRIB(rails[i], rails[i].level_attr, 0, level);
		VDD_RES_RO_ATTRIB(rails[i], rails[i].value_attr, 1, value);
		rails[i].attr_gp.attrs[2] = NULL;

		rc = sysfs_create_group(vdd_rstr_reg_kobj[i],
				&rails[i].attr_gp);
		if (rc) {
			pr_err("cannot create attribute group for %s. err:%d\n",
					rails[i].name, rc);
			goto thermal_sysfs_add_exit;
		}
	}

	return rc;

thermal_sysfs_add_exit:
	if (rc) {
		for (i = 0; i < rails_cnt; i++) {
			kobject_del(vdd_rstr_reg_kobj[i]);
			kfree(rails[i].attr_gp.attrs);
		}
		if (vdd_rstr_kobj)
			kobject_del(vdd_rstr_kobj);
	}
	return rc;
}

static int msm_thermal_add_ocr_nodes(void)
{
	struct kobject *module_kobj = NULL;
	struct kobject *ocr_kobj = NULL;
	struct kobject *ocr_reg_kobj[MAX_RAILS] = {0};
	int rc = 0;
	int i = 0;

	if (!ocr_probed) {
		ocr_nodes_called = true;
		return rc;
	}

	if (ocr_probed && ocr_rail_cnt == 0)
		return rc;

	module_kobj = kset_find_obj(module_kset, KBUILD_MODNAME);
	if (!module_kobj) {
		pr_err("%s: cannot find kobject for module %s\n",
			__func__, KBUILD_MODNAME);
		rc = -ENOENT;
		goto ocr_node_exit;
	}

	ocr_kobj = kobject_create_and_add("opt_curr_req", module_kobj);
	if (!ocr_kobj) {
		pr_err("%s: cannot create ocr kobject\n", KBUILD_MODNAME);
		rc = -ENOMEM;
		goto ocr_node_exit;
	}

	for (i = 0; i < ocr_rail_cnt; i++) {
		ocr_reg_kobj[i] = kobject_create_and_add(ocr_rails[i].name,
					ocr_kobj);
		if (!ocr_reg_kobj[i]) {
			pr_err("%s: cannot create for kobject for %s\n",
					KBUILD_MODNAME, ocr_rails[i].name);
			rc = -ENOMEM;
			goto ocr_node_exit;
		}
		ocr_rails[i].attr_gp.attrs = kzalloc( \
				sizeof(struct attribute *) * 2, GFP_KERNEL);
		if (!ocr_rails[i].attr_gp.attrs) {
			rc = -ENOMEM;
			goto ocr_node_exit;
		}

		OCR_RW_ATTRIB(ocr_rails[i], ocr_rails[i].mode_attr, 0, mode);
		ocr_rails[i].attr_gp.attrs[1] = NULL;

		rc = sysfs_create_group(ocr_reg_kobj[i], &ocr_rails[i].attr_gp);
		if (rc) {
			pr_err("%s: cannot create attribute group for %s\n",
				KBUILD_MODNAME, ocr_rails[i].name);
			goto ocr_node_exit;
		}
	}

ocr_node_exit:
	if (rc) {
		for (i = 0; i < ocr_rail_cnt; i++) {
			if (ocr_reg_kobj[i])
				kobject_del(ocr_reg_kobj[i]);
			if (ocr_rails[i].attr_gp.attrs) {
				kfree(ocr_rails[i].attr_gp.attrs);
				ocr_rails[i].attr_gp.attrs = NULL;
			}
		}
		if (ocr_kobj)
			kobject_del(ocr_kobj);
	}
	return rc;
}

static int msm_thermal_add_psm_nodes(void)
{
	struct kobject *module_kobj = NULL;
	struct kobject *psm_kobj = NULL;
	struct kobject *psm_reg_kobj[MAX_RAILS] = {0};
	int rc = 0;
	int i = 0;

	if (!psm_probed) {
		psm_nodes_called = true;
		return rc;
	}

	if (psm_probed && psm_rails_cnt == 0)
		return rc;

	module_kobj = kset_find_obj(module_kset, KBUILD_MODNAME);
	if (!module_kobj) {
		pr_err("cannot find kobject\n");
		rc = -ENOENT;
		goto psm_node_exit;
	}

	psm_kobj = kobject_create_and_add("pmic_sw_mode", module_kobj);
	if (!psm_kobj) {
		pr_err("cannot create psm kobject\n");
		rc = -ENOMEM;
		goto psm_node_exit;
	}

	for (i = 0; i < psm_rails_cnt; i++) {
		psm_reg_kobj[i] = kobject_create_and_add(psm_rails[i].name,
					psm_kobj);
		if (!psm_reg_kobj[i]) {
			pr_err("cannot create kobject for %s\n",
					psm_rails[i].name);
			rc = -ENOMEM;
			goto psm_node_exit;
		}
		psm_rails[i].attr_gp.attrs = kzalloc( \
				sizeof(struct attribute *) * 2, GFP_KERNEL);
		if (!psm_rails[i].attr_gp.attrs) {
			pr_err("kzalloc failed\n");
			rc = -ENOMEM;
			goto psm_node_exit;
		}

		PSM_RW_ATTRIB(psm_rails[i], psm_rails[i].mode_attr, 0, mode);
		psm_rails[i].attr_gp.attrs[1] = NULL;

		rc = sysfs_create_group(psm_reg_kobj[i], &psm_rails[i].attr_gp);
		if (rc) {
			pr_err("cannot create attribute group for %s. err:%d\n",
					psm_rails[i].name, rc);
			goto psm_node_exit;
		}
	}

	return rc;

psm_node_exit:
	if (rc) {
		for (i = 0; i < psm_rails_cnt; i++) {
			kobject_del(psm_reg_kobj[i]);
			kfree(psm_rails[i].attr_gp.attrs);
		}
		if (psm_kobj)
			kobject_del(psm_kobj);
	}
	return rc;
}
>>>>>>> df2159f0784... msm: thermal: Remove alarm support in KTM

    if (bricked_thermal_throttled == 3) {
        len += sprintf(buf + len, "%s %llu\n", "max",
                       (msm_thermal_stats.time_max +
                        (ktime_to_ms(ktime_get()) -
                         msm_thermal_stats.time_max_start)));
    } else
        len += sprintf(buf + len, "%s %llu\n", "max", msm_thermal_stats.time_max);

    return len;
}
define_one_global_ro(throttle_times);

static ssize_t show_is_throttled(struct kobject *a, struct attribute *b,
                                 char *buf)
{
    return sprintf(buf, "%u\n", bricked_thermal_throttled);
}
define_one_global_ro(is_throttled);

static struct attribute *msm_thermal_stats_attributes[] = {
    &is_throttled.attr,
    &throttle_times.attr,
    NULL
};


static struct attribute_group msm_thermal_stats_attr_group = {
    .attrs = msm_thermal_stats_attributes,
    .name = "stats",
};
/**************************** SYSFS END ****************************/

int __init msm_thermal_init(struct msm_thermal_data *pdata)
{
    int ret = 0, rc = 0;

    BUG_ON(!pdata);
    BUG_ON(pdata->sensor_id >= TSENS_MAX_SENSORS);
    memcpy(&msm_thermal_info, pdata, sizeof(struct msm_thermal_data));

    enabled = 1;
    check_temp_workq=alloc_workqueue("msm_thermal", WQ_UNBOUND | WQ_RESCUER, 1);
    if (!check_temp_workq)
        BUG_ON(ENOMEM);
    INIT_DELAYED_WORK(&check_temp_work, check_temp);
    queue_delayed_work(check_temp_workq, &check_temp_work, 0);

    msm_thermal_kobject = kobject_create_and_add("msm_thermal", kernel_kobj);
    if (msm_thermal_kobject) {
        rc = sysfs_create_group(msm_thermal_kobject, &msm_thermal_attr_group);
        if (rc) {
            pr_warn("msm_thermal: sysfs: ERROR, could not create sysfs group");
        }
        rc = sysfs_create_group(msm_thermal_kobject,
                                &msm_thermal_stats_attr_group);
        if (rc) {
            pr_warn("msm_thermal: sysfs: ERROR, could not create sysfs stats group");
        }
    } else
        pr_warn("msm_thermal: sysfs: ERROR, could not create sysfs kobj");

    pr_info("%s complete.", __func__);

<<<<<<< HEAD
    return ret;
=======
int __init msm_thermal_late_init(void)
{
	if (num_possible_cpus() > 1)
		msm_thermal_add_cc_nodes();
	msm_thermal_add_psm_nodes();
	msm_thermal_add_vdd_rstr_nodes();
	msm_thermal_add_ocr_nodes();
	msm_thermal_add_default_temp_limit_nodes();

	interrupt_mode_init();
	return 0;
>>>>>>> df2159f0784... msm: thermal: Remove alarm support in KTM
}

