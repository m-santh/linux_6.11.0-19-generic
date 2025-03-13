#ifndef _LINUX_GPU_CGROUP_H
#define _LINUX_GPU_CGROUP_H

#include <linux/cgroup.h>
#include <linux/kernel.h>

#define STRICT_MODE	  8
#define PROPORTIONATE_MODE 88

typedef enum {
    HARD_LIMIT_CHANGE = 0,
    SOFT_LIMIT_CHANGE,
    MODE_CHANGE,
    WEIGHT_CHANGE,
    EVICTION_CHANGE,
    INVALID_CHANGE
} GPUChangeCommand;

typedef int (*get_gpu_mem_cgroup_task_limit_change_t)(pid_t pid, GPUChangeCommand cmd, unsigned long new_val);
static get_gpu_mem_cgroup_task_limit_change_t gpu_mem_task_callback = NULL;

typedef enum {
    EVICTION_PRIORITY = 0,
    EVICTION_LRU,
    EVICTION_GREEDY,
    EVICTION_WEIGHTS,
    EVICTION_HINTS,
    EVICTION_INVALID // Used for error handling
} EvictionPolicy;

int set_gpu_mem_cgroup_global_gpu_mem(unsigned long strict_mem, unsigned long proportionate_mem, unsigned long soft_mem);

int get_gpu_mem_cgroup_task_limits(struct task_struct *task, unsigned long *hard_limit, unsigned long *soft_limit, int *mode, int *weight, int *eviction);

int set_gpu_mem_cgroup_task_limits(struct task_struct *task, unsigned long prop_limit, unsigned long curr_usage);

void register_gpu_mem_cgroup_callback(get_gpu_mem_cgroup_task_limit_change_t cb);

#endif /* _LINUX_GPU_CGROUP_H */
