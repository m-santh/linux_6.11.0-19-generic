#include <linux/module.h>
#include <linux/cgroup.h>
#include <linux/mutex.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/cgroup_gpu_mem.h>

/* Struct for tracking GPU memory usage per cgroup */
struct gpu_mem_cgroup {
    struct cgroup_subsys_state css;
    unsigned long hard_limit;  /* Hard limit on GPU memory */
    unsigned long soft_limit;  /* Soft limit (preferred max beyond hard-limit) */
    unsigned long prop_hard_limit;  /* proportionate hard limit (preferred max beyond hard-limit) */
    unsigned long curr_gpu_mem_used;  /* current gpu memory used */
    int mode;                  /* Mode (strict = 8, proportionate = 88) */
    int weight;                /* proportionate weight */
    int eviction;
    spinlock_t lock;
};

static char *eviction_policy[] = {
	"priority",
	"lru",
	"greedy",
	"weights",
	"hints"
};

static char *gpu_app_mode_name[] = {
	"strict",
	"proportionate"
};

/* Global cgroup variables */
static spinlock_t gpu_lock;
//static int eviction = EVICTION_PRIORITY;
static unsigned long strict_mode_gpu_mem, proportionate_mode_gpu_mem, soft_gpu_mem_usage;

#define NUM_POLICIES (sizeof(eviction_policy) / sizeof(eviction_policy[0]))

/* Convert string to integer */
static EvictionPolicy eviction_policy_to_int(const char *policy, int nbytes) {
    int i;
    for (i = 0; i < NUM_POLICIES; i++) {
        if (strncmp(policy, eviction_policy[i], nbytes) == 0) {
            return (EvictionPolicy)i;
        }
    }
    pr_info("eviction policy %s\n", policy);
    return EVICTION_INVALID; // Return invalid if not found
}

/* Convert integer to string */
static const char *eviction_policy_to_string(EvictionPolicy policy) {
    if (policy >= 0 && policy < NUM_POLICIES) {
        return eviction_policy[policy];
    }
    return "invalid"; // Handle invalid input
}

static int mode_str_to_int(const char *input, int nbytes) {
    if(strncmp(input, gpu_app_mode_name[0], nbytes) == 0) {
	    return STRICT_MODE;
    }
    else if(strncmp(input, gpu_app_mode_name[1], nbytes) == 0) {
	    return PROPORTIONATE_MODE;
    }
    else {
        pr_info("mode write %s\n", input);
	return -EINVAL;
    }
}

static const char *mode_int_to_string(int mode) {
    if (mode == STRICT_MODE)
	    return gpu_app_mode_name[0];
    else  if(mode == PROPORTIONATE_MODE)
	    return gpu_app_mode_name[1];
    else
	    return "Invalid";
}

/* Convert from css to gpu_mem_cgroup */
static struct gpu_mem_cgroup *gpu_mem_cgroup_from_css(struct cgroup_subsys_state *css) {
    return css ? container_of(css, struct gpu_mem_cgroup, css) : NULL;
}

static void notify_uvm_about_cgroup_change(struct cgroup_subsys_state *css, GPUChangeCommand cmd, unsigned long new_val) {
    struct task_struct *task;
    struct css_task_iter it;
    pid_t pid;

    /* if no callback registered, nothing to do */
    if (gpu_mem_task_callback == NULL) 
	    return;

    /* Iterate over tasks in the cgroup to find if a specific process is targeted */
    /* assumes the new value is different */
    css_task_iter_start(css, 0, &it);
    while ((task = css_task_iter_next(&it))) {
        pid = task_pid_nr(task);
        if (pid > 0) {
            printk("Applying GPU limit change to PID %d\n", pid);
            gpu_mem_task_callback(pid, cmd, new_val);
        }
    }
    css_task_iter_end(&it);
}

/* Read and write functions for GPU memory limits */
static u64 gpu_mem_ml_read(struct cgroup_subsys_state *css, struct cftype *cft) {
    struct gpu_mem_cgroup *cg = gpu_mem_cgroup_from_css(css);
    return cg->hard_limit;
}

static ssize_t gpu_mem_ml_write(struct kernfs_open_file *of, char *buf, size_t nbytes, loff_t off) {
    struct gpu_mem_cgroup *cg = gpu_mem_cgroup_from_css(of_css(of));
    unsigned long limit;
    if (kstrtoul(buf, 10, &limit))
        return -EINVAL;

    spin_lock(&cg->lock);
    if (cg->hard_limit != limit)
	    notify_uvm_about_cgroup_change(of_css(of), HARD_LIMIT_CHANGE, limit);

    cg->hard_limit = limit;
    spin_unlock(&cg->lock);

    return nbytes;
}

static u64 gpu_mem_sl_read(struct cgroup_subsys_state *css, struct cftype *cft) {
    struct gpu_mem_cgroup *cg = gpu_mem_cgroup_from_css(css);
    return cg->soft_limit;
}

static ssize_t gpu_mem_sl_write(struct kernfs_open_file *of, char *buf, size_t nbytes, loff_t off) {
    struct gpu_mem_cgroup *cg = gpu_mem_cgroup_from_css(of_css(of));
    unsigned long limit;
    if (kstrtoul(buf, 10, &limit))
        return -EINVAL;

    spin_lock(&cg->lock);
    if (cg->soft_limit != limit)
	    notify_uvm_about_cgroup_change(of_css(of), SOFT_LIMIT_CHANGE, limit);

    cg->soft_limit = limit;
    spin_unlock(&cg->lock);

    return nbytes;
}

static int gpu_mem_mode_read(struct seq_file *sf, void *v)
{
    struct cgroup_subsys_state *css = seq_css(sf);
    struct gpu_mem_cgroup *cg = gpu_mem_cgroup_from_css(css);
    const char *mode = mode_int_to_string(cg->mode);

    pr_info("mode read sf %p, css %p cg %p\n", sf, css, cg);

    seq_printf(sf, "%s\n", mode);

    return 0;
}

static ssize_t gpu_mem_mode_write(struct kernfs_open_file *of, char *buf, size_t nbytes, loff_t off) {
    struct gpu_mem_cgroup *cg = gpu_mem_cgroup_from_css(of_css(of));
    int mode;
   
    if (nbytes > 0 && buf[nbytes -1] == '\n')
	    buf[nbytes - 1] = '\0';

    mode = mode_str_to_int(buf, nbytes);

    if(mode == -EINVAL) {
	return -EINVAL;
    }

    spin_lock(&cg->lock);
    if (cg->mode != mode)
	    notify_uvm_about_cgroup_change(of_css(of), MODE_CHANGE, mode);

    cg->mode = mode;
    spin_unlock(&cg->lock);

    return nbytes;
}

static int gpu_mem_eviction_read(struct seq_file *sf, void *v)
{
    struct gpu_mem_cgroup *cg = gpu_mem_cgroup_from_css(seq_css(sf));
    const char *str_eviction = eviction_policy_to_string(cg->eviction);

    seq_printf(sf, "%s\n", str_eviction);

    return 0;
}

static ssize_t gpu_mem_eviction_write(struct kernfs_open_file *of, char *buf, size_t nbytes, loff_t off) {
    struct gpu_mem_cgroup *cg = gpu_mem_cgroup_from_css(of_css(of));
    int local_eviction;

    if (nbytes > 0 && buf[nbytes -1] == '\n')
	    buf[nbytes - 1] = '\0';

    local_eviction = eviction_policy_to_int(buf, nbytes);
    if (local_eviction == EVICTION_INVALID)
	    return -EINVAL;

    spin_lock(&cg->lock);
    if (cg->eviction != local_eviction)
	    notify_uvm_about_cgroup_change(of_css(of), EVICTION_CHANGE, local_eviction);

    cg->eviction = local_eviction;
    spin_unlock(&cg->lock);

    return nbytes;
}

static u64 gpu_mem_weight_read(struct cgroup_subsys_state *css, struct cftype *cft) {
    struct gpu_mem_cgroup *cg = gpu_mem_cgroup_from_css(css);
    return (u64)cg->weight;
}

static ssize_t gpu_mem_weight_write(struct kernfs_open_file *of, char *buf, size_t nbytes, loff_t off) {
    struct gpu_mem_cgroup *cg = gpu_mem_cgroup_from_css(of_css(of));
    int weight;
    if (kstrtoint(buf, 10, &weight))
        return -EINVAL;

    spin_lock(&cg->lock);
    if (cg->weight != weight)
	    notify_uvm_about_cgroup_change(of_css(of), WEIGHT_CHANGE, weight);

    cg->weight = weight;
    spin_unlock(&cg->lock);

    return nbytes;
}

static u64 gpu_mem_phl_read(struct cgroup_subsys_state *css, struct cftype *cft) {

    struct gpu_mem_cgroup *cg = gpu_mem_cgroup_from_css(css);
    return cg->prop_hard_limit;
}

static u64 gpu_mem_usage_read(struct cgroup_subsys_state *css, struct cftype *cft) {

    struct gpu_mem_cgroup *cg = gpu_mem_cgroup_from_css(css);
    return cg->curr_gpu_mem_used;
}

/* Get the total gpu memory used by strict applications */
static u64 gpu_mem_strict_read(struct cgroup_subsys_state *css, struct cftype *cft) {

    return strict_mode_gpu_mem;
}

/* Get the total gpu memory used by proportionate applications */
static u64 gpu_mem_ps_read(struct cgroup_subsys_state *css, struct cftype *cft) {

    return proportionate_mode_gpu_mem;
}

/* Get the total gpu memory used beyond hard-limits */
static u64 gpu_mem_su_read(struct cgroup_subsys_state *css, struct cftype *cft) {

    return soft_gpu_mem_usage;
}

static ssize_t gpu_mem_dummy_write(struct kernfs_open_file *of, char *buf, size_t nbytes, loff_t off) {
	return 0;
}

/* Read and write functions for other parameters (soft_limit, mode, weight) */
static struct cftype gpu_mem_files[] = {
    {
        .name = "hard_limit",
        .read_u64 = gpu_mem_ml_read,
        .write = gpu_mem_ml_write,
    },
    {
        .name = "soft_limit",
        .read_u64 = gpu_mem_sl_read,
        .write = gpu_mem_sl_write,
    },
    {
        .name = "mode",
        .seq_show = gpu_mem_mode_read,
        .write = gpu_mem_mode_write,
    },
    {
        .name = "weight",
        .read_u64 = gpu_mem_weight_read,
        .write = gpu_mem_weight_write,
    },
    {
        .name = "eviction",
        .seq_show = gpu_mem_eviction_read,
        .write = gpu_mem_eviction_write,
    },
    {
        .name = "prop_hard_limit",
        .read_u64 = gpu_mem_phl_read,
        .write = gpu_mem_dummy_write,
    },
    {
        .name = "curr_usage",
        .read_u64 = gpu_mem_usage_read,
        .write = gpu_mem_dummy_write,
    },
    {
        .name = "strict_mode_usage",
        .read_u64 = gpu_mem_strict_read,
        .write = gpu_mem_dummy_write,
    },
    {
        .name = "prop_mode_usage",
        .read_u64 = gpu_mem_ps_read,
        .write = gpu_mem_dummy_write,
    },
    {
        .name = "soft_mode_usage",
        .read_u64 = gpu_mem_su_read,
        .write = gpu_mem_dummy_write,
    },
    { } /* End of array */
};

/* Allocate and free cgroup state */
static struct cgroup_subsys_state *gpu_mem_css_alloc(struct cgroup_subsys_state *parent) {
    struct gpu_mem_cgroup *cg;
    cg = kzalloc(sizeof(*cg), GFP_KERNEL);
    if (!cg)
        return ERR_PTR(-ENOMEM);

    cg->hard_limit = ULONG_MAX;  /* Hard limit on GPU memory */
    cg->soft_limit = ULONG_MAX;  /* Soft limit (preferred max beyond hard-limit) */
    cg->prop_hard_limit = ULONG_MAX;  /* proportionate hard limit (preferred max beyond hard-limit) */
    cg->curr_gpu_mem_used = 0;  /* current gpu memory used */
    cg->mode = PROPORTIONATE_MODE;                  /* Mode (strict = 8, proportionate = 88) */
    cg->weight = 1;                /* proportionate weight */
    cg->eviction = EVICTION_PRIORITY;
    spin_lock_init(&cg->lock);
    return &cg->css;
}

static void gpu_mem_css_free(struct cgroup_subsys_state *css) {
    kfree(gpu_mem_cgroup_from_css(css));
}

/* Define cgroup v2 subsystem */
struct cgroup_subsys gpu_mem_cgrp_subsys = {
    .css_alloc = gpu_mem_css_alloc,
    .css_free = gpu_mem_css_free,
    .legacy_cftypes = gpu_mem_files,
    .dfl_cftypes = gpu_mem_files,
    .name = "gpu_mem",
};

/*
int get_gpu_mem_cgroup_eviction_policy(void) {
	return eviction;
}
EXPORT_SYMBOL(get_gpu_mem_cgroup_eviction_policy);
*/

int set_gpu_mem_cgroup_global_gpu_mem(unsigned long strict_mem, unsigned long proportionate_mem, unsigned long soft_mem) {
    spin_lock(&gpu_lock);
    strict_mode_gpu_mem = strict_mem;
    proportionate_mode_gpu_mem = proportionate_mem;
    soft_gpu_mem_usage = soft_mem;
    spin_unlock(&gpu_lock);
    return 0;
}
EXPORT_SYMBOL(set_gpu_mem_cgroup_global_gpu_mem);

int get_gpu_mem_cgroup_task_limits(struct task_struct *task, unsigned long *hard_limit, unsigned long *soft_limit, int *mode, int *weight, int *eviction)
{
    struct cgroup_subsys_state *css;
    struct gpu_mem_cgroup *cg;
    if (task == NULL)
	    return -EINVAL;

    /* Get the subsystem state (css) for the gpu_mem_limit cgroup */
    css = task_css(task, gpu_mem_cgrp_subsys.id);
    if (!css)
        return -EINVAL; 

    cg = gpu_mem_cgroup_from_css(css);
    *hard_limit = cg->hard_limit;
    *soft_limit = cg->soft_limit;
    *mode =  cg->mode;
    *weight =  cg->weight;
    *eviction =  cg->eviction;

    return 0;
}
EXPORT_SYMBOL(get_gpu_mem_cgroup_task_limits);

int set_gpu_mem_cgroup_task_limits(struct task_struct *task, unsigned long prop_limit, unsigned long curr_usage)
{
    struct cgroup_subsys_state *css;
    struct gpu_mem_cgroup *cg;
    if (task == NULL)
	    return -EINVAL;

    /* Get the subsystem state (css) for the gpu_mem_limit cgroup */
    css = task_css(task, gpu_mem_cgrp_subsys.id);
    if (!css)
        return -EINVAL; 

    cg = gpu_mem_cgroup_from_css(css);

    spin_lock(&cg->lock);
    cg->prop_hard_limit = prop_limit;
    cg->curr_gpu_mem_used = curr_usage;
    spin_unlock(&cg->lock);

    return 0;
}
EXPORT_SYMBOL(set_gpu_mem_cgroup_task_limits);

void register_gpu_mem_cgroup_callback(get_gpu_mem_cgroup_task_limit_change_t cb)
{
    gpu_mem_task_callback = cb;
}
EXPORT_SYMBOL(register_gpu_mem_cgroup_callback);

/*
static int __init gpu_mem_cgroup_init(void) {
    spin_lock_init(&gpu_lock);
    return cgroup_add_subsys(&gpu_mem_cgrp_subsys);
}

static void __exit gpu_mem_cgroup_exit(void) {
    cgroup_remove_subsys(&gpu_mem_cgrp_subsys);
}

module_init(gpu_mem_cgroup_init);
module_exit(gpu_mem_cgroup_exit);
*/
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Santhosh Kumar, IITB");
MODULE_DESCRIPTION("GPU Memory Cgroup Controller");

