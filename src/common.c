#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sched.h>
#include "common.h"

char *strdup(const char *s)
{
    char *dst = malloc(strlen(s) + 1);
    if (!dst)
        return NULL;

    strcpy(dst, s);
    return dst;
}

pid_t gettid(void)
{
    return syscall(SYS_gettid);
}

int get_current_cpu(void)
{
    cpu_set_t cpuset;
    int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    int cpu_core = -1;

    /* Get the affinity mask of the current process */
    sched_getaffinity(0, sizeof(cpuset), &cpuset);

    /* Find the first CPU in the affinity mask */
    for (int i = 0; i < num_cpus; i++) {
        if (CPU_ISSET(i, &cpuset)) {
            cpu_core = i;
            break;
        }
    }
    return cpu_core;
}
