#ifndef __COMMON_H_

#include <syscall.h>
#include <sched.h>

char *strdup(const char *s);
pid_t gettid(void);
int get_current_cpu(void);

#endif // !__COMMON_H_