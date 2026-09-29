#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>
int main(int argc, char **argv) {
    int pid = atoi(argv[1]);
    int mib[3] = {CTL_KERN, KERN_PROCARGS2, pid};
    size_t sz = 0;
    int r1 = sysctl(mib, 3, NULL, &sz, NULL, 0);
    char *buf = malloc(sz + 1); size_t sz2 = sz;
    int r2 = r1 == 0 ? sysctl(mib, 3, buf, &sz2, NULL, 0) : -1;
    int found = 0;
    for (size_t i = 0; r2 == 0 && i + 6 < sz2; i++) if (memcmp(buf + i, "MARKER", 6) == 0) found = 1;
    int mib2[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0}; size_t s3 = 0;
    int r3 = sysctl(mib2, 4, NULL, &s3, NULL, 0);
    int ncpu; size_t s4 = sizeof ncpu; int r4 = sysctlbyname("hw.ncpu", &ncpu, &s4, NULL, 0);
    printf("procargs2=%s env_marker=%s proc_all=%s(%zu) hw.ncpu=%s\n", r2==0?"READ":"denied", found?"LEAKED":"no", r3==0?"READ":"denied", s3, r4==0?"ok":"denied");
    return 0;
}
