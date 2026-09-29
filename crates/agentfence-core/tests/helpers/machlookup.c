// Exit 0 if every named Mach service can be looked up, 1 otherwise.
#include <servers/bootstrap.h>
#include <stdio.h>
int main(int argc, char **argv) {
    int failed = 0;
    for (int i = 1; i < argc; i++) {
        mach_port_t p = MACH_PORT_NULL;
        kern_return_t kr = bootstrap_look_up(bootstrap_port, argv[i], &p);
        printf("%s %s\n", argv[i], kr == KERN_SUCCESS ? "ok" : "denied");
        if (kr != KERN_SUCCESS) failed = 1;
    }
    return failed;
}
