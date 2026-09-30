// Tries to inject a keystroke into its controlling tty (stdin). Prints errno.
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
int main(void) {
    char c = 'x';
    int r = ioctl(0, TIOCSTI, &c);
    printf("%s\n", r == 0 ? "injected" : strerror(errno));
    return r == 0 ? 0 : 1;
}
