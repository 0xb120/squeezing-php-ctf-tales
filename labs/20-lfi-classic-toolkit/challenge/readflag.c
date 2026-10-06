/* Prints the flag.  setuid root, because /flag.txt is 0400 root:root:
 * reading the file is not enough, you have to be able to *run* something. */
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    char buf[256];
    FILE *f;

    if (setuid(0) != 0 || setgid(0) != 0) {
        /* keep going: the open below is the real check */
    }
    f = fopen("/flag.txt", "r");
    if (!f) {
        fputs("cannot open /flag.txt\n", stderr);
        return 1;
    }
    while (fgets(buf, sizeof buf, f)) {
        fputs(buf, stdout);
    }
    fclose(f);
    return 0;
}
