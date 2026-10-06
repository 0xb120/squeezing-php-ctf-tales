/* setuid helper: the flag is only readable by root, so command execution as
 * the web user is the only way to get it out. */
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    char buf[256];
    FILE *f;

    if (setuid(0) != 0)
        return 1;
    f = fopen("/flag.txt", "r");
    if (!f)
        return 1;
    while (fgets(buf, sizeof(buf), f))
        fputs(buf, stdout);
    fclose(f);
    return 0;
}
