#include "libsus.h"
#include <errno.h>
#include <stdio.h>

int main(void)
{
    int fd = sus_open();
    if (fd <= 0)
    {
        perror("Failed to open sus ioctl. Is the driver loaded?");
        return -1;
    }

    return sus_close(fd);
}
