#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/eventfd.h>

int main()
{
    int evfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if(evfd < 0)
    {
        perror("eventfd failed!\n");
        return -1;
    }

    uint64_t val = 1; // 必须以8字节为单位
    write(evfd, &val, sizeof(val));
    write(evfd, &val, sizeof(val));
    write(evfd, &val, sizeof(val));
    write(evfd, &val, sizeof(val));

    uint64_t ret = 0;
    read(evfd, &ret, sizeof(ret));
    printf("%ld\n", ret);

    return 0;
}