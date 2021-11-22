#include "libsus.h"
#include <errno.h>
#include <fcntl.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define FKSM_ADDR "/fksm-test-addrs"
#define FKSM_PIDS "/fksm-test-pids"
#define PAGES_PER_PID 5
#define NUM_PIDS 2
#define NUM_CHILDREN (NUM_PIDS - 1)

int child(int num)
{
    // TOOD: error checking
    int addrs_fd = shm_open(FKSM_ADDR, O_RDWR, S_IRUSR | S_IWUSR);
    if (addrs_fd == -1)
    {
        perror("addr shm_open failed");
        exit(EXIT_FAILURE);
    }
    int pids_fd = shm_open(FKSM_PIDS, O_RDWR, S_IRUSR | S_IWUSR);
    if (pids_fd == -1)
    {
        perror("pids shm_open failed");
        exit(EXIT_FAILURE);
    }
    void** addrs = mmap(NULL, sizeof(void*) * PAGES_PER_PID * NUM_PIDS,
                        PROT_READ | PROT_WRITE, MAP_SHARED, addrs_fd, 0);
    if (addrs == MAP_FAILED)
    {
        perror("addrs mmap failed");
        exit(EXIT_FAILURE);
    }
    pid_t* pids = mmap(NULL, sizeof(pid_t) * NUM_PIDS, PROT_READ | PROT_WRITE,
                       MAP_SHARED, pids_fd, 0);
    if (pids == MAP_FAILED)
    {
        perror("pids mmap failed");
        exit(EXIT_FAILURE);
    }

    pids[(1 + (1 * num))] = getpid(); // offset by 1 for the children segment,
                                      // then offset by num of the child
    int child_offset = PAGES_PER_PID * num;//offset for which child we are
    for (int i = 0; i < PAGES_PER_PID; i++)
    {
        addrs[(child_offset + PAGES_PER_PID + i)] =
            malloc(sizeof(char) * 4096);
    }

    return 0;
}

int main(void)
{
    // TODO: BLAKE2b each page from userspace and print hashes
    // TODO: call ioctl and print hashes 

    int addrs_fd =
        shm_open(FKSM_ADDR, O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IWUSR);
    if (addrs_fd == -1)
    {
        perror("addr shm_open failed");
        exit(EXIT_FAILURE);
    }
    int pids_fd =
        shm_open(FKSM_PIDS, O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IWUSR);
    if (pids_fd == -1)
    {
        perror("pids shm_open failed");
        exit(EXIT_FAILURE);
    }

    void** addrs = mmap(NULL, sizeof(void*) * 10, PROT_READ | PROT_WRITE,
                        MAP_SHARED, addrs_fd, 0);
    if (addrs == MAP_FAILED)
    {
        perror("addrs mmap failed");
        exit(EXIT_FAILURE);
    }
    pid_t* pids = mmap(NULL, sizeof(pid_t) * 2, PROT_READ | PROT_WRITE,
                       MAP_SHARED, pids_fd, 0);
    if (pids == MAP_FAILED)
    {
        perror("pids mmap failed");
        exit(EXIT_FAILURE);
    }

    pids[0] = getpid();
    for (int i = 0; i < PAGES_PER_PID; i++)
    {
        addrs[i] = malloc(sizeof(char) * 4096);
    }

    pid_t cpid;
    cpid = fork();
    if (cpid == -1)
    {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (cpid == 0)
    { /* Code executed by child */
        printf("%d | %d \n", getppid(), getpid());
        child(0);
        return 0;
    }
    else
    { /* Code executed by parent */
        sleep(1);
        // TODO: BLAKE2b hash each page here
    }

    int fd = sus_open();
    if (fd <= 0)
    {
        printf("Error opening ioctl: %d\n", errno);
        goto release;
    }
    int ret = sus_fksm_merge(fd, pids[0], pids[1]);
    if (ret != 0)
    {
        printf("Error writing to ioctl: %d\n", ret);
        goto release;
    }
    else
    {
        printf("Wrote to ioctl\n");
    }
    sleep(15); // arbitrary
    printf("Slept\n");
    sus_close(fd);
    printf("Closed ioctl\n");

release:
    free(pids);
    for (int i = 0; i < PAGES_PER_PID * NUM_PIDS; i++)
    {
        free(addrs[i]);
    }
    free(addrs);
    shm_unlink(FKSM_ADDR);
    shm_unlink(FKSM_PIDS);

    return 0;
}
