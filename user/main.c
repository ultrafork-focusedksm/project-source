#include "libsus.h"
#include <blake2.h>
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

void print_bytes(uint8_t* input, size_t size)
{
    size_t i;
    for (i = 0; i < size; i++)
    {
        printf("%02X", input[i]);
    }
    printf("\n");
}

int child(int num)
{
    int pids_fd = shm_open(FKSM_PIDS, O_RDWR, S_IRUSR | S_IWUSR);
    if (pids_fd == -1)
    {
        perror("pids shm_open failed");
        exit(EXIT_FAILURE);
    }
    if (ftruncate(pids_fd, sizeof(void*) * NUM_PIDS) == -1)
    {
        perror("pids ftruncate");
        exit(EXIT_FAILURE);
    }
    pid_t* pids = mmap(NULL, sizeof(pid_t) * NUM_PIDS, PROT_READ | PROT_WRITE,
                       MAP_SHARED, pids_fd, 0);
    if (pids == MAP_FAILED)
    {
        perror("pids mmap failed");
        exit(EXIT_FAILURE);
    }

    int addrs_fd = shm_open(FKSM_ADDR, O_RDWR, S_IRUSR | S_IWUSR);
    if (addrs_fd == -1)
    {
        perror("addr shm_open failed");
        exit(EXIT_FAILURE);
    }
    if (ftruncate(addrs_fd, sizeof(void*) * PAGES_PER_PID * NUM_PIDS) == -1)
    {
        perror("addrs ftruncate");
        exit(EXIT_FAILURE);
    }
    void** addrs = mmap(NULL, sizeof(void*) * PAGES_PER_PID * NUM_PIDS,
                        PROT_READ | PROT_WRITE, MAP_SHARED, addrs_fd, 0);
    if (addrs == MAP_FAILED)
    {
        perror("addrs mmap failed");
        exit(EXIT_FAILURE);
    }

    pids[(1 + num)] = getpid(); // offset by 1 for the children segment,
                                // then offset by num of the child
    int child_offset;
    child_offset = PAGES_PER_PID * num; // offset for which child we are
    for (int i = 0; i < PAGES_PER_PID; i++)
    {
        addrs[(child_offset + PAGES_PER_PID + i)] = malloc(getpagesize());
    }

    sleep(60);

    return 0;
}

int main(void)
{
    // TODO: call ioctl and print hashes
    // TODO: reset this after testing is done
    sus_hash_tree_test(sus_open(), 1);
    
    int pids_fd =
        shm_open(FKSM_PIDS, O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IWUSR);
    if (pids_fd == -1)
    {
        perror("pids shm_open failed");
        exit(EXIT_FAILURE);
    }
    if (ftruncate(pids_fd, sizeof(void*) * NUM_PIDS) == -1)
    {
        perror("pids ftruncate");
        exit(EXIT_FAILURE);
    }
    pid_t* pids = mmap(NULL, sizeof(pid_t) * NUM_PIDS, PROT_READ | PROT_WRITE,
                       MAP_SHARED, pids_fd, 0);
    if (pids == MAP_FAILED)
    {
        perror("pids mmap failed");
        exit(EXIT_FAILURE);
    }
    int addrs_fd =
        shm_open(FKSM_ADDR, O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IWUSR);
    if (addrs_fd == -1)
    {
        perror("addr shm_open failed");
        exit(EXIT_FAILURE);
    }
    if (ftruncate(addrs_fd, sizeof(void*) * PAGES_PER_PID * NUM_PIDS) == -1)
    {
        perror("addrs ftruncate");
        exit(EXIT_FAILURE);
    }
    void** addrs = mmap(NULL, sizeof(void*) * PAGES_PER_PID * NUM_PIDS,
                        PROT_READ | PROT_WRITE, MAP_SHARED, addrs_fd, 0);
    if (addrs == MAP_FAILED)
    {
        perror("addrs mmap failed");
        exit(EXIT_FAILURE);
    }

    pids[0] = getpid();
    for (int i = 0; i < PAGES_PER_PID; i++)
    {
        addrs[i] = malloc(sizeof(char) * getpagesize());
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
        uint8_t blake2b_out[BLAKE2B_OUTBYTES];
        for (int i = 0; i < PAGES_PER_PID * NUM_PIDS; i++)
        {
            int res = blake2b(blake2b_out, addrs[i], NULL, BLAKE2B_OUTBYTES,
                              getpagesize(),
                              0); // todo: add key and keylen?
            if (res == -1)
            {
                printf("blake2b hash error");
            }
            else
            {
                print_bytes(blake2b_out, BLAKE2B_OUTBYTES);
            }
        }
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
