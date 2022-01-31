#include "libsus.h"
#include <blake2.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <semaphore.h>
#include <stdint.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define FKSM_ADDR "/fksm-test-addrs"
#define FKSM_PIDS "/fksm-test-pids"
#define PAGES_PER_PID 15
#define NUM_PIDS 2
#define NUM_CHILDREN (NUM_PIDS - 1)
#define ADDR_SEGMENT_SIZE                                                      \
    (8 * NUM_PIDS * PAGES_PER_PID) // 8 byte pointers for each segment
#define PIDS_SEGMENT_SIZE                                                      \
    (4 * NUM_PIDS) // 4 bytes for 32 bit int * number of pids

static pthread_t threads[2];

static void print_bytes(uint8_t* input, size_t size)
{
    size_t i;
    for (i = 0; i < size; i++)
    {
        printf("%02X", input[i]);
    }
    printf("\n");
}

static inline void fail_fast()
{
    __asm__("ud2");
}

static void* thread_function(void* arg)
{
    (void)arg;
    printf("started %d\n", gettid());
    sleep(10);
    printf("done %d\n", gettid());
    return NULL;
}

static void ufrk_fork_test(int fd)
{
    pid_t pid = fork();

    if (pid > 0)
    {
        // parent process
        // IMPORTANT: we pass getpid() here, not the pid of the child.
        printf("Parent PID: %d, TID: %d\n", getpid(), gettid());
        sus_ufrk_fork(fd, getpid(), 0);
        // fail_fast();
        printf("Survived ufrk: %d,%d\n", getpid(), gettid());

        pthread_create(&threads[0], NULL, thread_function, NULL);
        sleep(10);
    }
    else if (pid == 0)
    {
        // child process
        printf("Child PID: %d, TID: %d\n", getpid(), gettid());
        pthread_create(&threads[1], NULL, thread_function, NULL);
        sleep(10);
        printf("Child PID: %d, TID: %d\n", getpid(), gettid());
    }
    else
    {
        printf("Unable to fork test process\n");
    }
}

static void print_help(const char* progname)
{
    printf("%s -[uh]\nu: ultrafork test\nh: print help\n", progname);
}

int child(int num, int addr_segment_id, int pids_segment_id)
{
    void** addrs = shmat(addr_segment_id, 0, 0);
    int* pids = shmat(pids_segment_id, 0, 0);

    pids[(1 + num)] = getpid(); // offset by 1 for the children segment,
                                // then offset by num of the current child
    int child_offset;
    child_offset = PAGES_PER_PID *
                   (num + 1); // offset in addrs based on which child we are
    for (int i = 0; i < PAGES_PER_PID; i++)
    {
        addrs[(child_offset + i)] = aligned_alloc(getpagesize(), getpagesize());
        memset(addrs[(child_offset + i)], 0xaa, getpagesize());
    }
    shmdt(addrs);
    shmdt(pids);

    sleep(60);
    return 0;
}

int fksm_parent(int fd)
{
    void** addrs;
    int* pids;
    int i;

    int addr_segment_id;
    addr_segment_id = shmget(IPC_PRIVATE, ADDR_SEGMENT_SIZE,
                             IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR);
    if (addr_segment_id == -1)
    {
        perror("addr_shmget");
    }
    // todo: attach after fork

    int pids_segment_id;
    pids_segment_id = shmget(IPC_PRIVATE, PIDS_SEGMENT_SIZE,
                             IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR);
    if (pids_segment_id == -1)
    {
        perror("pids_shmget");
    }
    // todo: check if shmget worked

    pid_t cpid;
    for (i = 0; i < NUM_CHILDREN; i++)
    {
        // fork off a child, check for errors, if in child process run function
        // then return if in parent process, loop back to start until for ends
        cpid = fork();
        if (cpid == -1)
        {
            perror("fork");
            exit(EXIT_FAILURE);
        }

        if (cpid == 0)
        { /* Code executed by child */
            // printf("%d | %d \n", getppid(), getpid());
            child(i, addr_segment_id, pids_segment_id);
            return 0;
        }
    }

    /* Code executed by parent */
    addrs = shmat(addr_segment_id, 0, 0);
    pids = shmat(pids_segment_id, 0, 0);
    pids[0] = getpid();
    for (int i = 0; i < PAGES_PER_PID; i++)
    {
        addrs[i] = aligned_alloc(getpagesize(), getpagesize());
        memset(addrs[i], 0xaa, getpagesize());
    }
    sleep(3);
    uint8_t blake2b_out[BLAKE2B_OUTBYTES];
    for (int i = 0; i < PAGES_PER_PID * NUM_PIDS; i++)
    {
        // print_bytes(addrs[i], getpagesize());
        int res = blake2b(blake2b_out, addrs[i], NULL, BLAKE2B_OUTBYTES,
                          getpagesize(), 0);
        if (res == -1)
        {
            printf("blake2b hash error");
        }
        else
        {
            printf("hash for #%d: %p \n", i, addrs[i]);
            print_bytes(blake2b_out, BLAKE2B_OUTBYTES);
        }
        memset(blake2b_out, 0, BLAKE2B_OUTBYTES);
        printf("\n");
    }

    /* int fd = sus_open(); */
    if (fd <= 0)
    {
        printf("Error opening ioctl: %d\n", errno);
        goto release;
    }
    for (i = 0; i < NUM_CHILDREN; i++)
    {
        int ret = sus_fksm_merge(fd, pids[0], pids[i + 1]);
        if (ret != 0)
        {
            printf("Error writing to ioctl: %d\n", ret);
            goto release;
        }
        else
        {
            printf("Wrote to ioctl\n");
        }
        sleep(1); // arbitrary
        printf("Slept\n");
    }

    /* sus_close(fd); */
    /* printf("Closed ioctl\n"); */

release:
    shmdt(pids);
    shmctl(pids_segment_id, IPC_RMID, 0);
    for (int i = 0; i < PAGES_PER_PID * NUM_PIDS; i++)
    {
        free(addrs[i]);
    }
    shmdt(addrs);
    shmctl(addr_segment_id, IPC_RMID, 0);

    return 0;
}

static int hash_tree(int fd)
{
    int test = sus_hash_tree_test(fd, 1);
    if (test == 0)
    {
        printf("ioctl ran through\n");
    }
    return test;
}

int main(int argc, char* argv[])
{
    int c;
    int fd = sus_open();
    while ((c = getopt(argc, argv, "uhfa")) != -1)
    {
        switch (c)
        {
        case 'u':
            ufrk_fork_test(fd);
            break;
        case 'f':
            fksm_parent(fd);
            break;
        case 'a':
            hash_tree(fd);
            break;
        case 'h':
        default:
            print_help(argv[0]);
            break;
        }
    }

    return sus_close(fd);
}
