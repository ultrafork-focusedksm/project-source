#include "libsus.h"
#include <blake2.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stdint.h>
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
#define PROCESS_SLEEP_TIME 60 * 5
#define BYTES_TO_KILO(x) (x / 1024)

enum sus_tester_mode
{
    NONE,
    UFRK,
    COW,
    FKSM,
    HTREE
};

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

/**
 * Function for terminating a process with a single instruction. This is an
 * ugly hack to look at the traps message the kernel prints, which the IP and
 * SP values, without screwing them up by jumping away from the interesting
 * area.
 *
 * This function _needs_ to be inlined,  otherwise it is useless.
 *
 * Obviously, this only supports x86.
 */
static inline __attribute__((always_inline)) void fail_fast()
{
    __asm__("ud2");
}

static void* thread_function(void* arg)
{
    (void)arg;
    printf("started %d %d\n", gettid(), getpid());
    sleep(PROCESS_SLEEP_TIME + 2);
    printf("done %d\n", gettid());
    return NULL;
}

static void ufrk_fork_test(int fd, bool threading)
{

    pid_t pid = fork();

    if (pid > 0)
    {
        /* void* ret = malloc(8192UL * 1024 * 1024); */
        /* printf("%p\n", ret); */
        // parent process
        // IMPORTANT: we pass getpid() here, not the pid of the child.
        printf("Parent PID: %d\n", getpid());
        if (threading)
        {
            pthread_create(&threads[0], NULL, thread_function, NULL);
            sleep(1);
        }
        sus_ufrk_fork(fd, getpid(), 0);
        // fail_fast();
        printf("Survived ufrk: %d\n", getpid());

        sleep(PROCESS_SLEEP_TIME);
    }
    else if (pid == 0)
    {
        // child process
        printf("Child PID: %d, TID: %d\n", getpid(), gettid());
        if (threading)
        {
            pthread_create(&threads[1], NULL, thread_function, NULL);
        }
        sleep(PROCESS_SLEEP_TIME);
        printf("Child PID: %d, TID: %d\n", getpid(), gettid());
    }
    else
    {
        printf("Unable to fork test process\n");
    }
    printf("Process %d returning\n", getpid());
}

static void cow_count(int fd, pid_t cow_pid)
{
    size_t cow;
    size_t vm;
    int ret = sus_cow_counter(fd, cow_pid, &cow, &vm);

    if (ret == 0)
    {
        printf("Cow Counter: Pid %d has %ld kB COW memory, %ld kB Virtual "
               "Memory\n",
               cow_pid, BYTES_TO_KILO(cow), BYTES_TO_KILO(vm));
    }
    else
    {
        fprintf(stderr, "Unable to run cow counter, error %d\n", errno);
    }
}

static void print_help(const char* progname)
{
    printf("%s -[uhtc]\nu: ultrafork test\nh: print help\n", progname);
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
    pid_t cow_pid;

    volatile pid_t original = getpid();
    int fd = sus_open();
    enum sus_tester_mode mode = NONE;
    bool threading = false;

    while ((c = getopt(argc, argv, "uhfatc:")) != -1)
    {
        switch (c)
        {
        case 'c':
            mode = COW;
            cow_pid = atoi(optarg);
            break;
        case 'u':
            mode = UFRK;
            break;
        case 't':
            threading = true;
            break;
        case 'f':
            mode = FKSM;
            break;
        case 'a':
            mode = HTREE;
            break;
        case 'h':
        default:
            print_help(argv[0]);
            break;
        }
    }

    switch (mode)
    {
    case COW:
        cow_count(fd, cow_pid);
        break;
    case UFRK:
        ufrk_fork_test(fd, threading);
        break;
    case FKSM:
        fksm_parent(fd);
        break;
    case HTREE:
        hash_tree(fd);
        break;
    case NONE:
    default:
        print_help(argv[0]);
        exit(1);
    }

    if (getpid() == original)
    {
        return sus_close(fd);
    }
    else
    {
        return 0;
    }
}
