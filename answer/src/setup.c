#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <semaphore.h>

#include "util.h"

// extern int *copy_start_flag;
// extern int *copy_wait_count;
// extern sem_t *wait_copy_sem;

void assign_to_core(int core_id)
{
    int ret;
    cpu_set_t mask;

    CPU_ZERO(&mask);
    CPU_SET(core_id, &mask);
    ret = sched_setaffinity(0, sizeof(mask), &mask);
    if (ret < 0)
        errExit("[-] sched_setaffinity");
    else
        printf("[+] Assign to core %d\n", core_id);
}

void setup_sandbox(void)
{
    int ret;

    ret = unshare(CLONE_NEWUSER);
    if ( ret < 0)
        errExit("[-] unshare(CLONE_NEWUSER)");

    ret = unshare(CLONE_NEWNET);
    if ( ret < 0)
        errExit("[-] unshare(CLONE_NEWNET)");

    printf("[+] Setup sandbox with unshare\n");
}

// void setup_share_vars(void)
// {
//     int shmid;
//     int ret;

//     shmid = shmget(IPC_PRIVATE, sizeof(int), IPC_CREAT | 0666);
//     if (shmid < 0)
//         errExit("[-] shmget int");
//     copy_start_flag = shmat(shmid, NULL, 0);
//     if (copy_start_flag == (void *)-1)
//         errExit("[-] shmat");
//     *copy_start_flag = 0;

//     shmid = shmget(IPC_PRIVATE, sizeof(int), IPC_CREAT | 0666);
//     if (shmid < 0)
//         errExit("[-] shmget int");
//     copy_wait_count = shmat(shmid, NULL, 0);
//     if (copy_wait_count == (void *)-1)
//         errExit("[-] shmat");
//     *copy_wait_count = 0;

//     shmid = shmget(IPC_PRIVATE, sizeof(sem_t), IPC_CREAT | 0666);
//     wait_copy_sem = shmat(shmid, NULL, 0);
//     ret = sem_init(wait_copy_sem, 1, 0);
//     if (ret < 0)
//         errExit("[-] sem_init");

//     printf("[+] Setup share vars done\n");
// }