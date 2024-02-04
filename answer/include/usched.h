#ifndef _USCHED_H_
#define _USCHED_H_

#define LINK_NAME "lo"
#define BUF_SIZE 8192
#define U_DS_QDISC_HANDLE 0x80000
#define U_DS_KIND "dsmark"
#define U_QDISC_HANDLE 0x10000
#define U_QDISC_KIND "drr"
#define U_FILTER_KIND "tcindex"
#define U_CLASS_HANDLE 0x10100

int rt_getlink(int sock, char *link_name);
void rt_setlink(int sock, unsigned int link_id);
void rt_newqdisc_ds(int sock, unsigned int link_id, unsigned int handle);
void rt_newqdisc_drr(int sock, unsigned int link_id, unsigned int handle);
void rt_setclass_add(unsigned int link_id);
void send_add_class(unsigned int handle);
void rt_setclass_del(unsigned int link_id);
void send_del_class(unsigned int handle);
void rt_setfilter_inc(unsigned int link_id);
void send_inc_filter(unsigned int handle);
void rt_setfilter_clean(unsigned int link_id);
void send_clean_filter(void);
void rt_setfilter_del(unsigned int link_id);
void send_del_filter(unsigned int handle);
void send_destory_filter(void);
void rt_setaddr_add(unsigned int link_id);
void send_add_addr(void);
void rt_setaddr_del(unsigned int link_id);
void send_del_addr(void);

#endif