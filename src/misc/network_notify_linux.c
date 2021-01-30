#include "network_notify.h"
#include "common.h"

#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

static void* worker(void *data) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < -1){
        LOGE("failed to create netlink socket: %s\n", strerror(errno));
        return NULL;
    }

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0){
        LOGE("failed to bind nl_groups: %s\n", strerror(errno));
        goto ret;
    }
    network_notify_callback cb = (network_notify_callback)data;

    int len = 0;
    char buffer[BUFSIZ];
    while ((len = recv(fd, buffer, sizeof(buffer), 0)) > 0) {
        for(struct nlmsghdr* nlh = (struct nlmsghdr *)buffer; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
            if (nlh->nlmsg_type == NLMSG_DONE){
                /* Finish reading */
                break;
            }else if (nlh->nlmsg_type == NLMSG_ERROR) {
                /* Message is some kind of error */
                LOGE("read_netlink: Message is an error - decode TBD\n");
                goto ret;
            } else if (nlh->nlmsg_type == RTM_NEWADDR) {
                LOG("read_netlink: RTM_NEWADDR\n");
            } else if (nlh->nlmsg_type == RTM_DELADDR){
                LOG("read_netlink: RTM_DELADDR\n");
            } else{
                LOG("unknown read_netlink nlmsg_type=%d\n", nlh->nlmsg_type);
                continue;
            }

            struct ifaddrmsg* ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
            struct rtattr* rth = IFA_RTA(ifa);
            for(int rtl = IFA_PAYLOAD(nlh); rtl && RTA_OK(rth, rtl); rth = RTA_NEXT(rth,rtl)) {
            }
            char name[IF_NAMESIZE];
            LOG("netlink_interface %s is now changed\n", if_indextoname(ifa->ifa_index, name));
            cb();
        }
    }
    LOG("exiting netlink loop\n");
ret:
    if(fd >= 0){
        close(fd);
    }
    return NULL;
}

int notify_network_change(network_notify_callback cb){
    pthread_t tid;
    if(pthread_create(&tid, NULL, worker, cb)){
        LOGE("failed to create netlink thread: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}
