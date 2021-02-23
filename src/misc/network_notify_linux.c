#include "common/common.h"
#include "network_notify.h"
#include "net.h"

#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

static void* worker(void *data) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < -1){
        LOGE("failed to create netlink socket: %s\n", strerror(errno));
        return NULL;
    }

    struct sockaddr_nl local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.nl_family = AF_NETLINK;
    local_addr.nl_pid = getpid();
    local_addr.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR | RTMGRP_NOTIFY;

    if (bind(fd, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0){
        LOGE("failed to bind nl_groups: %s\n", strerror(errno));
        goto ret;
    }
    network_notify_callback cb = (network_notify_callback)data;

    int len = 0;
    char buffer[BUFSIZ];
retry:
    while ((len = recv(fd, buffer, sizeof(buffer), 0)) > 0) {
        bool changed = false;

        char name[IF_NAMESIZE]={0};
        struct sockaddr_storage addr;
        memset(&addr, 0, sizeof(addr));
        for(struct nlmsghdr* nlh = (struct nlmsghdr *)buffer; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
            if (nlh->nlmsg_type == NLMSG_DONE){
                /* Finish reading */
                break;
            }else if (nlh->nlmsg_type == NLMSG_ERROR) {
                /* Message is some kind of error */
                LOGE("read_netlink: Message is an error - decode TBD\n");
                goto ret;
            } else if (nlh->nlmsg_type == RTM_NEWADDR) {
                LOGD(DNET, "read_netlink: RTM_NEWADDR\n");
            } else if (nlh->nlmsg_type == RTM_DELADDR){
                LOGD(DNET, "read_netlink: RTM_DELADDR\n");
            } else{
                LOGD(DNET, "unknown read_netlink nlmsg_type=%d\n", nlh->nlmsg_type);
                goto retry;
            }

            struct ifaddrmsg* ifa = NLMSG_DATA(nlh);
            struct rtattr* rth = IFA_RTA(ifa);
            for(int rtl = IFA_PAYLOAD(nlh); rtl && RTA_OK(rth, rtl); rth = RTA_NEXT(rth,rtl)) {
                LOGD(DNET, "rtattr type: %d\n", rth->rta_type);
                if(rth->rta_type == IFA_LABEL){
                    strcpy(name, (char *)RTA_DATA(rth));
                }else if(rth->rta_type ==  IFA_LOCAL){
                    addr.ss_family = ifa->ifa_family;
                    if(ifa->ifa_family == AF_INET){
                        struct sockaddr_in* ip4 = (struct sockaddr_in*)&addr;
                        memcpy(&ip4->sin_addr, RTA_DATA(rth), rth->rta_len);
                    }else if(ifa->ifa_family == AF_INET6){
                        struct sockaddr_in6* ip6 = (struct sockaddr_in6*)&addr;
                        memcpy(&ip6->sin6_addr, RTA_DATA(rth), rth->rta_len);
                    }else{
                        LOGE("unkown addr family: %d\n", ifa->ifa_family);
                        goto retry;
                    }
                    changed = true;
                }
            }
        }
        if(changed){
            LOGD(DNET, "netlink_interface %s changed: %s\n",  name, getaddrstring(&addr));
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
