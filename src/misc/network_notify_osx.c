#include "common.h"
#include "network_notify.h"

#include <SystemConfiguration/SCNetworkReachability.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <pthread.h>

// Create a SCF dynamic store reference and a
// corresponding CFRunLoop source. If you add the
// run loop source to your run loop then the supplied
// callback function will be called when local IP
// address list changes.
static int  CreateIPAddressListChangeCallbackSCF(
        SCDynamicStoreCallBack callback,
        void *contextPtr,
        SCDynamicStoreRef *storeRef,
        CFRunLoopSourceRef *sourceRef)
{
    int result = -1;
    SCDynamicStoreContext   context = {0, contextPtr, NULL, NULL, NULL};
    CFStringRef patterns[2] = {NULL, NULL};
    CFArrayRef patternList  = NULL;

    assert(callback   != NULL);
    assert(*storeRef  == NULL);
    assert(*sourceRef == NULL);


    // Create a connection to the dynamic store, then create
    // a search pattern that finds all IPv4 entities.
    // The pattern is "State:/Network/Service/[^/]+/IPv4".
    *storeRef = SCDynamicStoreCreate(NULL,
                               CFSTR("AddIPAddressListChangeCallbackSCF"),
                               callback,
                               &context);
    if (*storeRef == NULL) {
        LOGE("SCDynamicStoreCreate failed: %d\n", SCError());
        goto err;
    }
    patterns[0] = SCDynamicStoreKeyCreateNetworkServiceEntity(
            NULL,
            kSCDynamicStoreDomainState,
            kSCCompAnyRegex,
            kSCEntNetIPv4);
    if (patterns[0] == NULL) {
        LOGE("SCDynamicStoreKeyCreateNetworkServiceEntity ipv4 failed: %d\n", SCError());
        goto err;
    }

    patterns[1] = SCDynamicStoreKeyCreateNetworkServiceEntity(
            NULL,
            kSCDynamicStoreDomainState,
            kSCCompAnyRegex,
            kSCEntNetIPv6);
    if (patterns[1] == NULL) {
        LOGE("SCDynamicStoreKeyCreateNetworkServiceEntity ipv6 failed: %d\n", SCError());
        goto err;
    }


    // Create a pattern list containing just one pattern,
    // then tell SCF that we want to watch changes in keys
    // that match that pattern list, then create our run loop
    // source.
    patternList = CFArrayCreate(NULL,
                                (const void **)patterns, 2,
                                &kCFTypeArrayCallBacks);
    if(patternList == NULL){
        LOGE("CFArrayCreate failed: %d\n", SCError());
        goto err;
    }
    if(!SCDynamicStoreSetNotificationKeys(*storeRef, NULL, patternList)){
        LOGE("SCDynamicStoreSetNotificationKeys failed: %d\n", SCError());
        goto err;
    }
    *sourceRef = SCDynamicStoreCreateRunLoopSource(NULL, *storeRef, 0);
    if(*sourceRef == NULL){
        LOGE("SCDynamicStoreCreateRunLoopSource failed: %d\n", SCError());
        goto err;
    }
    result = 0;
    goto ret;
err:
    if(*storeRef){
        CFRelease(*storeRef);
        *storeRef = NULL;
    }
    if(*sourceRef){
        CFRelease(*sourceRef);
        *sourceRef = NULL;
    }
ret:
    // Clean up.
    if(patterns[0]){
        CFRelease(patterns[0]);
    }
    if(patterns[1]){
        CFRelease(patterns[1]);
    }
    if(patternList){
        CFRelease(patternList);
    }
    return result;
}


static void* worker(void* param){
    network_notify_callback cb = (network_notify_callback)param;
    void * contextPtr = NULL;
    SCDynamicStoreRef storeRef = NULL;
    CFRunLoopSourceRef sourceRef = NULL;
    if (CreateIPAddressListChangeCallbackSCF((SCDynamicStoreCallBack)cb, contextPtr, &storeRef, &sourceRef) != noErr) {
        return (void*)-1;
    }
    CFRunLoopAddSource(CFRunLoopGetCurrent(), sourceRef, kCFRunLoopDefaultMode);
    CFRunLoopRun();
    CFRunLoopRemoveSource(CFRunLoopGetCurrent(), sourceRef, kCFRunLoopDefaultMode);
    CFRelease(storeRef);
    CFRelease(sourceRef);
    LOG("exting CFRunLoop...\n");
    return NULL;
}

int notify_network_change(network_notify_callback cb){
    pthread_t tid;
    if(pthread_create(&tid, NULL, worker, cb)){
        LOGE("failed to create CFRunLoop thread: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}
