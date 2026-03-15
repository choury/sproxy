#ifndef HOOK_CALLBACK_H__
#define HOOK_CALLBACK_H__

#include <string>

// Generic hook callback interface
class IHookCallback {
public:
    virtual ~IHookCallback() = default;
    virtual void OnCall(void* args) = 0;
    virtual std::string name() = 0;
};

#endif
