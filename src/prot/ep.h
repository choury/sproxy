//
// Created by 周威 on 2021/4/21.
//

#ifndef SPROXY_EP_H
#define SPROXY_EP_H

#include <stdint.h>
#include <signal.h>
#include <sys/types.h>


#include <map>
#ifdef __cpp_impl_coroutine
#include <coroutine>
#include <exception>
#endif

int event_loop(uint32_t timeout_ms);
enum class RW_EVENT{
    NONE = 0,
    READ = 1,
    WRITE = 2,
    READWRITE = READ | WRITE,
    READEOF = 4,
    ERROR = 8,
};

RW_EVENT operator&(RW_EVENT a, RW_EVENT b);
RW_EVENT operator|(RW_EVENT a, RW_EVENT b);
RW_EVENT operator~(RW_EVENT a);
bool operator!(RW_EVENT a);
extern const char *events_string[];

class Ep{
    int fd;
protected:
    RW_EVENT events = RW_EVENT::NONE;
    void setFd(int fd);
    [[nodiscard]] int getFd() const;
public:
    explicit Ep(int fd);
    virtual ~Ep();
    void setEvents(RW_EVENT events);
    void addEvents(RW_EVENT events);
    void delEvents(RW_EVENT events);
    void setNone();
    RW_EVENT getEvents();
    int checkSocket(const char* msg) const;
    void (Ep::*handleEvent)(RW_EVENT events) = nullptr;
    friend int event_loop(uint32_t timeout_ms);
};

#ifdef __cpp_lib_coroutine
struct None {};
extern None Void;
template <typename T = None>
struct Task {
    struct promise_type {
        T result;
        std::coroutine_handle<> continuation;
        Task<T> get_return_object() {
            return std::coroutine_handle<promise_type>::from_promise(*this);
        }
        std::suspend_never initial_suspend() { return {}; }

        // 修复：使用自定义awaiter来正确处理生命周期
        struct final_awaiter {
            std::coroutine_handle<> continuation;

            bool await_ready() noexcept { return false; }

            std::coroutine_handle<> await_suspend(std::coroutine_handle<promise_type>) noexcept {
                // 如果有continuation，返回它让调度器恢复
                // 否则返回noop_coroutine()表示没有更多工作
                return continuation ? continuation : std::noop_coroutine();
            }

            void await_resume() noexcept {}
        };

        final_awaiter final_suspend() noexcept {
            return final_awaiter{continuation};
        }
        //void return_void() {}
        void return_value(T value) { result = std::move(value); }
        void unhandled_exception() { std::terminate(); }
    };

    std::coroutine_handle<promise_type> coro;
    Task(std::coroutine_handle<promise_type> h = nullptr) : coro(h) {}
    ~Task() { if (coro) coro.destroy(); }
    Task(const Task&) = delete;
    Task& operator=(Task&& other) {
        if (coro) coro.destroy();
        coro = other.coro;
        other.coro = nullptr;
        return *this;
    }
    T get_result() {
        return coro.promise().result;
    }

    // 让Task可以被co_await
    bool await_ready() { return !coro || coro.done(); }
    void await_suspend(std::coroutine_handle<> h) {
        coro.promise().continuation = h;
        coro.resume();
    }
    void await_resume() {}
};

class CoEp: public Ep {
protected:
    RW_EVENT callback_events = RW_EVENT::NONE;
    CoEp(int fd): Ep(fd) {
        handleEvent = (void (Ep::*)(RW_EVENT))&CoEp::eventHE;
    }
    std::coroutine_handle<> handle;
    void eventHE(RW_EVENT e) {
        callback_events = e;
        if(!handle || handle.done()) {
            setEvents(RW_EVENT::NONE);
            return;
        }
        handle.resume();
    }
public:
    bool await_ready() { return false; }
    void await_suspend(std::coroutine_handle<> handle) {
        this->handle = handle;
    }
    RW_EVENT await_resume() {
        return callback_events;
    }

    CoEp& wait_for(RW_EVENT events) {
        setEvents(events);
        return *this;
    }
};
#endif

class Sign: public Ep {
    void defaultHE(RW_EVENT events);
    std::map<int, void(*)(int)> sigmap;
public:
    Sign();
    virtual ~Sign() override;
    int add(int sig, sig_t handler);
};

#endif //SPROXY_EP_H
