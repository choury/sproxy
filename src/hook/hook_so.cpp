#include "hook.h"

#include <iostream>

class Test{
    std::string hello = "Hello from Test!";
public:
    int operator()(int a, double b) {
        return a + b;
    }
    void sayHello() {
        std::cout << hello << std::endl;
    }
};

void hook_callback(void* args) {
    auto [testObj, firstArg, secondArg, thirdArg] = get_args<Test*, int, double, int>(args);

    std::cout << "First argument: " << firstArg << std::endl;
    std::cout << "Second argument: " << secondArg << std::endl;
    secondArg = thirdArg;
    testObj->sayHello();
}

