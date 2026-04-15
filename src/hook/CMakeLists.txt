set(hook_src hook.cpp)

if(HAVE_ELF)
    set(hook_src ${hook_src}
        bpf_bridge.cpp
        bpfvm/insn.cpp
        bpfvm/jit_compiler.cpp
        bpfvm/x86_emitter.cpp
        bpfvm/aarch64_emitter.cpp)
endif()

add_library(hook_lib ${hook_src})

if(HAVE_ELF)
    add_executable(hook_test hook_test.cpp)
    target_link_libraries(hook_test PRIVATE hook_lib elf sproxy_headers)

    if(CLANG_EXECUTABLE AND BPF_LD_EXECUTABLE)
        set(HOOK_BPF_MCPU v3)
        set(CLANG_VERSION_MAJOR 0)
        execute_process(
            COMMAND ${CLANG_EXECUTABLE} --version
            OUTPUT_VARIABLE CLANG_VERSION_OUTPUT
            ERROR_VARIABLE CLANG_VERSION_OUTPUT
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        string(REGEX MATCH "(Apple )?clang version ([0-9]+)\\." CLANG_VERSION_MATCH "${CLANG_VERSION_OUTPUT}")
        if(CLANG_VERSION_MATCH)
            set(CLANG_VERSION_MAJOR "${CMAKE_MATCH_2}")
        endif()
        if(CLANG_VERSION_MAJOR GREATER_EQUAL 18)
            set(HOOK_BPF_MCPU v4)
        endif()

        # Build BPF test ELF
        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/hook_bpf.o
            COMMAND ${CLANG_EXECUTABLE} -target bpf -mcpu=${HOOK_BPF_MCPU} -O1 -std=c11 -nostdinc -fno-builtin
                    -c -o ${CMAKE_CURRENT_BINARY_DIR}/hook_bpf.o
                    ${CMAKE_CURRENT_SOURCE_DIR}/hook_bpf.c
            DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/hook_bpf.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpf.h
                    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpf_call.h
            COMMENT "Compiling BPF test program with -mcpu=${HOOK_BPF_MCPU}"
        )
        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/hook_bpf.elf
            COMMAND ${BPF_LD_EXECUTABLE} -e hook_callback -o ${CMAKE_CURRENT_BINARY_DIR}/hook_bpf.elf
                    ${CMAKE_CURRENT_BINARY_DIR}/hook_bpf.o
            DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/hook_bpf.o
            COMMENT "Linking BPF test ELF"
        )

        add_custom_target(hook_bpf_elf ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/hook_bpf.elf)
    endif()
endif()
