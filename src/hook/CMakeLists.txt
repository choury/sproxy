set(hook_src hook.cpp)

if(HAVE_ELF)
    set(hook_src ${hook_src}
        bpf_bridge.cpp
        bpfvm/insn.cpp
        bpfvm/elf_loader.cpp
        bpfvm/jit/jit_compiler.cpp
        bpfvm/jit/x86_emitter.cpp
        bpfvm/jit/aarch64_emitter.cpp)
endif()

add_library(hook_lib ${hook_src})

if(HAVE_ELF)
    add_executable(hook_test hook_test.cpp)
    target_link_libraries(hook_test PRIVATE hook_lib sproxy_headers)
    if(HAVE_LIBELF)
        target_link_libraries(hook_test PRIVATE ${LIBELF_LIBRARIES})
    endif()

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

        # 从 hook_bpf.c 派生 BPF ELF 变体，建 <name>_elf 目标；额外参数传给 clang
        function(build_bpf_elf name)
            set(obj ${CMAKE_CURRENT_BINARY_DIR}/${name}.o)
            set(elf ${CMAKE_CURRENT_BINARY_DIR}/${name}.elf)
            add_custom_command(
                OUTPUT ${elf}
                COMMAND ${CLANG_EXECUTABLE} -target bpf -mcpu=${HOOK_BPF_MCPU} -O1 -std=c11 -nostdinc -fno-builtin
                        ${ARGN}
                        -c -o ${obj}
                        ${CMAKE_CURRENT_SOURCE_DIR}/hook_bpf.c
                COMMAND ${BPF_LD_EXECUTABLE} -e hook_callback -o ${elf}
                        ${obj}
                DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/hook_bpf.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/include/bpf.h
                        ${CMAKE_CURRENT_SOURCE_DIR}/include/bpf_syscall.h
                COMMENT "Compiling BPF ${name} with -mcpu=${HOOK_BPF_MCPU}"
            )
            add_custom_target(${name}_elf DEPENDS ${elf})
        endfunction()

        build_bpf_elf(hook_bpf)
        build_bpf_elf(bench_readback -DBENCH_READBACK)
        add_dependencies(hook_test hook_bpf_elf bench_readback_elf)
    endif()
endif()
