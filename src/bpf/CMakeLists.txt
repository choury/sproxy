#Cmake file for library bpf.a
#Author:   choury
#Created:  2024/9/1

execute_process(
    COMMAND uname -m
    COMMAND sed "s/x86_64/x86/"
    COMMAND sed "s/arm.*/arm/"
    COMMAND sed "s/aarch64/arm64/"
    COMMAND sed "s/ppc64le/powerpc/"
    COMMAND sed "s/mips.*/mips/"
    COMMAND sed "s/riscv64/riscv/"
    COMMAND sed "s/loongarch64/loongarch/"
    OUTPUT_VARIABLE ARCH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

add_custom_command(OUTPUT ${CMAKE_CURRENT_LIST_DIR}/vmlinux.h
                   WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
                   COMMAND ${BPFTOOL_EXECUTABLE} btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h)


add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/sockops.o
                   DEPENDS sockops.bpf.c
                   DEPENDS vmlinux.h
                   WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
                   COMMAND ${CLANG_EXECUTABLE} -g -O2 -target bpf -D__KERNEL__ -D__TARGET_ARCH_${ARCH} -c sockops.bpf.c -o ${CMAKE_CURRENT_BINARY_DIR}/sockops.o)

add_custom_command(OUTPUT ${CMAKE_CURRENT_LIST_DIR}/sockops.skel.h
                   DEPENDS sockops.o
                   WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
                   COMMAND ${BPFTOOL_EXECUTABLE} gen skeleton ${CMAKE_CURRENT_BINARY_DIR}/sockops.o > sockops.skel.h)

add_library(bpf_loader bpf.c)
set_source_files_properties(${CMAKE_CURRENT_LIST_DIR}/bpf.c
                            PROPERTIES
                            OBJECT_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/sockops.skel.h)
