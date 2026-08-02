//
// bpf_fp.h — 虚拟浮点指令编号（src_reg=2）
//
//   编码：BpfSoftFp pass（把浮点 IR 改成对 extern __ksym __bpf_fp_<ID> 的调用）→
//         bpfvm-ld（识别符号、改写 src_reg=2、imm=<ID>）→
//   执行：do_softfp（解释器 / JIT 回退）、emit_call_softfp（JIT 原生）。
//

#ifndef BPF_FP_H
#define BPF_FP_H


// 二元算术（i64 a, i64 b) -> i64
#define BPF_FP_ADD_F        1   // float    a + b
#define BPF_FP_SUB_F        2   // float    a - b
#define BPF_FP_MUL_F        3   // float    a * b
#define BPF_FP_DIV_F        4   // float    a / b
#define BPF_FP_ADD_D        5   // double   a + b
#define BPF_FP_SUB_D        6   // double   a - b
#define BPF_FP_MUL_D        7   // double   a * b
#define BPF_FP_DIV_D        8   // double   a / b
// 一元（i64 a) -> i64
#define BPF_FP_NEG_F        9   // float    -a
#define BPF_FP_NEG_D       10   // double   -a
#define BPF_FP_SQRT_F      11   // float    sqrt(a)
#define BPF_FP_SQRT_D      12   // double   sqrt(a)
// fp -> int
#define BPF_FP_F2SI        13   // float  -> int32   (fixsfsi)
#define BPF_FP_F2DI        14   // float  -> int64   (fixsfdi)
#define BPF_FP_F2USI       15   // float  -> uint32  (fixunssfsi)
#define BPF_FP_F2UDI       16   // float  -> uint64  (fixunssfdi)
#define BPF_FP_D2SI        17   // double -> int32   (fixdfsi)
#define BPF_FP_D2DI        18   // double -> int64   (fixdfdi)
#define BPF_FP_D2USI       19   // double -> uint32  (fixunsdfsi)
#define BPF_FP_D2UDI       20   // double -> uint64  (fixunsdfdi)
// int -> fp
#define BPF_FP_SI2F        21   // int32  -> float  (floatsisf)
#define BPF_FP_DI2F        22   // int64  -> float  (floatdisf)
#define BPF_FP_USI2F       23   // uint32 -> float  (floatunsisf)
#define BPF_FP_UDI2F       24   // uint64 -> float  (floatundisf)
#define BPF_FP_SI2D        25   // int32  -> double (floatsidf)
#define BPF_FP_DI2D        26   // int64  -> double (floatdidf)
#define BPF_FP_USI2D       27   // uint32 -> double (floatunsidf)
#define BPF_FP_UDI2D       28   // uint64 -> double (floatundidf)
// 类型转换
#define BPF_FP_EXTEND      29   // float  -> double (extendsfdf2)
#define BPF_FP_TRUNC       30   // double -> float  (truncdfsf2)
// 比较 (i64 a, i64 b) -> i64：负=小于,0=相等,正=大于；按 GCC 软浮点约定
#define BPF_FP_CMP_F       31   // float  比较（ltdf2 风格）
#define BPF_FP_CMP_D       32   // double 比较
// 无序判定 (i64 a, i64 b) -> i64：任一操作数为 NaN 返回 1，否则 0（__unordXX2）。
//   单一三态 CMP 丢失了 NaN 信息，无法区分"相等"与"NaN 无法比较"，故 oeq/ueq
//   等谓词必须配合 UNORD 才能精确还原 IEEE754 比较（见 BpfSoftFp 的 fcmp 处理）。
#define BPF_FP_UNORD_F     33   // float  无序判定（__unordsf2）
#define BPF_FP_UNORD_D     34   // double 无序判定（__unorddf2）
#define BPF_FP_FABS_F      35   // float  fabs（一元）
#define BPF_FP_FABS_D      36   // double fabs
#define BPF_FP_COPYSIGN_F  37   // float  copysign（二元）
#define BPF_FP_COPYSIGN_D  38   // double copysign

#endif //BPF_FP_H
