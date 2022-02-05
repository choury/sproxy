#include "http_code.h"
#include "common/common.h"

#include <stddef.h>
#include <assert.h>
#include <string.h>

#define HFM_EOS 256

static struct node {
    struct node* left,* right;
    const uint16_t  info;
    const uint16_t  len;
    const unsigned long long code;
} hfmnodes[512]= {
        {NULL, NULL, 0, 13, 0x1ff8},
        {NULL, NULL, 1, 23, 0x7fffd8},
        {NULL, NULL, 2, 28, 0xfffffe2},
        {NULL, NULL, 3, 28, 0xfffffe3},
        {NULL, NULL, 4, 28, 0xfffffe4},
        {NULL, NULL, 5, 28, 0xfffffe5},
        {NULL, NULL, 6, 28, 0xfffffe6},
        {NULL, NULL, 7, 28, 0xfffffe7},
        {NULL, NULL, 8, 28, 0xfffffe8},
        {NULL, NULL, 9, 24, 0xffffea},
        {NULL, NULL, 10, 30, 0x3ffffffc},
        {NULL, NULL, 11, 28, 0xfffffe9},
        {NULL, NULL, 12, 28, 0xfffffea},
        {NULL, NULL, 13, 30, 0x3ffffffd},
        {NULL, NULL, 14, 28, 0xfffffeb},
        {NULL, NULL, 15, 28, 0xfffffec},
        {NULL, NULL, 16, 28, 0xfffffed},
        {NULL, NULL, 17, 28, 0xfffffee},
        {NULL, NULL, 18, 28, 0xfffffef},
        {NULL, NULL, 19, 28, 0xffffff0},
        {NULL, NULL, 20, 28, 0xffffff1},
        {NULL, NULL, 21, 28, 0xffffff2},
        {NULL, NULL, 22, 30, 0x3ffffffe},
        {NULL, NULL, 23, 28, 0xffffff3},
        {NULL, NULL, 24, 28, 0xffffff4},
        {NULL, NULL, 25, 28, 0xffffff5},
        {NULL, NULL, 26, 28, 0xffffff6},
        {NULL, NULL, 27, 28, 0xffffff7},
        {NULL, NULL, 28, 28, 0xffffff8},
        {NULL, NULL, 29, 28, 0xffffff9},
        {NULL, NULL, 30, 28, 0xffffffa},
        {NULL, NULL, 31, 28, 0xffffffb},
        {NULL, NULL, 32,  6, 0x14},
        {NULL, NULL, 33, 10, 0x3f8},
        {NULL, NULL, 34, 10, 0x3f9},
        {NULL, NULL, 35, 12, 0xffa},
        {NULL, NULL, 36, 13, 0x1ff9},
        {NULL, NULL, 37,  6, 0x15},
        {NULL, NULL, 38,  8, 0xf8},
        {NULL, NULL, 39, 11, 0x7fa},
        {NULL, NULL, 40, 10, 0x3fa},
        {NULL, NULL, 41, 10, 0x3fb},
        {NULL, NULL, 42,  8, 0xf9},
        {NULL, NULL, 43, 11, 0x7fb},
        {NULL, NULL, 44,  8, 0xfa},
        {NULL, NULL, 45,  6, 0x16},
        {NULL, NULL, 46,  6, 0x17},
        {NULL, NULL, 47,  6, 0x18},
        {NULL, NULL, 48,  5, 0x0},
        {NULL, NULL, 49,  5, 0x1},
        {NULL, NULL, 50,  5, 0x2},
        {NULL, NULL, 51,  6, 0x19},
        {NULL, NULL, 52,  6, 0x1a},
        {NULL, NULL, 53,  6, 0x1b},
        {NULL, NULL, 54,  6, 0x1c},
        {NULL, NULL, 55,  6, 0x1d},
        {NULL, NULL, 56,  6, 0x1e},
        {NULL, NULL, 57,  6, 0x1f},
        {NULL, NULL, 58,  7, 0x5c},
        {NULL, NULL, 59,  8, 0xfb},
        {NULL, NULL, 60, 15, 0x7ffc},
        {NULL, NULL, 61,  6, 0x20},
        {NULL, NULL, 62, 12, 0xffb},
        {NULL, NULL, 63, 10, 0x3fc},
        {NULL, NULL, 64, 13, 0x1ffa},
        {NULL, NULL, 65,  6, 0x21},
        {NULL, NULL, 66,  7, 0x5d},
        {NULL, NULL, 67,  7, 0x5e},
        {NULL, NULL, 68,  7, 0x5f},
        {NULL, NULL, 69,  7, 0x60},
        {NULL, NULL, 70,  7, 0x61},
        {NULL, NULL, 71,  7, 0x62},
        {NULL, NULL, 72,  7, 0x63},
        {NULL, NULL, 73,  7, 0x64},
        {NULL, NULL, 74,  7, 0x65},
        {NULL, NULL, 75,  7, 0x66},
        {NULL, NULL, 76,  7, 0x67},
        {NULL, NULL, 77,  7, 0x68},
        {NULL, NULL, 78,  7, 0x69},
        {NULL, NULL, 79,  7, 0x6a},
        {NULL, NULL, 80,  7, 0x6b},
        {NULL, NULL, 81,  7, 0x6c},
        {NULL, NULL, 82,  7, 0x6d},
        {NULL, NULL, 83,  7, 0x6e},
        {NULL, NULL, 84,  7, 0x6f},
        {NULL, NULL, 85,  7, 0x70},
        {NULL, NULL, 86,  7, 0x71},
        {NULL, NULL, 87,  7, 0x72},
        {NULL, NULL, 88,  8, 0xfc},
        {NULL, NULL, 89,  7, 0x73},
        {NULL, NULL, 90,  8, 0xfd},
        {NULL, NULL, 91, 13, 0x1ffb},
        {NULL, NULL, 92, 19, 0x7fff0},
        {NULL, NULL, 93, 13, 0x1ffc},
        {NULL, NULL, 94, 14, 0x3ffc},
        {NULL, NULL, 95,  6, 0x22},
        {NULL, NULL, 96, 15, 0x7ffd},
        {NULL, NULL, 97,  5, 0x3},
        {NULL, NULL, 98,  6, 0x23},
        {NULL, NULL, 99,  5, 0x4},
        {NULL, NULL, 100,  6, 0x24},
        {NULL, NULL, 101,  5, 0x5},
        {NULL, NULL, 102,  6, 0x25},
        {NULL, NULL, 103,  6, 0x26},
        {NULL, NULL, 104,  6, 0x27},
        {NULL, NULL, 105,  5, 0x6},
        {NULL, NULL, 106,  7, 0x74},
        {NULL, NULL, 107,  7, 0x75},
        {NULL, NULL, 108,  6, 0x28},
        {NULL, NULL, 109,  6, 0x29},
        {NULL, NULL, 110,  6, 0x2a},
        {NULL, NULL, 111,  5, 0x7},
        {NULL, NULL, 112,  6, 0x2b},
        {NULL, NULL, 113,  7, 0x76},
        {NULL, NULL, 114,  6, 0x2c},
        {NULL, NULL, 115,  5, 0x8},
        {NULL, NULL, 116,  5, 0x9},
        {NULL, NULL, 117,  6, 0x2d},
        {NULL, NULL, 118,  7, 0x77},
        {NULL, NULL, 119,  7, 0x78},
        {NULL, NULL, 120,  7, 0x79},
        {NULL, NULL, 121,  7, 0x7a},
        {NULL, NULL, 122,  7, 0x7b},
        {NULL, NULL, 123, 15, 0x7ffe},
        {NULL, NULL, 124, 11, 0x7fc},
        {NULL, NULL, 125, 14, 0x3ffd},
        {NULL, NULL, 126, 13, 0x1ffd},
        {NULL, NULL, 127, 28, 0xffffffc},
        {NULL, NULL, 128, 20, 0xfffe6},
        {NULL, NULL, 129, 22, 0x3fffd2},
        {NULL, NULL, 130, 20, 0xfffe7},
        {NULL, NULL, 131, 20, 0xfffe8},
        {NULL, NULL, 132, 22, 0x3fffd3},
        {NULL, NULL, 133, 22, 0x3fffd4},
        {NULL, NULL, 134, 22, 0x3fffd5},
        {NULL, NULL, 135, 23, 0x7fffd9},
        {NULL, NULL, 136, 22, 0x3fffd6},
        {NULL, NULL, 137, 23, 0x7fffda},
        {NULL, NULL, 138, 23, 0x7fffdb},
        {NULL, NULL, 139, 23, 0x7fffdc},
        {NULL, NULL, 140, 23, 0x7fffdd},
        {NULL, NULL, 141, 23, 0x7fffde},
        {NULL, NULL, 142, 24, 0xffffeb},
        {NULL, NULL, 143, 23, 0x7fffdf},
        {NULL, NULL, 144, 24, 0xffffec},
        {NULL, NULL, 145, 24, 0xffffed},
        {NULL, NULL, 146, 22, 0x3fffd7},
        {NULL, NULL, 147, 23, 0x7fffe0},
        {NULL, NULL, 148, 24, 0xffffee},
        {NULL, NULL, 149, 23, 0x7fffe1},
        {NULL, NULL, 150, 23, 0x7fffe2},
        {NULL, NULL, 151, 23, 0x7fffe3},
        {NULL, NULL, 152, 23, 0x7fffe4},
        {NULL, NULL, 153, 21, 0x1fffdc},
        {NULL, NULL, 154, 22, 0x3fffd8},
        {NULL, NULL, 155, 23, 0x7fffe5},
        {NULL, NULL, 156, 22, 0x3fffd9},
        {NULL, NULL, 157, 23, 0x7fffe6},
        {NULL, NULL, 158, 23, 0x7fffe7},
        {NULL, NULL, 159, 24, 0xffffef},
        {NULL, NULL, 160, 22, 0x3fffda},
        {NULL, NULL, 161, 21, 0x1fffdd},
        {NULL, NULL, 162, 20, 0xfffe9},
        {NULL, NULL, 163, 22, 0x3fffdb},
        {NULL, NULL, 164, 22, 0x3fffdc},
        {NULL, NULL, 165, 23, 0x7fffe8},
        {NULL, NULL, 166, 23, 0x7fffe9},
        {NULL, NULL, 167, 21, 0x1fffde},
        {NULL, NULL, 168, 23, 0x7fffea},
        {NULL, NULL, 169, 22, 0x3fffdd},
        {NULL, NULL, 170, 22, 0x3fffde},
        {NULL, NULL, 171, 24, 0xfffff0},
        {NULL, NULL, 172, 21, 0x1fffdf},
        {NULL, NULL, 173, 22, 0x3fffdf},
        {NULL, NULL, 174, 23, 0x7fffeb},
        {NULL, NULL, 175, 23, 0x7fffec},
        {NULL, NULL, 176, 21, 0x1fffe0},
        {NULL, NULL, 177, 21, 0x1fffe1},
        {NULL, NULL, 178, 22, 0x3fffe0},
        {NULL, NULL, 179, 21, 0x1fffe2},
        {NULL, NULL, 180, 23, 0x7fffed},
        {NULL, NULL, 181, 22, 0x3fffe1},
        {NULL, NULL, 182, 23, 0x7fffee},
        {NULL, NULL, 183, 23, 0x7fffef},
        {NULL, NULL, 184, 20, 0xfffea},
        {NULL, NULL, 185, 22, 0x3fffe2},
        {NULL, NULL, 186, 22, 0x3fffe3},
        {NULL, NULL, 187, 22, 0x3fffe4},
        {NULL, NULL, 188, 23, 0x7ffff0},
        {NULL, NULL, 189, 22, 0x3fffe5},
        {NULL, NULL, 190, 22, 0x3fffe6},
        {NULL, NULL, 191, 23, 0x7ffff1},
        {NULL, NULL, 192, 26, 0x3ffffe0},
        {NULL, NULL, 193, 26, 0x3ffffe1},
        {NULL, NULL, 194, 20, 0xfffeb},
        {NULL, NULL, 195, 19, 0x7fff1},
        {NULL, NULL, 196, 22, 0x3fffe7},
        {NULL, NULL, 197, 23, 0x7ffff2},
        {NULL, NULL, 198, 22, 0x3fffe8},
        {NULL, NULL, 199, 25, 0x1ffffec},
        {NULL, NULL, 200, 26, 0x3ffffe2},
        {NULL, NULL, 201, 26, 0x3ffffe3},
        {NULL, NULL, 202, 26, 0x3ffffe4},
        {NULL, NULL, 203, 27, 0x7ffffde},
        {NULL, NULL, 204, 27, 0x7ffffdf},
        {NULL, NULL, 205, 26, 0x3ffffe5},
        {NULL, NULL, 206, 24, 0xfffff1},
        {NULL, NULL, 207, 25, 0x1ffffed},
        {NULL, NULL, 208, 19, 0x7fff2},
        {NULL, NULL, 209, 21, 0x1fffe3},
        {NULL, NULL, 210, 26, 0x3ffffe6},
        {NULL, NULL, 211, 27, 0x7ffffe0},
        {NULL, NULL, 212, 27, 0x7ffffe1},
        {NULL, NULL, 213, 26, 0x3ffffe7},
        {NULL, NULL, 214, 27, 0x7ffffe2},
        {NULL, NULL, 215, 24, 0xfffff2},
        {NULL, NULL, 216, 21, 0x1fffe4},
        {NULL, NULL, 217, 21, 0x1fffe5},
        {NULL, NULL, 218, 26, 0x3ffffe8},
        {NULL, NULL, 219, 26, 0x3ffffe9},
        {NULL, NULL, 220, 28, 0xffffffd},
        {NULL, NULL, 221, 27, 0x7ffffe3},
        {NULL, NULL, 222, 27, 0x7ffffe4},
        {NULL, NULL, 223, 27, 0x7ffffe5},
        {NULL, NULL, 224, 20, 0xfffec},
        {NULL, NULL, 225, 24, 0xfffff3},
        {NULL, NULL, 226, 20, 0xfffed},
        {NULL, NULL, 227, 21, 0x1fffe6},
        {NULL, NULL, 228, 22, 0x3fffe9},
        {NULL, NULL, 229, 21, 0x1fffe7},
        {NULL, NULL, 230, 21, 0x1fffe8},
        {NULL, NULL, 231, 23, 0x7ffff3},
        {NULL, NULL, 232, 22, 0x3fffea},
        {NULL, NULL, 233, 22, 0x3fffeb},
        {NULL, NULL, 234, 25, 0x1ffffee},
        {NULL, NULL, 235, 25, 0x1ffffef},
        {NULL, NULL, 236, 24, 0xfffff4},
        {NULL, NULL, 237, 24, 0xfffff5},
        {NULL, NULL, 238, 26, 0x3ffffea},
        {NULL, NULL, 239, 23, 0x7ffff4},
        {NULL, NULL, 240, 26, 0x3ffffeb},
        {NULL, NULL, 241, 27, 0x7ffffe6},
        {NULL, NULL, 242, 26, 0x3ffffec},
        {NULL, NULL, 243, 26, 0x3ffffed},
        {NULL, NULL, 244, 27, 0x7ffffe7},
        {NULL, NULL, 245, 27, 0x7ffffe8},
        {NULL, NULL, 246, 27, 0x7ffffe9},
        {NULL, NULL, 247, 27, 0x7ffffea},
        {NULL, NULL, 248, 27, 0x7ffffeb},
        {NULL, NULL, 249, 28, 0xffffffe},
        {NULL, NULL, 250, 27, 0x7ffffec},
        {NULL, NULL, 251, 27, 0x7ffffed},
        {NULL, NULL, 252, 27, 0x7ffffee},
        {NULL, NULL, 253, 27, 0x7ffffef},
        {NULL, NULL, 254, 27, 0x7fffff0},
        {NULL, NULL, 255, 26, 0x3ffffee},
        {NULL, NULL, 256, 30, 0x3fffffff},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        {NULL, NULL, 0, 0, 0},
        };

static struct node root= {NULL, NULL, 0, 0, 0};


__attribute__((constructor, unused)) static void init_hfmtree() {
    int tail = 511;
    int i;
    for(i = 0; i <= 256; ++i) {
        unsigned long long code = hfmnodes[i].code;
        uint16_t len = hfmnodes[i].len;
        struct node *curnode = &root;
        while(--len){
            if(code&(1u<<len)) {
                if(curnode->right == NULL)
                    curnode->right = &hfmnodes[tail--];
                curnode = curnode->right;
            }else{
                if(curnode->left == NULL)
                    curnode->left = &hfmnodes[tail--];
                curnode = curnode->left;
            }
        }
        if(code & 1u)
            curnode->right = &hfmnodes[i];
        else
            curnode->left = &hfmnodes[i];
    }
}


int hfm_decode(const unsigned char *s, size_t len, char* result) {
    struct node *curnode = &root;
    int padding = 0;
    int n = 0;
    for(size_t i = 0; i < len; ++i){
        uint8_t c = s[i];
        for(int j = 8; j; --j) {
            if(c & 0x80u)
                curnode = curnode->right;
            else
                curnode = curnode->left;
            c <<= 1u;
            padding ++;

            if(curnode->len) {
                if(unlikely(curnode->info == HFM_EOS)){
                    LOGE("found EOS in hfm encoder packet\n");
                    return -1;
                }
                result[n++] = (char)curnode->info;
                curnode = &root;
                padding = 0;
            }
        }
    }
    if(padding >= 8){
        LOGE("the padding len in pack packet is more than 7\n");
        return -1;
    }
    return n;
}

size_t hfm_encode(const char *s, size_t len, unsigned char *result){
    unsigned char out=0;
    unsigned char *buf_begin = result;
    int count=0;
    while(len--) {
        int lenght = hfmnodes[*(uchar *)s].len;
        int code  = hfmnodes[*(uchar *)s].code;
        //TODO 待优化去掉循环
        while(lenght--){
            if(count == 8){
                *result++ = out;
                count = 0;
            }
            out<<=1u;
            out |= (code >> lenght) & 1u;
            count++;
        }
        s++;
    }
    if(count){
        out<<=8u-count;
        *result++ = out | (0xffu >> count);
    }
    return result - buf_begin;
}

int integer_decode(const unsigned char *s, size_t len, int prefix, uint64_t *value) {
    assert(prefix <= 8);
    if(len == 0){
        return 0;
    }
    uint32_t mask = ((1u << prefix) - 1u);
    if((s[0] & mask) == mask){
        *value = mask;
        size_t i;
        for(i=1;s[i]&0x80;++i) {
            if(i >= len){
                //incomplete integer
                return 0;
            }
            *value += (s[i]&0x7fu) << (i*7-7);
        }
        *value += s[i] << (i*7-7);
        return (int)i + 1;
    } else {
        *value = s[0] & mask;
        return 1;
    }
}

size_t integer_encode(uint64_t value, int prefix, unsigned char *buff){
    assert(prefix <= 8);
    unsigned char *buf_begin = buff;
    uint32_t mask = ((1u << prefix) - 1u);
    if(value < mask) {
        *buff &= ~mask;
        *buff++ |= value;
    }else{
        *buff++ |= mask;
        value -= mask;
        while(value >= 128){
            *buff++ = (value%128u) | 0x80u;
            value /= 128;
        }
        *buff++ = value;
    }
    return buff - buf_begin;
}

int literal_decode(const unsigned char *s, size_t len, int prefix, char* result) {
    assert(prefix >= 0 && prefix <= 7);
    uint64_t value;
    int i = integer_decode(s, len, prefix, &value);
    if(i == 0)
        return 0;
    if(i + value > len) {
        //incomplete literal
        return 0;
    }
    if(value >= 0xffff){
        LOGE("too long value: %d\n", (int)value);
        return -1;
    }
    if(s[0] & (1<<prefix)) {
        int ret = hfm_decode(s+i, value, result);
        if(ret < 0)return -1;
        result[ret] = 0;
    } else {
        memcpy(result, s+i, value);
        result[value] = 0;
    }
    return i + (int)value;
}

size_t literal_encode(const char* s, int prefix, unsigned char *result){
    unsigned char *buf_begin = result;
    size_t size = strlen(s);
    size_t len = hfm_encode(s, size, result + 1);
    if(len >= size){
        *result &= ~(1<<prefix);
        result += integer_encode(size, prefix, result);
        memcpy(result, s, size);
        return result + size - buf_begin;
    }else{
        *result |= (1<<prefix);
        result += integer_encode(len, prefix, result);
        if(result - buf_begin > 1){
            result += hfm_encode(s, size, result);
        }else{
            result += len;
        }
        return result - buf_begin;
    }
}

