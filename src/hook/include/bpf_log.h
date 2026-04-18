/*
 * bpf_log.h - Minimal snprintf for BPF programs (no va_args)
 *
 * Usage:
 *   char buf[256];
 *   bpf_snprintf(buf, sizeof(buf), "window [%u]: %d", id, winsize);
 *
 * Supported format specifiers:
 *   %d, %i  - signed integer
 *   %u      - unsigned integer
 *   %x      - hexadecimal (lowercase)
 *   %X      - hexadecimal (uppercase)
 *   %p      - pointer (0x prefixed hex)
 *   %s      - string
 *   %c      - character
 *   %%      - literal '%'
 *   Length:  l  modifier (e.g. %ld, %lu, %lx)
 *   Width:  number (e.g. %5d, %08x) with optional '0' prefix for zero-pad
 *
 * Maximum 10 format arguments.
 */
#ifndef BPF_LOG_H__
#define BPF_LOG_H__

/* ---- va_list simulation (from bpfvm/pdclib) ---- */

#define ___bpf_nth(_, _1, _2, _3, _4, _5, _6, _7, _8, _9, _a, _b, N, ...) N
#define ___bpf_narg(...) \
    ___bpf_nth(_, ##__VA_ARGS__, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

#define ___bpf_cc(x, y) x##y
#define ___bpf_apply(fn, n) ___bpf_cc(fn, n)

#define ___bpf_fill0(arr, p, x) do {} while (0)
#define ___bpf_fill1(arr, p, x) arr[p] = (unsigned long long)(x)
#define ___bpf_fill2(arr, p, x, args...) arr[p] = (unsigned long long)(x); ___bpf_fill1(arr, p + 1, args)
#define ___bpf_fill3(arr, p, x, args...) arr[p] = (unsigned long long)(x); ___bpf_fill2(arr, p + 1, args)
#define ___bpf_fill4(arr, p, x, args...) arr[p] = (unsigned long long)(x); ___bpf_fill3(arr, p + 1, args)
#define ___bpf_fill5(arr, p, x, args...) arr[p] = (unsigned long long)(x); ___bpf_fill4(arr, p + 1, args)
#define ___bpf_fill6(arr, p, x, args...) arr[p] = (unsigned long long)(x); ___bpf_fill5(arr, p + 1, args)
#define ___bpf_fill7(arr, p, x, args...) arr[p] = (unsigned long long)(x); ___bpf_fill6(arr, p + 1, args)
#define ___bpf_fill8(arr, p, x, args...) arr[p] = (unsigned long long)(x); ___bpf_fill7(arr, p + 1, args)
#define ___bpf_fill9(arr, p, x, args...) arr[p] = (unsigned long long)(x); ___bpf_fill8(arr, p + 1, args)
#define ___bpf_fill10(arr, p, x, args...) arr[p] = (unsigned long long)(x); ___bpf_fill9(arr, p + 1, args)
#define ___bpf_fill(arr, args...) \
    ___bpf_apply(___bpf_fill, ___bpf_narg(args))(arr, 0, args)

typedef struct {
    int pos;
    unsigned long long* data;
} _bpf_va_list;

#define _bpf_va_arg(ap, type) ({ (ap).pos++; (type)(ap).data[(ap).pos - 1]; })

/* Create va_list from args: local array + struct, 4 params max for BPF */
#define __bpf_make_va_list(name, args...) \
    unsigned long long name##_data[___bpf_narg(args)]; \
    _bpf_va_list name = {0, name##_data}; \
    ___bpf_fill(name##_data, ##args)

/* ---- snprintf core (4 params, BPF safe) ---- */

static inline int __bpf_vsnprintf(char* buf, unsigned long size,
                                   const char* fmt, _bpf_va_list ap) {
    unsigned long pos = 0;

#define FMT_PUTC(c) do { if (pos < size - 1) buf[pos++] = (c); } while (0)

    while (*fmt && pos < size - 1) {
        if (*fmt != '%') {
            FMT_PUTC(*fmt++);
            continue;
        }
        fmt++;

        if (*fmt == '%') {
            FMT_PUTC('%');
            fmt++;
            continue;
        }

        char pad = ' ';
        if (*fmt == '0') {
            pad = '0';
            fmt++;
        }

        int width = 0;
        while (*fmt >= '0' && *fmt <= '9')
            width = width * 10 + (*fmt++ - '0');

        int longness = 0;
        while (*fmt == 'l') {
            longness++;
            fmt++;
        }

        unsigned long long val = _bpf_va_arg(ap, unsigned long long);

        char nbuf[20];
        int nlen;

        switch (*fmt++) {
        case 'd':
        case 'i': {
            int neg = 0;
            unsigned long long uval;
            if (longness == 0) {
                long iv = (long)(int)(long)val;
                neg = iv < 0;
                uval = neg ? (unsigned long long)(-iv) : (unsigned long long)iv;
            } else {
                neg = (long long)val < 0;
                uval = neg ? -(unsigned long long)(long long)val : val;
            }
            nlen = 0;
            do {
                nbuf[nlen++] = '0' + (char)(uval % 10);
                uval /= 10;
            } while (uval);
            for (int i = 0; i < nlen / 2; i++) {
                char t = nbuf[i];
                nbuf[i] = nbuf[nlen - 1 - i];
                nbuf[nlen - 1 - i] = t;
            }
            int total = nlen + neg;
            int padlen = width > total ? width - total : 0;
            if (neg && pad == '0') { FMT_PUTC('-'); neg = 0; }
            for (int i = 0; i < padlen; i++) FMT_PUTC(pad);
            if (neg) FMT_PUTC('-');
            for (int i = 0; i < nlen; i++) FMT_PUTC(nbuf[i]);
            break;
        }
        case 'u': {
            unsigned long long uval = (longness == 0)
                ? (unsigned long long)(unsigned int)(long)val : val;
            nlen = 0;
            do {
                nbuf[nlen++] = '0' + (char)(uval % 10);
                uval /= 10;
            } while (uval);
            for (int i = 0; i < nlen / 2; i++) {
                char t = nbuf[i];
                nbuf[i] = nbuf[nlen - 1 - i];
                nbuf[nlen - 1 - i] = t;
            }
            int padlen = width > nlen ? width - nlen : 0;
            for (int i = 0; i < padlen; i++) FMT_PUTC(pad);
            for (int i = 0; i < nlen; i++) FMT_PUTC(nbuf[i]);
            break;
        }
        case 'x':
        case 'X': {
            const char* hex = (fmt[-1] == 'X')
                ? "0123456789ABCDEF" : "0123456789abcdef";
            unsigned long long uval = (longness == 0)
                ? (unsigned long long)(unsigned int)(long)val : val;
            nlen = 0;
            if (uval == 0) {
                nbuf[nlen++] = '0';
            } else {
                while (uval) {
                    nbuf[nlen++] = hex[uval & 0xf];
                    uval >>= 4;
                }
            }
            for (int i = 0; i < nlen / 2; i++) {
                char t = nbuf[i];
                nbuf[i] = nbuf[nlen - 1 - i];
                nbuf[nlen - 1 - i] = t;
            }
            int padlen = width > nlen ? width - nlen : 0;
            for (int i = 0; i < padlen; i++) FMT_PUTC(pad);
            for (int i = 0; i < nlen; i++) FMT_PUTC(nbuf[i]);
            break;
        }
        case 'p': {
            FMT_PUTC('0');
            FMT_PUTC('x');
            nlen = 0;
            if (val == 0) {
                nbuf[nlen++] = '0';
            } else {
                while (val) {
                    nbuf[nlen++] = "0123456789abcdef"[val & 0xf];
                    val >>= 4;
                }
            }
            for (int i = 0; i < nlen / 2; i++) {
                char t = nbuf[i];
                nbuf[i] = nbuf[nlen - 1 - i];
                nbuf[nlen - 1 - i] = t;
            }
            for (int i = 0; i < nlen; i++) FMT_PUTC(nbuf[i]);
            break;
        }
        case 's': {
            const char* s = (const char*)(long)val;
            if (s) {
                while (*s && pos < size - 1)
                    FMT_PUTC(*s++);
            }
            break;
        }
        case 'c': {
            FMT_PUTC((char)(long)val);
            break;
        }
        default:
            break;
        }
    }

#undef FMT_PUTC

    buf[pos] = '\0';
    return (int)pos;
}

/* ---- public macro ---- */

#define __bpf_snprintf0(s, n, fmt) __bpf_vsnprintf(s, n, fmt, (_bpf_va_list){0, (unsigned long long[]){0}})
#define __bpf_snprintf(s, n, fmt, args...) \
({ \
    __bpf_make_va_list(_va, ##args); \
    __bpf_vsnprintf(s, n, fmt, _va); \
})

#define ___bpf_pick_snprintf(_, ...) \
    ___bpf_nth(_, ##__VA_ARGS__, \
        __bpf_snprintf, \
        __bpf_snprintf, \
        __bpf_snprintf, \
        __bpf_snprintf, \
        __bpf_snprintf, \
        __bpf_snprintf, \
        __bpf_snprintf, \
        __bpf_snprintf, \
        __bpf_snprintf, \
        __bpf_snprintf, \
        __bpf_snprintf, \
        __bpf_snprintf0)

#define bpf_snprintf(s, n, fmt, args...) \
    ___bpf_pick_snprintf(_, ##args)(s, n, fmt, ##args)

#endif /* BPF_LOG_H__ */
