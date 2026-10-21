/* SPDX-License-Identifier: Apache-2.0 */
/* A minimal static userspace executable for a version-3 immutable DAX lower.
 * Build with: cc -nostdlib -static -no-pie -Wl,--build-id=none \
 *   -Wl,-z,max-page-size=4096 -o dax-exec guest-exec-probe.S
 * It performs only exit(73), without a loader or another image's code pages.
 */
.global _start
.text
_start:
#if defined(__aarch64__)
    mov x0, #73
    mov x8, #93
    svc #0
#elif defined(__x86_64__)
    mov $73, %edi
    mov $60, %eax
    syscall
#else
#error Unsupported native DAX execution probe architecture
#endif

.section .note.GNU-stack,"",%progbits
