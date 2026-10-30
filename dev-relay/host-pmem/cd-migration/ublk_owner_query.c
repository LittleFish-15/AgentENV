/* Read-only UBLK GET_DEV_INFO query. No ADD/STOP/DEL/START command exists here.
 * Linux v6.6 UAPI: drivers/block/ublk_drv.c and include/uapi/linux/ublk_cmd.h.
 * Target compatibility must be checked on the real kernel; an error grants nothing.
 */
#define _GNU_SOURCE
#include <linux/io_uring.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

struct ctrl_cmd { uint32_t id; uint16_t queue, len; uint64_t addr, data;
                  uint16_t path_len, pad; uint32_t reserved; };
struct dev_info { uint16_t queues, depth, state, pad; uint32_t max_io, id;
                  int32_t pid; uint32_t pad1; uint64_t flags, private_flags;
                  uint32_t uid, gid; uint64_t reserved1, reserved2;
                  /* Accept the retained libublk 80-byte envelope as well as
                   * v6.6's 64-byte prefix. Unused output stays zero. */
                  uint64_t extension[2]; };
_Static_assert(sizeof(struct ctrl_cmd)==32,"control ABI");
_Static_assert(sizeof(struct dev_info)==80,"device info ABI envelope");
int main(int argc, char **argv) {
    if (argc==2 && !strcmp(argv[1],"--self-test")) {
        puts("UBLK_QUERY_ONLY_ABI_32_80"); return 0;
    }
    if (argc!=2 || !*argv[1] || strlen(argv[1])>8) return 2;
    for (char *s=argv[1]; *s; s++) if (*s<'0'||*s>'9') return 2;
    unsigned long id=strtoul(argv[1],NULL,10);
    if (id>1048575) return 2;
    int ctl=open("/dev/ublk-control",O_RDWR|O_CLOEXEC|O_NOFOLLOW);
    if (ctl<0) return 3;
    struct stat st;
    if (fstat(ctl,&st) || !S_ISCHR(st.st_mode)) return 3;
    struct io_uring_params p={0}; p.flags=IORING_SETUP_SQE128;
    int ring=syscall(__NR_io_uring_setup,2,&p);
    if (ring<0) return 4;
    size_t sq_len=p.sq_off.array+p.sq_entries*4;
    size_t cq_len=p.cq_off.cqes+p.cq_entries*sizeof(struct io_uring_cqe);
    if (p.features&IORING_FEAT_SINGLE_MMAP) sq_len=cq_len=sq_len>cq_len?sq_len:cq_len;
    char *sq=mmap(NULL,sq_len,PROT_READ|PROT_WRITE,MAP_SHARED,ring,IORING_OFF_SQ_RING);
    char *cq=(p.features&IORING_FEAT_SINGLE_MMAP)?sq:mmap(NULL,cq_len,PROT_READ|PROT_WRITE,MAP_SHARED,ring,IORING_OFF_CQ_RING);
    char *es=mmap(NULL,p.sq_entries*128,PROT_READ|PROT_WRITE,MAP_SHARED,ring,IORING_OFF_SQES);
    if (sq==MAP_FAILED || cq==MAP_FAILED || es==MAP_FAILED) return 5;
    uint32_t *tail=(void *)(sq+p.sq_off.tail), *array=(void *)(sq+p.sq_off.array);
    struct io_uring_sqe *e=(void *)es;
    struct dev_info info={0};
    struct ctrl_cmd cmd={.id=(uint32_t)id,.queue=65535,.len=sizeof(info),.addr=(uintptr_t)&info};
    memset(es,0,128); e->opcode=IORING_OP_URING_CMD; e->fd=ctl;
    e->cmd_op=_IOR('u',0x02,struct ctrl_cmd); e->user_data=0x48504d454d;
    memcpy((char *)e+48,&cmd,sizeof(cmd)); array[0]=0;
    __atomic_store_n(tail,1,__ATOMIC_RELEASE);
    if (syscall(__NR_io_uring_enter,ring,1,0,0,NULL,0)!=1) return 6;
    uint32_t *ct=(void *)(cq+p.cq_off.tail), *ch=(void *)(cq+p.cq_off.head);
    if (__atomic_load_n(ct,__ATOMIC_ACQUIRE)==*ch) {
        struct pollfd wait={.fd=ring,.events=POLLIN};
        if (poll(&wait,1,250)!=1) return 7;
    }
    if (__atomic_load_n(ct,__ATOMIC_ACQUIRE)==*ch) return 7;
    struct io_uring_cqe *done=(void *)(cq+p.cq_off.cqes);
    if (done->user_data!=0x48504d454d || done->res!=0 || info.id!=id) return 8;
    printf("{\"id\":%u,\"pid\":%d,\"uid\":%u,\"gid\":%u,\"state\":%u}\n",
           info.id,info.pid,info.uid,info.gid,info.state);
    return 0;
}
