/* Guarded normal deletion of the attributed inactive device4. No force/STOP/ADD/START.
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
    if (argc!=4 || strcmp(argv[1],"4")) return 2;
    unsigned long long expected_inode=strtoull(argv[2],NULL,10), expected_rdev=strtoull(argv[3],NULL,10);
    if (!expected_inode || !expected_rdev) return 2;
    int pin=open("/dev/ublkc4",O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOFOLLOW);
    struct stat pinned;
    if (pin<0 || fstat(pin,&pinned) || !S_ISCHR(pinned.st_mode) ||
        pinned.st_ino!=expected_inode || pinned.st_rdev!=expected_rdev) return 9;
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
    if (info.uid!=1204 || info.gid!=1205 || info.pid!=-1 || info.state!=0) return 10;
    struct stat now;
    if (lstat("/dev/ublkc4",&now) || now.st_ino!=pinned.st_ino || now.st_rdev!=pinned.st_rdev) return 11;
    /* The open cdev pins the device instance and prevents a new daemon open.
     * Submit normal DEL asynchronously, then release this sole reference after
     * devnode removal. No force flag or retry is provided. */
    __atomic_store_n(ch,1,__ATOMIC_RELEASE);
    e=(void *)(es+128);memset(e,0,128);
    cmd=(struct ctrl_cmd){.id=4,.queue=65535};
    e->opcode=IORING_OP_URING_CMD;e->flags=IOSQE_ASYNC;e->fd=ctl;
    e->cmd_op=_IOWR('u',0x05,struct ctrl_cmd);e->user_data=0x5245544952;
    memcpy((char *)e+48,&cmd,sizeof(cmd));array[1]=1;
    __atomic_store_n(tail,2,__ATOMIC_RELEASE);
    if (syscall(__NR_io_uring_enter,ring,1,0,0,NULL,0)!=1) return 12;
    int removed=0;
    for (int n=0;n<300;n++) {
        if (lstat("/dev/ublkc4",&now)<0 && errno==ENOENT) {removed=1;break;}
        if (now.st_ino!=pinned.st_ino || now.st_rdev!=pinned.st_rdev) {removed=1;break;}
        if (__atomic_load_n(ct,__ATOMIC_ACQUIRE)>1) break;
        usleep(10000);
    }
    close(pin);
    struct pollfd wait={.fd=ring,.events=POLLIN};
    if (__atomic_load_n(ct,__ATOMIC_ACQUIRE)==1 && poll(&wait,1,3000)!=1) return 13;
    if (__atomic_load_n(ct,__ATOMIC_ACQUIRE)<=1) return 13;
    done=(void *)(cq+p.cq_off.cqes+sizeof(struct io_uring_cqe));
    if (done->user_data!=0x5245544952 || done->res!=0) return 14;
    (void)removed;
    puts("{\"deviceId\":4,\"normalDeleteAcknowledged\":true,\"force\":false}");
    return 0;
}
