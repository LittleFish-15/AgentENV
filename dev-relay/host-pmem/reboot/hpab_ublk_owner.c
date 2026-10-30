/* udev PROGRAM, metadata GET_DEV_INFO only. Grant only kernel-owned jwk devices. */
#define _GNU_SOURCE
#include <linux/io_uring.h>
#include <linux/ublk_cmd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

int main(int argc,char **argv) {
    if(geteuid()!=0 || argc!=2) return 2;
    alarm(1); /* A stuck metadata query must not indefinitely stall a udev worker. */
    const char *s=argv[1];
    if(strncmp(s,"ublkc",5) && strncmp(s,"ublkb",5)) return 2;
    if(!s[5] || strlen(s)>15) return 2;
    for(size_t i=5;s[i];i++) if(s[i]<'0'||s[i]>'9') return 2;
    char *end=NULL;unsigned long id=strtoul(s+5,&end,10);
    if(!end||*end||id>UINT_MAX) return 2;
    struct io_uring_params p={0};p.flags=IORING_SETUP_SQE128;
    int ring=syscall(__NR_io_uring_setup,2,&p);
    if(ring<0) return 3;
    size_t sqsz=p.sq_off.array+p.sq_entries*sizeof(unsigned);
    size_t cqsz=p.cq_off.cqes+p.cq_entries*sizeof(struct io_uring_cqe);
    if(p.features&IORING_FEAT_SINGLE_MMAP) { if(cqsz>sqsz) sqsz=cqsz; cqsz=sqsz; }
    void *sq=mmap(NULL,sqsz,PROT_READ|PROT_WRITE,MAP_SHARED,ring,IORING_OFF_SQ_RING);
    if(sq==MAP_FAILED) {close(ring);return 3;}
    void *cq=(p.features&IORING_FEAT_SINGLE_MMAP)?sq:
        mmap(NULL,cqsz,PROT_READ|PROT_WRITE,MAP_SHARED,ring,IORING_OFF_CQ_RING);
    if(cq==MAP_FAILED) {munmap(sq,sqsz);close(ring);return 3;}
    size_t esz=p.sq_entries*128;
    struct io_uring_sqe *es=mmap(NULL,esz,PROT_READ|PROT_WRITE,MAP_SHARED,ring,IORING_OFF_SQES);
    int ctrl=open("/dev/ublk-control",O_RDWR|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    int ok=0;
    if(es!=MAP_FAILED && ctrl>=0) {
        struct stat st;
        struct ublksrv_ctrl_dev_info info={0};
        struct ublksrv_ctrl_cmd cmd={0};cmd.dev_id=(unsigned)id;cmd.queue_id=(uint16_t)-1;
        cmd.len=sizeof(info);cmd.addr=(uint64_t)(uintptr_t)&info;
        _Static_assert(sizeof(cmd)<=80,"ctrl payload exceeds SQE128");
        _Static_assert(offsetof(struct io_uring_sqe,cmd)==48,"SQE command offset differs");
        if(fstat(ctrl,&st)==0 && S_ISCHR(st.st_mode) && st.st_uid==0) {
            memset(es,0,128);es->opcode=IORING_OP_URING_CMD;es->fd=ctrl;
            es->cmd_op=UBLK_U_CMD_GET_DEV_INFO;es->user_data=0x68706162;
            memcpy(es->cmd,&cmd,sizeof(cmd));
            unsigned *tail=(unsigned*)((char*)sq+p.sq_off.tail);
            unsigned *array=(unsigned*)((char*)sq+p.sq_off.array);array[0]=0;
            __atomic_store_n(tail,1,__ATOMIC_RELEASE);
            int rc=syscall(__NR_io_uring_enter,ring,1,1,IORING_ENTER_GETEVENTS,NULL,0);
            unsigned *head=(unsigned*)((char*)cq+p.cq_off.head),*ctail=(unsigned*)((char*)cq+p.cq_off.tail);
            unsigned h=__atomic_load_n(head,__ATOMIC_ACQUIRE),t=__atomic_load_n(ctail,__ATOMIC_ACQUIRE);
            struct io_uring_cqe *cqe=(void*)((char*)cq+p.cq_off.cqes);
            if(rc==1 && t-h==1 && cqe[h&(p.cq_entries-1)].res==0 &&
                cqe[h&(p.cq_entries-1)].user_data==0x68706162 && info.dev_id==id &&
                info.owner_uid==1204 && info.owner_gid==1205) ok=1;
        }
    }
    if(ctrl>=0)close(ctrl);
    if(es!=MAP_FAILED)munmap(es,esz);
    if(cq!=sq)munmap(cq,cqsz);
    munmap(sq,sqsz);close(ring);
    if(ok) { puts("1204:1205"); return 0; }
    return 1; /* Unsupported/mismatched kernel metadata fails closed. */
}
