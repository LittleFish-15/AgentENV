/* Bounded read-only Guest file probe. All output is emitted after timed reads.
 * Measures read syscall latency and achieved process throughput, not UB wire
 * capacity. Uses existing files; never writes, drops caches or maps devices.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAX_FILES 16
#define MAX_RECORDS 18000
#define MAX_BYTES (64ULL * 1024 * 1024)
struct record { uint64_t start, end, offset, bytes; unsigned file, pass; int error; };
struct input { int fd; const char *name; struct stat before; };
static uint64_t now(clockid_t clock) {
    struct timespec value;
    if (clock_gettime(clock, &value)) { perror("clock_gettime"); exit(2); }
    return (uint64_t)value.tv_sec * 1000000000ULL + (uint64_t)value.tv_nsec;
}
static uint64_t number(const char *text) {
    char *end; errno=0;
    unsigned long long n=strtoull(text,&end,10);
    if (errno || !text[0] || *end || text[0]=='-') { fprintf(stderr,"invalid number\n"); exit(2); }
    return n;
}
static void quote(const char *s) {
    putchar('"');
    for (;*s;s++) {
        unsigned char c=(unsigned char)*s;
        if (c=='"' || c=='\\') { putchar('\\'); putchar(c); }
        else if (c<32 || c>=127) printf("\\u%04x",c);
        else putchar(c);
    }
    putchar('"');
}
static int same(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev && a->st_ino==b->st_ino && a->st_size==b->st_size
        && a->st_mtim.tv_sec==b->st_mtim.tv_sec && a->st_mtim.tv_nsec==b->st_mtim.tv_nsec
        && a->st_ctim.tv_sec==b->st_ctim.tv_sec && a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;
}
int main(int argc,char **argv) {
    uint64_t budget=MAX_BYTES,block=256*1024; int first=1;
    for (;first<argc;first++) {
        if (!strcmp(argv[first],"--max-bytes") && first+1<argc) budget=number(argv[++first]);
        else if (!strcmp(argv[first],"--block-bytes") && first+1<argc) block=number(argv[++first]);
        else if (!strcmp(argv[first],"--")) { first++; break; }
        else if (argv[first][0]=='-') { fprintf(stderr,"unknown option\n"); return 2; }
        else break;
    }
    int count=argc-first;
    if (budget<8192 || budget>MAX_BYTES || block<4096 || block>256*1024 || block%4096
            || count<1 || count>MAX_FILES) {
        fprintf(stderr,"usage: probe [--max-bytes <=67108864] [--block-bytes 4096..262144] -- file...\n"); return 2;
    }
    struct input files[MAX_FILES]; memset(files,0,sizeof files);
    for (int i=0;i<count;i++) {
        files[i].name=argv[first+i];
        files[i].fd=open(files[i].name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
        if (files[i].fd<0 || fstat(files[i].fd,&files[i].before) || !S_ISREG(files[i].before.st_mode)
                || files[i].before.st_size<=0) { perror("readonly regular input"); return 2; }
        for (int j=0;j<i;j++) if (files[i].before.st_dev==files[j].before.st_dev
                && files[i].before.st_ino==files[j].before.st_ino) {
            fprintf(stderr,"duplicate input inode\n"); return 2;
        }
    }
    void *buffer=malloc(block);
    struct record *records=calloc(MAX_RECORDS,sizeof(*records));
    if (!buffer || !records) { fprintf(stderr,"bounded allocation failed\n"); return 2; }
    unsigned used=0; uint64_t total=0,pass_start[2]={0},pass_end[2]={0},pass_bytes[2]={0};
    int failed=0; uint64_t real_start=now(CLOCK_REALTIME),whole_start=now(CLOCK_MONOTONIC);
    for (unsigned pass=0;pass<2 && !failed;pass++) {
        uint64_t remaining=budget/2;pass_start[pass]=now(CLOCK_MONOTONIC);
        for (int i=0;i<count && remaining && !failed;i++) {
            uint64_t file_limit=(uint64_t)files[i].before.st_size;
            if (file_limit>remaining) file_limit=remaining;
            for (uint64_t offset=0;offset<file_limit;) {
                if (used>=MAX_RECORDS) { failed=1; break; }
                uint64_t wanted=file_limit-offset;if(wanted>block)wanted=block;
                struct record *r=&records[used++];r->file=(unsigned)i;r->pass=pass;r->offset=offset;
                r->start=now(CLOCK_MONOTONIC);errno=0;
                ssize_t got=pread(files[i].fd,buffer,(size_t)wanted,(off_t)offset);
                int error=errno;r->end=now(CLOCK_MONOTONIC);
                if (got<=0 || (uint64_t)got!=wanted) {
                    r->bytes=got>0?(uint64_t)got:0;r->error=error?error:EIO;failed=1;break;
                }
                r->bytes=(uint64_t)got;offset+=r->bytes;remaining-=r->bytes;
                pass_bytes[pass]+=r->bytes;total+=r->bytes;
            }
        }
        pass_end[pass]=now(CLOCK_MONOTONIC);
        for(int i=0;i<count;i++) {
            struct stat after;
            if(fstat(files[i].fd,&after) || !same(&files[i].before,&after))failed=1;
        }
    }
    uint64_t whole_end=now(CLOCK_MONOTONIC);
    printf("{\"version\":1,\"scope\":\"Guest pread syscall; cache state not inferred\",\"state\":\"%s\","
           "\"maxBytes\":%" PRIu64 ",\"blockBytes\":%" PRIu64 ",\"actualBytes\":%" PRIu64 ","
           "\"startUnixNs\":%" PRIu64 ",\"startMonotonicNs\":%" PRIu64 ",\"endMonotonicNs\":%" PRIu64 ","
           "\"files\":[",failed?"failed":"completed",budget,block,total,real_start,whole_start,whole_end);
    for(int i=0;i<count;i++) {
        if(i)putchar(',');printf("{\"index\":%d,\"path\":",i);quote(files[i].name);
        printf(",\"device\":%" PRIu64 ",\"inode\":%" PRIu64 ",\"bytes\":%" PRIu64 "}",
               (uint64_t)files[i].before.st_dev,(uint64_t)files[i].before.st_ino,(uint64_t)files[i].before.st_size);
    }
    printf("],\"passes\":[");
    for(unsigned p=0;p<2;p++) {
        if(p)putchar(',');printf("{\"pass\":%u,\"startNs\":%" PRIu64 ",\"endNs\":%" PRIu64 ",\"bytes\":%" PRIu64 "}",
                               p,pass_start[p],pass_end[p],pass_bytes[p]);
    }
    printf("],\"reads\":[");
    for(unsigned i=0;i<used;i++) {
        struct record *r=&records[i];if(i)putchar(',');
        printf("{\"file\":%u,\"pass\":%u,\"offset\":%" PRIu64 ",\"bytes\":%" PRIu64
               ",\"startNs\":%" PRIu64 ",\"endNs\":%" PRIu64 ",\"error\":%d}",
               r->file,r->pass,r->offset,r->bytes,r->start,r->end,r->error);
    }
    printf("],\"globalCacheDrop\":false,\"pureUbLinkBandwidth\":false,\"contentDigestComputed\":false}\n");
    for(int i=0;i<count;i++)close(files[i].fd);
    free(buffer);free(records);return failed?1:0;
}
