/* Metadata-only named-object reconciliation. No allocate/map/deallocate API. */
#include <stdbool.h>
#include <ubs_mem.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void quiet(int level, const char *message) { (void)level; (void)message; }
static int valid(const char *s) {
    if (!s || strlen(s)!=37 || strncmp(s,"aenv_",5)) return 0;
    for (int i=5;i<37;i++) if (!strchr("0123456789abcdef",s[i])) return 0;
    return 1;
}
int main(int argc,char **argv) {
    if (argc<2 || argc>33) return 2;
    for (int i=1;i<argc;i++) if (!valid(argv[i])) return 2;
    ubsmem_options_t opts;
    int rc=ubsmem_set_extern_logger(quiet);
    if (!rc) rc=ubsmem_set_logger_level(3);
    if (!rc) rc=ubsmem_init_attributes(&opts);
    if (!rc) rc=ubsmem_initialize(&opts);
    if (rc) { int fin=ubsmem_finalize();
        printf("{\"initializeRc\":%d,\"finalizeRc\":%d,\"objects\":[],\"allAbsent\":false}\n",rc,fin); return 3; }
    printf("{\"initializeRc\":0,\"objects\":[");
    int absent=1;
    for (int i=1;i<argc;i++) {
        struct { unsigned char before[64]; ubsmem_shmem_info_t info; unsigned char after[64]; } guarded;
        memset(&guarded,0,sizeof(guarded));memset(guarded.before,0xa5,64);memset(guarded.after,0x5a,64);
        rc=ubsmem_shmem_lookup(argv[i],&guarded.info);
        int intact=1;
        for(int j=0;j<64;j++) if(guarded.before[j]!=0xa5 || guarded.after[j]!=0x5a) intact=0;
        int missing=(rc==UBSM_ERR_NOT_FOUND && intact);
        if(!missing) absent=0;
        /* No physical addresses or opaque memory IDs are exposed. */
        printf("%s{\"name\":\"%s\",\"rc\":%d,\"guardIntact\":%s,\"notFound\":%s}",
               i==1?"":",",argv[i],rc,intact?"true":"false",missing?"true":"false");
    }
    int fin=ubsmem_finalize();
    printf("],\"finalizeRc\":%d,\"allAbsent\":%s}\n",fin,absent && !fin?"true":"false");
    return absent && !fin?0:4;
}
