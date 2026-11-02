/* Production fill_pool function with deterministic kernel dependency fixtures.
 * SHA fixture tests the comparison/state logic, NOT cryptographic correctness.
 * No kernel scheduling, actual NC mapping or UB hardware acceptance is claimed.
 */
#define main existing_read_tests
#include "read_contract.c"
#undef main
#define SHA256_DIGEST_SIZE 32
#define GFP_KERNEL 0
#define __iomem
#define IS_ALIGNED(x,a) (((x)&((a)-1))==0)
#define kvzalloc(n,f) calloc(1,n)
#define kvmalloc(n,f) malloc(n)
#define kvfree(p) free(p)
#define memcpy_toio(to,from,n) memcpy(to,from,n)
#define wmb() ((void)0)
#define OBMM_PMEM_ABI 1
struct pmem_slot { u32 bytes;u8 state;u8 sha256[32]; };
struct obmm_pmem_pool_fill { u32 version,bytes;u8 uuid[16];u64 slot_offset,user_data;u8 sha256[32]; };
static bool pmem_demand_write_enable;
static struct pmem_volume *test_pool;
static struct pmem_volume *lookup_pool(const u8 uuid[16]) { return uuid[0]==1?test_pool:NULL; }
static void sha256(const u8 *data,unsigned int n,u8 *digest)
{ for(unsigned i=0;i<32;i++)digest[i]=data[i%n]^data[n-1]^(u8)(n+i); }
#include "pool_methods.inc"

int main(void)
{
    existing_read_tests();
    u8 *memory=calloc(1,OBMM_PMEM_LOAD_BYTES),*data=malloc(PAGE_SIZE);
    assert(memory && data);memset(data,0x64,PAGE_SIZE);data[0]=3;
    struct pmem_extent extent={0,OBMM_PMEM_LOAD_BYTES,memory,true};
    struct pmem_slot slot={0};
    struct pmem_volume pool={.bytes=OBMM_PMEM_LOAD_BYTES,.extents=&extent,.nr_extents=1,.slots=&slot,.controlled_writer=true};
    struct obmm_pmem_pool_fill request={.version=1,.bytes=PAGE_SIZE,.uuid={1},.user_data=1};
    test_pool=&pool;sha256(data,PAGE_SIZE,request.sha256);
    assert(fill_pool(&request,true,data)==-EINVAL && slot.state==0);
    pmem_demand_write_enable=true;
    request.sha256[0]^=1;
    assert(fill_pool(&request,true,data)==-EBADMSG && slot.state==0 && memory[0]==0);
    request.sha256[0]^=1;
    assert(fill_pool(&request,true,data)==0 && slot.state==2 && slot.bytes==PAGE_SIZE);
    assert(!memcmp(memory,data,PAGE_SIZE));assert(memory[PAGE_SIZE]==0);
    data[0]=8;
    assert(fill_pool(&request,true,data)==-EEXIST && memory[0]==3);
    pool.controlled_writer=false;slot.state=0;request.user_data=0;
    assert(fill_pool(&request,false,NULL)==0 && slot.state==2 && memory[0]==3);
    pool.controlled_writer=true;slot.state=0;request.user_data=1;
    sha256(data,PAGE_SIZE,request.sha256);fail_copy=true;
    assert(fill_pool(&request,true,data)==-EIO && slot.state==3);
    fail_copy=false;
    assert(fill_pool(&request,true,data)==-EEXIST && slot.state==3);
    free(memory);free(data);
    puts("PRODUCTION_POOL_WRITE_ONCE_STATE_PASS_NO_KERNEL_OR_HARDWARE_ACCEPTANCE");
    return 0;
}
