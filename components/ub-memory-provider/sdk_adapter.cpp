// SDK ABI stays in C++, compiled against the installed public headers.
// Only the public NC shmem API is used. No exported SDK-internal FD or root work.
#include <ubs_mem.h>
#include <algorithm>
#include <sys/mman.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <initializer_list>
#include <mutex>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
std::mutex guard;
bool initialized = false;
char region[128] = "default";
struct Mapping { void* address = nullptr; uint64_t bytes = 0; bool writable = false; char name[48]{}; };
Mapping maps[64];
void sdk_logger(int level, const char* message) {
    if (level < 3 || !message) return;
    for (const char* marker : {"ret=", "ret: ", "rc=", "errCode="}) {
        const char* at = std::strstr(message, marker);
        if (!at) continue;
        char* end = nullptr;
        const long value = std::strtol(at + std::strlen(marker), &end, 10);
        if (end != at + std::strlen(marker)) std::fprintf(stderr, "SDK_NUMERIC_ERROR=%ld\n", value);
    }
}
bool valid_name(const char* name) {
    if (!name || ::strnlen(name, 48) != 37 || std::strncmp(name, "aenv_", 5)) return false;
    for (size_t i = 5; i < 37; ++i)
        if (!std::strchr("0123456789abcdef", name[i])) return false;
    return true;
}
int start() {
    if (initialized) return 0;
    int rc = ubsmem_set_extern_logger(sdk_logger);
    if (rc) return rc;
    rc = ubsmem_set_logger_level(3);
    if (rc) return rc;
    ubsmem_options_t options{};
    rc = ubsmem_init_attributes(&options);
    if (rc) return rc;
    rc = ubsmem_initialize(&options);
    if (rc) { ubsmem_finalize(); return rc; }
    initialized = true;
    return 0;
}
Mapping* find(int slot, uint64_t offset, uint64_t count) {
    if (slot < 1 || slot > 64) return nullptr;
    auto& map = maps[slot - 1];
    if (!map.address || offset > map.bytes || count > map.bytes - offset) return nullptr;
    return &map;
}
}

extern "C" {
int aenv_ub_abi_version() { return 3; }
int aenv_ub_configure_region(const char* value) {
    std::lock_guard<std::mutex> lock(guard);
    if (initialized || !value || !value[0] || ::strnlen(value, sizeof(region)) >= sizeof(region)) return 9001;
    std::strcpy(region, value);
    return 0;
}

int aenv_ub_initialize() {
    std::lock_guard<std::mutex> lock(guard);
    return start();
}

int aenv_ub_allocate(const char* name, uint64_t bytes) {
    std::lock_guard<std::mutex> lock(guard);
    if (!valid_name(name) || !bytes || bytes % (4ULL * 1024 * 1024)) return 9001;
    const int rc = start();
    return rc ? rc : ubsmem_shmem_allocate(region, name, bytes, 0600,
                                          UBSM_FLAG_NONCACHE | UBSM_FLAG_WR_DELAY_COMP);
}

int aenv_ub_map(const char* name, uint64_t bytes, int writable, int* handle,
                uint64_t* backing_coverage) {
    std::lock_guard<std::mutex> lock(guard);
    if (!valid_name(name) || !bytes || bytes % (4ULL * 1024 * 1024) || !handle || !backing_coverage
        || bytes > std::numeric_limits<size_t>::max()) return 9001;
    int slot = -1;
    for (int i = 0; i < 64; ++i) {
        if (maps[i].address && std::strcmp(maps[i].name, name) == 0) return 9002;
        if (!maps[i].address && slot < 0) slot = i;
    }
    if (slot < 0) return 9003;
    int rc = start();
    if (rc) return rc;
    void* address = nullptr;
    rc = ubsmem_shmem_map(nullptr, bytes, PROT_READ | (writable ? PROT_WRITE : 0),
                          MAP_SHARED, name, 0, &address);
    if (rc) return rc;
    auto& mapped = maps[slot];
    // Keep the mapping recorded even if metadata validation or cleanup fails.
    mapped.address = address; mapped.bytes = bytes; mapped.writable = writable != 0;
    std::memcpy(mapped.name, name, 38);
    *handle = slot + 1;
    struct { unsigned char before[64]; ubsmem_shmem_info_t value; unsigned char after[64]; } info{};
    std::memset(info.before, 0xa5, 64); std::memset(info.after, 0x5a, 64);
    rc = ubsmem_shmem_lookup(name, &info.value);
    bool intact = true;
    for (size_t i = 0; i < 64; ++i) intact = intact && info.before[i] == 0xa5 && info.after[i] == 0x5a;
    if (rc || !intact || !address || address == MAP_FAILED || info.value.size != bytes
        || ::strnlen(info.value.name, sizeof(info.value.name)) != 37
        || std::strcmp(info.value.name, name) != 0 || !info.value.mem_num
        || info.value.mem_num > MAX_MEMID_NUM || !info.value.mem_unit_size
        || info.value.mem_unit_size > std::numeric_limits<uint64_t>::max() / info.value.mem_num)
        return rc ? rc : 9004;
    *backing_coverage = info.value.mem_unit_size * info.value.mem_num;
    return 0;
}

int aenv_ub_read(int handle, uint64_t offset, void* destination, uint64_t count) {
    std::lock_guard<std::mutex> lock(guard);
    auto* map = find(handle, offset, count);
    if (!map || !destination || count > 1024 * 1024) return 9001;
    auto* source = static_cast<volatile const unsigned char*>(map->address) + offset;
    auto* out = static_cast<unsigned char*>(destination);
    for (uint64_t i = 0; i < count; ++i) out[i] = source[i];
    return 0;
}

int aenv_ub_write(int handle, uint64_t offset, const void* source, uint64_t count) {
    std::lock_guard<std::mutex> lock(guard);
    auto* map = find(handle, offset, count);
    if (!map || !map->writable || !source || count > 1024 * 1024) return 9001;
    auto* target = static_cast<volatile unsigned char*>(map->address) + offset;
    const auto* in = static_cast<const unsigned char*>(source);
    for (uint64_t i = 0; i < count; ++i) target[i] = in[i];
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    return 0;
}

int aenv_ub_unmap(int handle) {
    std::lock_guard<std::mutex> lock(guard);
    auto* map = find(handle, 0, 0);
    if (!map) return 9001;
    const int rc = ubsmem_shmem_unmap(map->address, map->bytes);
    if (!rc) *map = Mapping{};
    return rc;
}

int aenv_ub_deallocate(const char* name) {
    std::lock_guard<std::mutex> lock(guard);
    if (!valid_name(name)) return 9001;
    for (const auto& map : maps)
        if (map.address && std::strcmp(map.name, name) == 0) return 9005;
    const int rc = start();
    return rc ? rc : ubsmem_shmem_deallocate(name);
}

int aenv_ub_finalize() {
    std::lock_guard<std::mutex> lock(guard);
    for (const auto& map : maps) if (map.address) return 9005;
    if (!initialized) return 0;
    const int rc = ubsmem_finalize();
    if (!rc) initialized = false;
    return rc;
}

// Export every device range needed for the raw image, in public lookup order.
// No stored-layer header or SDK-private descriptor table is involved.
int aenv_ub_open_readonly_fds(int handle, uint64_t bytes, int* fds,
                            uint64_t* lengths, uint32_t capacity, uint32_t* count) {
    std::lock_guard<std::mutex> lock(guard);
    if (!fds || !lengths || !count || !capacity || capacity > 32) return 9001;
    *count = 0;
    for (uint32_t i = 0; i < capacity; ++i) { fds[i] = -1; lengths[i] = 0; }
    auto* map = find(handle, 0, bytes);
    constexpr uint64_t alignment = 2ULL * 1024 * 1024;
    if (!map || map->writable || !bytes || bytes % alignment) return 9001;
    struct { unsigned char before[64]; ubsmem_shmem_info_t value; unsigned char after[64]; } info{};
    std::memset(info.before, 0xa5, 64); std::memset(info.after, 0x5a, 64);
    const int rc = ubsmem_shmem_lookup(map->name, &info.value);
    if (rc) return rc;
    for (size_t i = 0; i < 64; ++i) if (info.before[i] != 0xa5 || info.after[i] != 0x5a) return 9004;
    const auto& value = info.value;
    if (::strnlen(value.name, sizeof(value.name)) != 37 || std::strcmp(value.name, map->name)
        || value.size != map->bytes || !value.mem_num || value.mem_num > MAX_MEMID_NUM
        || !value.mem_unit_size || value.mem_unit_size % alignment
        || value.mem_unit_size > std::numeric_limits<uint64_t>::max() / value.mem_num
        || value.mem_unit_size * value.mem_num < map->bytes) return 9004;
    const uint64_t needed = bytes / value.mem_unit_size + (bytes % value.mem_unit_size != 0);
    if (needed > capacity || needed > value.mem_num) return 9004;
    uint64_t remaining = bytes;
    for (uint32_t i = 0; i < needed; ++i) {
        char path[64]{};
        int fd = -1;
        if (value.mem_id_list[i]) {
            const int length = std::snprintf(path, sizeof(path), "/dev/obmm_shmdev%llu",
                static_cast<unsigned long long>(value.mem_id_list[i]));
            if (length > 0 && static_cast<size_t>(length) < sizeof(path))
                fd = ::open(path, O_RDONLY | O_SYNC | O_CLOEXEC | O_NOFOLLOW);
        }
        struct stat metadata{};
        if (fd < 0 || ::fstat(fd, &metadata) != 0 || !S_ISCHR(metadata.st_mode)) {
            if (fd >= 0) ::close(fd);
            for (uint32_t j = 0; j < *count; ++j) { ::close(fds[j]); fds[j] = -1; lengths[j] = 0; }
            *count = 0;
            return 9006;
        }
        fds[i] = fd;
        lengths[i] = std::min(remaining, static_cast<uint64_t>(value.mem_unit_size));
        remaining -= lengths[i];
        ++*count;
    }
    return 0;
}
}
