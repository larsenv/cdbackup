#include <stddef.h>
#include <stdint.h>

/* Compatibility exports for the vendored libpatcher archive, which predates
 * libogc's PPC-prefixed cache symbol names. */
extern void PPCDCacheFlushAsync(const volatile void *buffer, size_t size);
extern void PPCICacheInvalidate(const volatile void *buffer, size_t size);

void DCFlushRange(void *buffer, uint32_t size)
{
    PPCDCacheFlushAsync(buffer, size);
}

void ICInvalidateRange(void *buffer, uint32_t size)
{
    PPCICacheInvalidate(buffer, size);
}
