// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) Status Research & Development GmbH

// A `free` defined in the test executable: BoringSSL's calls to `free` resolve
// here, so every block it releases is scanned for a marker before it goes
// back to the system allocator. `OPENSSL_free` zeroes a block before calling
// `free`, so a match means the block was released without zeroing.
// macOS and glibc only (test_ssl_buffer_zeroing.nim skips elsewhere).
#if !defined(__APPLE__)
#define _GNU_SOURCE
#endif
#include <stddef.h>
#include <string.h>

#if defined(__APPLE__)
#include <malloc/malloc.h>
#else
#include <malloc.h>
extern void __libc_free(void *);
#endif

static const unsigned char *marker;
static size_t marker_len;
static volatile int hits;

void freescan_set(const void *p, size_t n) {
  marker = (const unsigned char *)p;
  marker_len = n;
  hits = 0;
}

int freescan_hits(void) { return hits; }

static int holds_marker(const void *p, size_t n) {
  return marker != NULL && n >= marker_len && memmem(p, n, marker, marker_len) != NULL;
}

void free(void *p) {
  if (p == NULL) {
    return;
  }
#if defined(__APPLE__)
  malloc_zone_t *zone = malloc_zone_from_ptr(p);
  if (zone == NULL) {
    return;
  }
  if (holds_marker(p, malloc_size(p))) {
    hits++;
  }
  malloc_zone_free(zone, p);
#else
  if (holds_marker(p, malloc_usable_size(p))) {
    hits++;
  }
  __libc_free(p);
#endif
}
