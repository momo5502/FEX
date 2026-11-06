// SPDX-License-Identifier: MIT
#pragma once
#include <FEXCore/Utils/CompilerDefs.h>
#include <FEXCore/Utils/EnumOperators.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/TypeDefines.h>

#ifndef _WIN32
#include <stdlib.h>
#ifdef __APPLE__
#include <malloc/malloc.h>
#include <pthread.h>
#else
#include <malloc.h>
#endif
#include <sys/mman.h>
#else
#define NTDDI_VERSION 0x0A000005
#include <memoryapi.h>
#endif

#include <new>
#include <cstddef>
#include <cstdint>
#include <sys/types.h>

namespace FEXCore::Allocator {
enum class ProtectOptions : uint32_t {
  None = 0,
  Read = (1U << 0),
  Write = (1U << 1),
  Exec = (1U << 2),
};
FEX_DEF_NUM_OPS(ProtectOptions)

enum class THPControl {
  Enable,
  Disable,
};

#ifndef _WIN32
FEX_DEFAULT_VISIBILITY void SetupHooks(size_t PageSize);
#else
using VirtualNamePtr = void (*)(const char*, const void*, size_t);
using VirtualTHPPtr = void (*)(const void*, size_t, THPControl);
struct HookPtrs {
  VirtualNamePtr VirtualName;
  VirtualTHPPtr VirtualTHPControl;
};
FEX_DEFAULT_VISIBILITY void SetupHooks(size_t PageSize, HookPtrs Ptrs);
#endif
FEX_DEFAULT_VISIBILITY void ClearHooks();

#ifdef _WIN32
inline void* VirtualAlloc(void* Base, size_t Size, bool Execute = false, bool Commit = true) {
  // Allocate top-down to avoid polluting the lower VA space, as even on 64-bit some programs (i.e. LuaJIT) require allocations below 4GB.
  DWORD Flags = (Commit ? MEM_COMMIT : 0) | MEM_RESERVE | MEM_TOP_DOWN;
#ifdef ARCHITECTURE_arm64ec
  MEM_EXTENDED_PARAMETER Parameter {};
  if (Execute) {
    Parameter.Type = MemExtendedParameterAttributeFlags;
    Parameter.ULong64 = MEM_EXTENDED_PARAMETER_EC_CODE;
  };
  return ::VirtualAlloc2(nullptr, Base, Size, Flags, Execute ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE, Execute ? &Parameter : nullptr,
                         Execute ? 1 : 0);
#else
  return ::VirtualAlloc(Base, Size, Flags, Execute ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE);
#endif
}

inline void* VirtualAlloc(size_t Size, bool Execute = false, bool Commit = true) {
  return VirtualAlloc(nullptr, Size, Execute, Commit);
}

inline void VirtualFree(void* Ptr, size_t Size) {
  ::VirtualFree(Ptr, 0, MEM_RELEASE);
}

inline void VirtualDontNeed(void* Ptr, size_t Size, bool Recommit = true) {
  // Zero the page-aligned region, preserving permissions.
  MEMORY_BASIC_INFORMATION Info;
  ::VirtualQuery(Ptr, &Info, sizeof(Info));
  ::VirtualFree(Ptr, Size, MEM_DECOMMIT);
  if (Recommit) {
    ::VirtualAlloc(Ptr, Size, MEM_COMMIT, Info.Protect);
  }
}

inline bool VirtualProtect(void* Ptr, size_t Size, ProtectOptions options) {
  DWORD prot {PAGE_NOACCESS};

  if (options == ProtectOptions::None) {
    prot = PAGE_NOACCESS;
  } else if (options == ProtectOptions::Read) {
    prot = PAGE_READONLY;
  } else if (options == (ProtectOptions::Read | ProtectOptions::Write)) {
    prot = PAGE_READWRITE;
  } else if (options == (ProtectOptions::Read | ProtectOptions::Exec)) {
    prot = PAGE_EXECUTE_READ;
  } else if (options == (ProtectOptions::Read | ProtectOptions::Write | ProtectOptions::Exec)) {
    prot = PAGE_EXECUTE_READWRITE;
  } else {
    LOGMAN_MSG_A_FMT("Unknown VirtualProtect options combination");
  }

  return ::VirtualProtect(Ptr, Size, prot, nullptr) == 0;
}

FEX_DEFAULT_VISIBILITY extern VirtualNamePtr VirtualName;
FEX_DEFAULT_VISIBILITY extern VirtualTHPPtr VirtualTHPControl;
#else
using MMAP_Hook = void* (*)(void*, size_t, int, int, int, off_t);
using MUNMAP_Hook = int (*)(void*, size_t);
using DONTNEED_Hook = void (*)(void*, size_t);

FEX_DEFAULT_VISIBILITY extern MMAP_Hook mmap;
FEX_DEFAULT_VISIBILITY extern MUNMAP_Hook munmap;
// Told before VirtualDontNeed replaces pages, so an embedder that maps this memory elsewhere (a hypervisor guest)
// can drop its view of the old pages.
FEX_DEFAULT_VISIBILITY extern DONTNEED_Hook dontneed;
FEX_DEFAULT_VISIBILITY extern void VirtualName(const char* Name, void* Ptr, size_t Size);

// All commit parameters are ignored here, they are unnecessary as Linux supports overcommit

#ifdef __APPLE__
// Apple's hardened runtime forbids RWX mappings outright: executable anonymous memory must be
// requested with MAP_JIT, and even then a thread may only write to it while that thread's JIT
// write-protection is explicitly disabled (see JITWriteScope below) - RWX from mmap() alone
// (what the generic path below does on Linux) is rejected.
inline int MapJitFlagIfExecutable(bool Execute) {
  return Execute ? MAP_JIT : 0;
}
#endif

inline void* VirtualAlloc(size_t Size, bool Execute = false, bool Commit = true) {
#ifdef __APPLE__
  return FEXCore::Allocator::mmap(nullptr, Size, PROT_READ | PROT_WRITE | (Execute ? PROT_EXEC : 0),
                                  MAP_PRIVATE | MAP_ANONYMOUS | MapJitFlagIfExecutable(Execute), -1, 0);
#else
  return FEXCore::Allocator::mmap(nullptr, Size, PROT_READ | PROT_WRITE | (Execute ? PROT_EXEC : 0), MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
}

inline void* VirtualAlloc(void* Base, size_t Size, bool Execute = false, bool Commit = true) {
#ifdef __APPLE__
  return FEXCore::Allocator::mmap(Base, Size, PROT_READ | PROT_WRITE | (Execute ? PROT_EXEC : 0),
                                  MAP_PRIVATE | MAP_ANONYMOUS | MapJitFlagIfExecutable(Execute), -1, 0);
#else
  return FEXCore::Allocator::mmap(Base, Size, PROT_READ | PROT_WRITE | (Execute ? PROT_EXEC : 0), MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
}

#ifdef __APPLE__
// Toggles the calling thread's JIT write-protection (Apple Silicon's W^X enforcement is
// per-thread, not per-mapping): writable-and-not-executable while `false`, executable-and-not-
// writable while `true`. Must bracket any code that writes into a MAP_JIT region - wrap the
// coarse "compile one block" / "emit one stub" boundary, not individual instruction emits, since
// toggling has real per-call overhead.
struct JITWriteScope {
  JITWriteScope() {
    ::pthread_jit_write_protect_np(0);
  }
  ~JITWriteScope() {
    ::pthread_jit_write_protect_np(1);
  }
  JITWriteScope(const JITWriteScope&) = delete;
  JITWriteScope& operator=(const JITWriteScope&) = delete;
};
#endif

inline void VirtualFree(void* Ptr, size_t Size) {
  FEXCore::Allocator::munmap(Ptr, Size);
}
inline void VirtualDontNeed(void* Ptr, size_t Size, bool Recommit = true) {
#ifdef __APPLE__
  // Darwin's madvise(MADV_DONTNEED) does NOT zero-fill anonymous pages the way Linux does - it is
  // effectively advisory - so every caller that relies on VirtualDontNeed to *clear* memory would
  // silently keep stale data on macOS. The critical one is LookupCache::ClearThreadLocalCaches, run on
  // each JIT code-buffer switch (ChangeGuestToHostMapping) to drop the per-thread L1/L2 block lookup
  // cache: with the clear silently no-op'ing, a stale entry mapping a guest RIP to an older buffer's
  // host code survives, and once that buffer is freed the dispatcher jumps into it - inaccessible
  // (PROT_NONE) on Apple - and faults. Honour the zero-on-reuse contract explicitly: for page-aligned
  // regions replace them with fresh, zero-filled, decommitted anonymous pages (mmap MAP_FIXED, the
  // Darwin equivalent of Linux's MADV_DONTNEED on anonymous memory - this also keeps the large, sparsely
  // populated L2 page table from being fully committed by a plain memset); zero the rare sub-page
  // caller in place (__builtin_memset avoids pulling <string.h> into this widely-included header).
  const uintptr_t Addr = reinterpret_cast<uintptr_t>(Ptr);
  if ((Addr & (FEXCore::Utils::FEX_HOST_PAGE_SIZE - 1)) == 0 && (Size & (FEXCore::Utils::FEX_HOST_PAGE_SIZE - 1)) == 0) {
    if (dontneed) {
      dontneed(Ptr, Size);
    }
    ::mmap(Ptr, Size, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  } else {
    __builtin_memset(Ptr, 0, Size);
  }
#else
  ::madvise(reinterpret_cast<void*>(Ptr), Size, MADV_DONTNEED);
#endif
}
inline bool VirtualProtect(void* Ptr, size_t Size, ProtectOptions options) {
  int prot {PROT_NONE};
  if ((options & ProtectOptions::Read) == ProtectOptions::Read) {
    prot |= PROT_READ;
  }
  if ((options & ProtectOptions::Write) == ProtectOptions::Write) {
    prot |= PROT_WRITE;
  }
  if ((options & ProtectOptions::Exec) == ProtectOptions::Exec) {
    prot |= PROT_EXEC;
  }

  return ::mprotect(Ptr, Size, prot) == 0;
}

inline void VirtualTHPControl(const void* Ptr, size_t Size, THPControl Control) {
#ifdef __APPLE__
  // Darwin has no per-mapping transparent-huge-page madvise hint; the VM system manages this itself.
  (void)Ptr;
  (void)Size;
  (void)Control;
#else
  ::madvise(const_cast<void*>(Ptr), Size, Control == THPControl::Enable ? MADV_HUGEPAGE : MADV_NOHUGEPAGE);
#endif
}

#endif

// Memory allocation routines to be defined externally.
// This allows to use jemalloc for emulation while using the normal allocator
// for host tools without building FEXCore twice.
void* malloc(size_t size);
void* calloc(size_t n, size_t size);
void* memalign(size_t align, size_t s);
void* valloc(size_t size);
int posix_memalign(void** r, size_t a, size_t s);
void* realloc(void* ptr, size_t size);
void free(void* ptr);
size_t malloc_usable_size(void* ptr);
void* aligned_alloc(size_t a, size_t s);
void aligned_free(void* ptr);

FEX_DEFAULT_VISIBILITY extern void InitializeThread();

#ifndef _WIN32
void SetupAllocatorHooks(void* (*)(void* addr, size_t length, int prot, int flags, int fd, off_t offset), int (*)(void* addr, size_t length));
#endif

struct FEXAllocOperators {
  FEXAllocOperators() = default;

  void* operator new(size_t size) {
    return FEXCore::Allocator::malloc(size);
  }

  void* operator new(size_t size, std::align_val_t align) {
    return FEXCore::Allocator::aligned_alloc(static_cast<size_t>(align), size);
  }

  void operator delete(void* ptr) {
    return FEXCore::Allocator::free(ptr);
  }

  void operator delete(void* ptr, std::align_val_t align) {
    return FEXCore::Allocator::aligned_free(ptr);
  }
};
} // namespace FEXCore::Allocator
