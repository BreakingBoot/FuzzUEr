#!/usr/bin/env python3
"""Assert the SMM allocator describes its freed memory, and that a freed pool block is
not handed straight back.

Three things that were missing, all in MdeModulePkg/Core/PiSmmCore.

**Page.c had no poisoning at all.** `grep -c 'Asan\\|Poison' Page.c` was 0. The DXE core
poisons a freed page range (MdeModulePkg/Core/Dxe/Mem/Page.c, twice: once in
CoreInternalFreePages and once in CoreFreePoolPages, because the pool's page-backed
blocks bypass the first), and SMM did not -- so an access to a freed SMM page, or to
SMRAM that was never allocated at all, read as addressable and raised nothing. The whole
of free SMRAM reaches `SmmInternalFreePagesEx` once through `SmmAddMemoryRegion`, which
is what makes the never-allocated case reachable from the same hook.

The ORDER is the part that is easy to get wrong in the direction that looks right. DXE
poisons AFTER its conversion because CoreConvertPages unpoisons on the way back into the
map. SMM must poison BEFORE the range is linked, because `ConvertSmmMemoryMapEntry` can
call `AllocateMemoryMapEntry`, which allocates a page out of the very range being freed
-- at SMM core init, out of the range being added. Poisoning afterwards would poison a
page that had just been handed out and was about to be filled with MEMORY_MAP
descriptors. The assertions below are on the POSITION of the poison relative to the
validation returns and to the list insert, not on its presence.

**There was no quarantine.** `InternalFreePoolByIndex` poisoned the freed block and put
it straight back on `mSmmPoolLists`; `InternalAllocPoolByIndex` takes the FIRST node of
that list, so the next allocation of the same size class got that same block and
unpoisoned it. The poison expired before anything could trip over it, and a double free
found Signature == 0 and returned EFI_INVALID_PARAMETER in silence. The quarantine holds
recent frees back under two bounds at once, and -- because a held block is on no list --
can poison from before the caller's buffer rather than from `sizeof (FREE_POOL_HEADER)`,
which is the difference between catching a use-after-free at Buffer[0] and not.

The quarantine is checked by COMPILING IT, not by reading it: the two functions are
extracted from Pool.c and driven against a stub, so the FIFO order, both bounds, the
no-lost-block property and the poisoned spans are measured. Struct sizes come from
ctypes as well as from gcc and the two have to agree -- hand-written ABI padding got
sizeof (POOL_HEADER) wrong here once.

Run: python3 scripts/smm_page_poison_check.py
"""
import ctypes
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
FORK = os.path.join(REPO, 'eval_source', 'edk2')
SMM = os.path.join(FORK, 'MdeModulePkg', 'Core', 'PiSmmCore')

POOL_C = os.path.join(SMM, 'Pool.c')
PAGE_C = os.path.join(SMM, 'Page.c')
SMM_H = os.path.join(SMM, 'PiSmmCore.h')
DSC = os.path.join(FORK, 'OvmfPkg', 'OvmfPkgX64.dsc')
FDF = os.path.join(FORK, 'OvmfPkg', 'OvmfPkgX64.fdf')
BENCH = os.path.join(FORK, 'MdeModulePkg', 'Universal', 'SanBenchSmm')

FAILED = 0
PASSED = 0


def check(what, ok, detail=''):
    global FAILED, PASSED
    if ok:
        PASSED += 1
        print(f'  [OK]   {what}')
    else:
        FAILED += 1
        print(f'  [FAIL] {what}' + (f'\n         {detail}' if detail else ''))


def read(path):
    if not os.path.exists(path):
        return ''
    with open(path, encoding='utf-8', errors='replace', newline='') as handle:
        return handle.read().replace('\r\n', '\n')


def body(src, name):
    """The brace-matched body of the function definition called `name`.

    Anchored on a definition rather than on the first mention: Page.c forward-declares
    SmmInternalAllocatePagesEx at the top of the file, and a window anchored there spans
    the wrong region entirely.
    """
    for match in re.finditer(r'^%s\s*\(' % re.escape(name), src, re.M):
        close = src.index(')', match.end())
        rest = src[close + 1:]
        if not rest.lstrip().startswith('{'):
            continue
        start = src.index('{', close)
        depth = 0
        for k in range(start, len(src)):
            if src[k] == '{':
                depth += 1
            elif src[k] == '}':
                depth -= 1
                if depth == 0:
                    return src[start:k + 1]
    raise LookupError(name)


def region(src, start_pat, end_pat):
    """The text between two anchors, used to lift real declarations into the stub."""
    begin = re.search(start_pat, src)
    stop = re.search(end_pat, src)
    if begin is None or stop is None:
        raise LookupError(start_pat)
    return src[begin.start():stop.end()]


# --------------------------------------------------------------------------- the stub
#
# One translation unit: the stub, the real declarations lifted out of PiSmmCore.h, the
# real quarantine lifted out of Pool.c, and a driver. The quarantine's statics are STATIC,
# which is exactly why the driver has to live in the same unit to read them.
#
STUB = r'''
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned long long  UINT64;
typedef unsigned long       UINTN;
typedef unsigned int        UINT32;
typedef unsigned short      UINT16;
typedef unsigned char       UINT8;
typedef unsigned char       BOOLEAN;
typedef char                CHAR8;
typedef long                INTN;
typedef UINT64              EFI_PHYSICAL_ADDRESS;

#define IN
#define OUT
#define OPTIONAL
#define CONST     const
#define STATIC    static
#define TRUE      1
#define FALSE     0
#define VOID      void

#define OFFSET_OF(TYPE, Field)     ((UINTN) __builtin_offsetof(TYPE, Field))
#define SIGNATURE_16(A, B)         ((A) | ((B) << 8))
#define SIGNATURE_32(A, B, C, D)   (SIGNATURE_16 (A, B) | ((UINT32)(SIGNATURE_16 (C, D)) << 16))
#define SIZE_64KB                  0x00010000
#define SIZE_32KB                  0x00008000
#define EFI_PAGE_SHIFT             12
#define EFI_PAGE_SIZE              0x1000
#define EFI_PAGES_TO_SIZE(p)       ((p) << EFI_PAGE_SHIFT)

#define MIN_POOL_SHIFT  6
#define MIN_POOL_SIZE   (1 << MIN_POOL_SHIFT)
#define MAX_POOL_SHIFT  (EFI_PAGE_SHIFT - 1)
#define MAX_POOL_SIZE   (1 << MAX_POOL_SHIFT)
#define MAX_POOL_INDEX  (MAX_POOL_SHIFT - MIN_POOL_SHIFT + 1)

#define kAsanHeapFreeMagic          0xfd
#define kAsanHeapLeftRedzoneMagic   0xfa
/*
 * kAsanHeapLeftRedzoneSize, POOL_HEAD_SIGNATURE and POOL_TAIL_SIGNATURE are deliberately
 * NOT defined here. They come from the extracted PiSmmCore.h below, because a stub copy
 * SHADOWS the header: with 128 pinned here, a header carrying a different redzone was
 * compiled as 128 while the ctypes model read the header's real value, and the size
 * assertions then measured a struct the source does not declare.
 */

#define ASSERT(x)  do { if (!(x)) { gAssertions++; } } while (0)

typedef enum {
  EfiReservedMemoryType,
  EfiLoaderCode,
  EfiLoaderData,
  EfiBootServicesCode,
  EfiBootServicesData,
  EfiRuntimeServicesCode,
  EfiRuntimeServicesData,
  EfiConventionalMemory,
  EfiMaxMemoryType
} EFI_MEMORY_TYPE;

typedef struct _LIST_ENTRY LIST_ENTRY;
struct _LIST_ENTRY {
  LIST_ENTRY  *ForwardLink;
  LIST_ENTRY  *BackLink;
};

static int    gAssertions = 0;
static int    gBadWrites = 0;
static int    gIterations = 0;

/*
 * A byte of poison state per byte of simulated SMRAM, rather than AsanLib's granule
 * encoding. Every span this code writes is 8-aligned -- asserted separately -- so the
 * byte map and the real shadow agree, and the byte map reports an exact span.
 */
#define SMRAM_BYTES  (1u << 20)
static UINT8  gMem[SMRAM_BYTES] __attribute__ ((aligned (4096)));
static UINT8  gPoison[SMRAM_BYTES];

static UINTN MemOff (UINTN Addr) { return Addr - (UINTN)gMem; }

static int InRange (UINTN Addr, UINTN Size) {
  return Size != 0 && Addr >= (UINTN)gMem && Addr + Size <= (UINTN)gMem + SMRAM_BYTES;
}

void PoisonPool (const UINTN Addr, UINTN Size, const UINT8 Value) {
  if (!InRange (Addr, Size)) { gBadWrites++; return; }
  memset (gPoison + MemOff (Addr), Value, Size);
}

void UnpoisonPool (const UINTN Addr, UINTN Size) {
  if (!InRange (Addr, Size)) { gBadWrites++; return; }
  memset (gPoison + MemOff (Addr), 0, Size);
}

void PoisonPages (const UINT64 Start, const UINTN PageNum, const UINT8 Value) {
  PoisonPool ((UINTN)Start, EFI_PAGES_TO_SIZE (PageNum), Value);
}

void UnpoisonPages (const UINT64 Start, const UINTN PageNum) {
  UnpoisonPool ((UINTN)Start, EFI_PAGES_TO_SIZE (PageNum));
}

void SerialOutput (const char *s) { (void)s; }
void Num2Str64bit (UINT64 n, char *out) { (void)n; out[0] = 0; }
void AsanSignalSolution (void) { }

/*
 * The write a list insertion performs lands in the block's own Link. If that Link is
 * still poisoned the SMM core is writing to memory it has described as freed, and the
 * sanitizer reports the core against itself -- which is the bug this stub is here to
 * catch, so it is counted rather than ignored.
 */
static void CheckedLinkWrite (LIST_ENTRY *Entry) {
  UINTN i;
  if (!InRange ((UINTN)Entry, sizeof (LIST_ENTRY))) { gBadWrites++; return; }
  for (i = 0; i < sizeof (LIST_ENTRY); i++) {
    if (gPoison[MemOff ((UINTN)Entry) + i] != 0) { gBadWrites++; return; }
  }
}

void InitializeListHead (LIST_ENTRY *Head) {
  Head->ForwardLink = Head;
  Head->BackLink = Head;
}

void InsertHeadList (LIST_ENTRY *Head, LIST_ENTRY *Entry) {
  CheckedLinkWrite (Entry);
  Entry->ForwardLink = Head->ForwardLink;
  Entry->BackLink = Head;
  Head->ForwardLink->BackLink = Entry;
  Head->ForwardLink = Entry;
}
'''

DRIVER = r'''
/* ------------------------------------------------------------------ the driver */

static UINTN  gBlockSize[4096];
static int    gBlocks = 0;

static FREE_POOL_HEADER *MakeBlock (UINTN Size) {
  /*
   * Blocks are laid out end to end from the base of the simulated SMRAM. The quarantine
   * never looks at the memory between blocks, so the layout only has to be disjoint.
   *
   * Two refusals rather than two silent overruns. A block smaller than FREE_POOL_HEADER
   * cannot exist: SmmInternalAllocatePool adds POOL_OVERHEAD before it picks a bucket,
   * so the smallest real bucket block is 256 even though MIN_POOL_SIZE is 64 -- and at
   * 64 the Link the free path writes lands PAST the block, in the next one, which made a
   * mutation look like a crash in this driver rather than the behaviour change it was.
   * And a layout that runs off the end of gMem corrupts whatever follows, which is how a
   * pathological eviction order turned into a segfault in an unrelated print.
   */
  static UINTN Next = 0;
  FREE_POOL_HEADER *Hdr;
  if (Size < sizeof (FREE_POOL_HEADER) || Next + Size > SMRAM_BYTES) {
    gBadWrites++;
    return NULL;
  }
  Hdr = (FREE_POOL_HEADER *)(gMem + Next);
  Next += Size;
  memset (Hdr, 0, Size);
  Hdr->Header.Size      = Size;
  Hdr->Header.Type      = EfiRuntimeServicesData;
  Hdr->Header.Available = TRUE;
  Hdr->Header.Signature = POOL_QUARANTINE_SIGNATURE;
  gBlockSize[gBlocks++] = Size;
  return Hdr;
}

static UINTN IndexFor (UINTN Size) {
  UINTN Index = 0;
  while ((UINTN)(MIN_POOL_SIZE << Index) < Size) { Index++; }
  return Index;
}

/* The members of one free list, head first, as offsets into the simulated SMRAM. */
static void PrintList (UINTN Index) {
  LIST_ENTRY *Head = &mSmmPoolLists[SmmPoolTypeData][Index];
  LIST_ENTRY *Node;
  printf ("list %lu:", (unsigned long)Index);
  for (Node = Head->ForwardLink; Node != Head; Node = Node->ForwardLink) {
    FREE_POOL_HEADER *Hdr = (FREE_POOL_HEADER *)((UINT8 *)Node - OFFSET_OF (FREE_POOL_HEADER, Link));
    printf (" %lu", (unsigned long)MemOff ((UINTN)Hdr));
  }
  printf ("\n");
}

/* The poisoned span of one block, as [first,last] byte offsets within the block. */
static void PrintSpan (FREE_POOL_HEADER *Hdr) {
  UINTN Base = MemOff ((UINTN)Hdr);
  UINTN Size = gBlockSize[0];
  UINTN i, first = Size, last = Size;
  for (i = 0; i < Size; i++) {
    if (gPoison[Base + i] != 0) { if (first == Size) { first = i; } last = i; }
  }
  if (first == Size) { printf ("span none\n"); }
  else { printf ("span %lu %lu %u\n", (unsigned long)first, (unsigned long)last,
                 gPoison[Base + first]); }
}

int main (int argc, char **argv) {
  const char *mode = argc > 1 ? argv[1] : "fifo";
  int count = argc > 2 ? atoi (argv[2]) : 8;
  UINTN size = argc > 3 ? (UINTN)atol (argv[3]) : 256;
  int i, j;
  UINTN peakBytes = 0, peakCount = 0;

  for (i = 0; i < SmmPoolTypeMax; i++) {
    for (j = 0; j < MAX_POOL_INDEX; j++) { InitializeListHead (&mSmmPoolLists[i][j]); }
  }

  printf ("sizeof POOL_HEADER %lu\n", (unsigned long)sizeof (POOL_HEADER));
  printf ("sizeof POOL_TAIL %lu\n", (unsigned long)sizeof (POOL_TAIL));
  printf ("sizeof FREE_POOL_HEADER %lu\n", (unsigned long)sizeof (FREE_POOL_HEADER));
  printf ("sizeof FREE_PAGE_LIST %lu\n", (unsigned long)sizeof (FREE_PAGE_LIST));
  printf ("offset Link %lu\n", (unsigned long)OFFSET_OF (FREE_POOL_HEADER, Link));
  printf ("offset OriSize %lu\n", (unsigned long)OFFSET_OF (POOL_HEADER, OriSize));
  printf ("offset Size %lu\n", (unsigned long)OFFSET_OF (POOL_HEADER, Size));
  printf ("offset NumberOfPages %lu\n",
          (unsigned long)OFFSET_OF (FREE_PAGE_LIST, NumberOfPages));
  printf ("sizeof LIST_ENTRY %lu\n", (unsigned long)sizeof (LIST_ENTRY));
  printf ("sizeof EFI_PAGE_SIZE %lu\n", (unsigned long)EFI_PAGE_SIZE);
  printf ("keep %lu\n", (unsigned long)ASAN_SMM_QUARANTINE_KEEP);
  printf ("slots %lu\n", (unsigned long)ASAN_SMM_QUARANTINE_SLOTS);
  printf ("ceiling %lu\n", (unsigned long)ASAN_SMM_QUARANTINE_MAX_BYTES);
  printf ("quarantine_sig %lu\n", (unsigned long)(UINT32)POOL_QUARANTINE_SIGNATURE);
  printf ("head_sig %lu\n", (unsigned long)(UINT32)POOL_HEAD_SIGNATURE);
  printf ("tail_sig %lu\n", (unsigned long)(UINT32)POOL_TAIL_SIGNATURE);

  if (!strcmp (mode, "span")) {
    /* One block in and one block out, to read the two spans the design turns on. */
    FREE_POOL_HEADER *Hdr = MakeBlock (size);
    if (Hdr == NULL) { printf ("bad %d assertions %d\n", gBadWrites, gAssertions); return 0; }
    AsanSmmQuarantinePush (Hdr, SmmPoolTypeData, IndexFor (size));
    printf ("held ");
    PrintSpan (Hdr);
    /*
     * Bounded by the ring itself. Under a correct FIFO the first block is out after
     * ASAN_SMM_QUARANTINE_SLOTS more pushes; a bound of 100000 instead meant a quarantine
     * that never released it filled the simulated SMRAM and crashed, which reads as a
     * broken harness instead of a failed assertion.
     */
    while (mAsanSmmQuarantineCount > 0 && gIterations < ASAN_SMM_QUARANTINE_SLOTS + 8) {
      FREE_POOL_HEADER *Filler = MakeBlock (size);
      if (Filler == NULL) { break; }
      AsanSmmQuarantinePush (Filler, SmmPoolTypeData, IndexFor (size));
      gIterations++;
    }
    printf ("released ");
    PrintSpan (Hdr);
    printf ("bad %d assertions %d\n", gBadWrites, gAssertions);
    return 0;
  }

  for (i = 0; i < count; i++) {
    /* Sizes cycle through the buckets in "mixed" so the byte bound, not the count
       bound, is the one that binds. */
    /*
     * The top three buckets, not all six. Across the whole range the average block is
     * small enough that ASAN_SMM_QUARANTINE_SLOTS blocks fit under the byte ceiling, so
     * the slot bound binds, the byte bound does nothing, and removing it entirely still
     * passed. 512/1024/2048 averages 1194, and SLOTS of those is over the ceiling.
     */
    UINTN thisSize = strcmp (mode, "mixed") ? size
                     : (UINTN)(MIN_POOL_SIZE << (3 + (i % 3)));
    FREE_POOL_HEADER *Hdr = MakeBlock (thisSize);
    if (Hdr == NULL) { break; }
    AsanSmmQuarantinePush (Hdr, SmmPoolTypeData, IndexFor (thisSize));
    if (mAsanSmmQuarantineBytes > peakBytes) { peakBytes = mAsanSmmQuarantineBytes; }
    if (mAsanSmmQuarantineCount > peakCount) { peakCount = mAsanSmmQuarantineCount; }
    printf ("step %d pushed %lu held %lu bytes %lu\n", i,
            (unsigned long)MemOff ((UINTN)Hdr),
            (unsigned long)mAsanSmmQuarantineCount,
            (unsigned long)mAsanSmmQuarantineBytes);
    for (j = 0; j < MAX_POOL_INDEX; j++) { PrintList ((UINTN)j); }
  }

  printf ("peak bytes %lu count %lu\n", (unsigned long)peakBytes,
          (unsigned long)peakCount);
  printf ("bad %d assertions %d\n", gBadWrites, gAssertions);
  return 0;
}
'''


def build_and_run(pool_src, head_src, ceiling, slots, mode, count, size):
    """Compile the real quarantine against the stub and drive it."""
    try:
        return _build_and_run(pool_src, head_src, ceiling, slots, mode, count, size)
    except (LookupError, ValueError) as problem:
        # A source this check can no longer find its way around has to come back as a
        # failure. Raising here printed a traceback and no [OK]/[FAIL] lines at all,
        # which in CI is indistinguishable from a clean run.
        return None, ['cannot extract from the source: %r' % (problem,)]


def _build_and_run(pool_src, head_src, ceiling, slots, mode, count, size):
    # The anchor matches the macro, not its value. Pinning the 128 here meant a header
    # whose redzone had changed could not be extracted at all, and the check reported
    # "cannot extract" instead of the size assertion that had actually gone wrong.
    decls = region(head_src,
                   r'#define kAsanHeapLeftRedzoneSize\s+\d+',
                   r'extern LIST_ENTRY  mSmmPoolLists\[SmmPoolTypeMax\]\[MAX_POOL_INDEX\];')
    pages = region(head_src, r'typedef struct \{\n  LIST_ENTRY    Link;',
                   r'\} FREE_PAGE_LIST;')
    quarantine = region(pool_src, r'#define POOL_QUARANTINE_SIGNATURE',
                        r'void AsanSignalSolution \(VOID\);')

    # The two bounds come in on the command line so the "turned off" behaviour can be
    # driven without editing the file under test. The values passed are the ones parsed
    # out of Pool.c, except where a case deliberately overrides them.
    quarantine = re.sub(r'^#define\s+ASAN_SMM_QUARANTINE_(SLOTS|MAX_BYTES).*$', '',
                        quarantine, flags=re.M)
    # The forward declaration of AsanSignalSolution would collide with the stub's
    # definition only in signature spelling, so drop it and keep the stub's.
    quarantine = quarantine.replace('void AsanSignalSolution (VOID);', '')

    decls = decls.replace(
        'extern LIST_ENTRY  mSmmPoolLists[SmmPoolTypeMax][MAX_POOL_INDEX];',
        'LIST_ENTRY  mSmmPoolLists[SmmPoolTypeMax][MAX_POOL_INDEX];')

    # Order matters: the stub's types, then the header's structs, then the
    # quarantine's own declarations, then the functions that use them, then the driver.
    unit = '\n'.join([STUB, pages, decls, quarantine,
                      quarantine_functions(pool_src), DRIVER])

    with tempfile.TemporaryDirectory() as work:
        cfile = os.path.join(work, 'unit.c')
        exe = os.path.join(work, 'drive')
        with open(cfile, 'w') as handle:
            handle.write(unit)
        built = subprocess.run(
            ['gcc', '-std=c11', '-Wall', '-Wno-unused-function', '-O1', '-o', exe, cfile,
             '-DASAN_SMM_QUARANTINE_SLOTS=%s' % slots,
             '-DASAN_SMM_QUARANTINE_MAX_BYTES=%s' % ceiling],
            capture_output=True, text=True)
        if built.returncode != 0:
            return None, built.stderr.strip().splitlines()[:6]
        ran = subprocess.run([exe, mode, str(count), str(size)],
                             capture_output=True, text=True)
        return ran.stdout, None


def quarantine_functions(pool_src):
    """The two quarantine functions, lifted whole from Pool.c.

    Signature and body both, so the thing compiled is the thing in the file. Anchored on
    "STATIC\nVOID\n<name> (" because that is how edk2 formats a definition, and the
    parameter list is taken verbatim up to its closing parenthesis.
    """
    out = []
    for name in ('AsanSmmQuarantineRelease', 'AsanSmmQuarantinePush'):
        anchor = 'STATIC\nVOID\n%s (' % name
        start = pool_src.index(anchor)
        params = pool_src[start + len(anchor):pool_src.index(')', start)]
        out.append('STATIC VOID %s (%s)\n%s' % (name, params, body(pool_src, name)))
    return '\n'.join(out)


def parse_steps(out):
    """(pushed offsets, held counts, held bytes, free list snapshots) per step."""
    steps = []
    for block in re.finditer(
            r'step (\d+) pushed (\d+) held (\d+) bytes (\d+)\n((?:list \d+:[^\n]*\n)+)',
            out):
        lists = {}
        for row in re.finditer(r'list (\d+):([^\n]*)', block.group(5)):
            lists[int(row.group(1))] = [int(x) for x in row.group(2).split()]
        steps.append(dict(step=int(block.group(1)), pushed=int(block.group(2)),
                          held=int(block.group(3)), bytes=int(block.group(4)),
                          lists=lists))
    return steps


def main():
    pool = read(POOL_C)
    page = read(PAGE_C)
    head = read(SMM_H)
    if not (pool and page and head):
        print('[FAIL] PiSmmCore sources not readable')
        return 1

    # ------------------------------------------------- the layout, from gcc and ctypes
    #
    # Two independent models of the same structs, and they have to agree. gcc reads the
    # real PiSmmCore.h, so it is what ties these numbers to the source; the ctypes model
    # is written out by hand here, so it is what catches a header change that happens to
    # keep the total size the same. Asserting only the hand-written model is how this
    # check first managed to pass against a header it was no longer describing.
    #
    print('the layout the two poisoned spans depend on')
    redzone = int(re.search(r'#define\s+kAsanHeapLeftRedzoneSize\s+(\d+)', head).group(1))

    class PoolHeader(ctypes.Structure):
        _fields_ = [('Signature', ctypes.c_uint32),
                    ('Available', ctypes.c_uint8),
                    ('Type', ctypes.c_int),
                    ('Size', ctypes.c_uint64),
                    ('OriSize', ctypes.c_uint64),
                    ('AsanRightRZSize', ctypes.c_uint64),
                    ('AsanLeftRZ', ctypes.c_char * redzone)]

    class ListEntry(ctypes.Structure):
        pass

    ListEntry._fields_ = [('ForwardLink', ctypes.POINTER(ListEntry)),
                          ('BackLink', ctypes.POINTER(ListEntry))]

    class FreePoolHeader(ctypes.Structure):
        _fields_ = [('Header', PoolHeader), ('Link', ListEntry)]

    class FreePageList(ctypes.Structure):
        _fields_ = [('Link', ListEntry), ('NumberOfPages', ctypes.c_uint64)]

    hdr_size = ctypes.sizeof(PoolHeader)
    free_hdr = ctypes.sizeof(FreePoolHeader)
    page_node = ctypes.sizeof(FreePageList)
    keep_fields = PoolHeader.Size.offset + ctypes.sizeof(ctypes.c_uint64)

    keep = re.search(r'#define\s+ASAN_SMM_QUARANTINE_KEEP\s+(.*)', pool)
    slots_m = re.search(r'#define\s+ASAN_SMM_QUARANTINE_SLOTS\s+(.+)', pool)
    ceil_m = re.search(r'#define\s+ASAN_SMM_QUARANTINE_MAX_BYTES\s+(.+)', pool)
    check('both bounds and the keep window are declared', None not in
          (keep, slots_m, ceil_m))
    slots_txt = slots_m.group(1).strip() if slots_m else '0'
    ceil_txt = ceil_m.group(1).strip() if ceil_m else '0'

    out, err = build_and_run(pool, head, ceil_txt, slots_txt, 'fifo', 8, 256)
    check('the quarantine compiles out of Pool.c and runs', out is not None,
          '\n         '.join(err or []))
    if out is None:
        print(f'\n{PASSED} passed, {FAILED} failed')
        return 1

    # Defaulting to a distinct negative per key, so a fact the drive did not print
    # compares unequal to everything instead of comparing equal to another absent one.
    # facts.get(a) == facts.get(b) is True when BOTH are missing, which is how two of
    # these assertions passed against a header the extraction could not even parse.
    class Facts(dict):
        def __missing__(self, key):
            return -abs(hash(key)) - 1

    facts = Facts((k, int(v)) for k, v in
                  re.findall(r'^(?:sizeof|offset) ?(\w+) (\d+)$', out, re.M))
    scalars = Facts((k, int(v)) for k, v in
                    re.findall(r'^(keep|slots|ceiling|quarantine_sig|head_sig|tail_sig) '
                               r'(\d+)$', out, re.M))

    check('sizeof (POOL_HEADER) is 168',
          facts['POOL_HEADER'] == 168 and hdr_size == 168,
          f"gcc {facts['POOL_HEADER']}, ctypes {hdr_size}")
    check('sizeof (FREE_POOL_HEADER) is 184',
          facts['FREE_POOL_HEADER'] == 184 and free_hdr == 184,
          f"gcc {facts['FREE_POOL_HEADER']}, ctypes {free_hdr}")
    check('sizeof (FREE_PAGE_LIST) is 24',
          facts['FREE_PAGE_LIST'] == 24 and page_node == 24,
          f"gcc {facts['FREE_PAGE_LIST']}, ctypes {page_node}")
    check('the two models agree on every struct',
          facts['POOL_HEADER'] == hdr_size
          and facts['FREE_POOL_HEADER'] == free_hdr
          and facts['FREE_PAGE_LIST'] == page_node,
          f"gcc {facts['POOL_HEADER']}/{facts['FREE_POOL_HEADER']}/"
          f"{facts['FREE_PAGE_LIST']} against ctypes {hdr_size}/{free_hdr}/"
          f'{page_node}; a header change that keeps a total the same while moving a '
          f'field is exactly what one model alone cannot see')
    check('FREE_POOL_HEADER.Link starts exactly where POOL_HEADER ends',
          facts['Link'] == facts['POOL_HEADER']
          and FreePoolHeader.Link.offset == hdr_size,
          'the premise of the whole quarantine: Link IS the first bytes of the caller'
          "'s buffer, so a block on the free list cannot have those bytes poisoned")
    check('the free page node is smaller than a page',
          0 < facts['FREE_PAGE_LIST'] < facts['EFI_PAGE_SIZE'],
          'the page free path skips sizeof (FREE_PAGE_LIST) bytes, so a node as large '
          'as a page would leave a single-page free with nothing poisoned at all')
    check('the free page node is Link followed by NumberOfPages',
          facts['NumberOfPages'] == facts['LIST_ENTRY']
          and FreePageList.NumberOfPages.offset == ctypes.sizeof(ListEntry),
          'the skip has to cover both, and InternalMergeNodes reads NumberOfPages on a '
          'range that is still free')
    check('the keep window covers Signature, Available, Type and Size and no more',
          scalars['keep'] == keep_fields,
          f"keep is {scalars['keep']}, those four fields end at {keep_fields}; a "
          f'shorter window poisons Size, which the release path reads to give the byte '
          f'ceiling back what the block cost')
    check('the keep window starts the poison at or before the caller buffer',
          0 < scalars['keep'] <= hdr_size,
          f"keep is {scalars['keep']} against a buffer at {hdr_size}: at "
          f'{free_hdr} the poison would start past Link and the quarantine would buy '
          f'delay without buying the coverage that justifies it')
    check('every span in play is 8-aligned',
          scalars['keep'] % 8 == 0 and free_hdr % 8 == 0 and page_node % 8 == 0,
          'the shadow granule is 8 bytes; an unaligned span would be rounded and the '
          'byte-granular model used here would stop describing the real shadow')
    check('the quarantine signature collides with neither pool signature',
          scalars['quarantine_sig'] not in
          (scalars['head_sig'], scalars['tail_sig']),
          'a collision with POOL_HEAD_SIGNATURE would make a double free look like a '
          'live block and the second free would corrupt the allocator')

    steps = parse_steps(out)
    check('the drive produced one record per push', len(steps) == 8,
          f'{len(steps)} records')

    # Nothing is released while the ring is filling: that is the delay the UAF class
    # needs. slots is 64 and 8 blocks were pushed, so the lists must all be empty.
    on_lists = [off for s in steps for row in s['lists'].values() for off in row]
    check('a freed block is not back on a free list while the ring has room',
          not on_lists,
          f'{len(on_lists)} block(s) released early -- the next allocation of that size '
          f'class would hand the freed block straight back and unpoison it')
    check('held count tracks the pushes',
          [s['held'] for s in steps] == list(range(1, 9)),
          f"{[s['held'] for s in steps]}")
    check('held bytes track the pushes',
          [s['bytes'] for s in steps] == [256 * n for n in range(1, 9)],
          f"{[s['bytes'] for s in steps]}")

    # Overflow the count bound: 70 pushes against 64 slots must release the first 6, in
    # push order.
    # 256, not 64: POOL_OVERHEAD is 184, so SmmInternalAllocatePool cannot land a
    # request in a bucket below 256 and a 64-byte block is not a thing this allocator
    # produces. Driving the quarantine with one put FREE_POOL_HEADER's Link past the end
    # of the block.
    out2, err2 = build_and_run(pool, head, ceil_txt, slots_txt, 'fifo', 70, 256)
    steps2 = parse_steps(out2 or '')
    released, seen = [], set()
    for s in steps2:
        for off in sorted(o for row in s['lists'].values() for o in row):
            if off not in seen:
                seen.add(off)
                released.append(off)
    pushed = [s['pushed'] for s in steps2]
    check('the smallest block the bucket path can produce still fits its header',
          256 >= facts['FREE_POOL_HEADER'],
          'the drive above would otherwise be measuring a block layout the SMM '
          'allocator never creates')
    check('the count bound evicts once it is reached',
          len(released) == 70 - scalars['slots'],
          f"{len(released)} released from 70 pushes against "
          f"{scalars['slots']} slots")
    check('eviction is FIFO: the oldest block is the one released',
          released == pushed[:len(released)],
          f'released {released[:6]} against pushed {pushed[:6]} -- a LIFO quarantine '
          f'releases the block most likely to still be pointed at')
    peak = re.search(r'peak bytes (\d+) count (\d+)', out2 or '')
    check('the held count never exceeds the slot bound',
          peak is not None and int(peak.group(2)) <= scalars['slots'],
          f'peak {peak.group(2) if peak else "?"} against {scalars.get("slots")}')
    held_now = steps2[-1]['held'] if steps2 else -1
    check('every block pushed is either held or released, exactly once',
          len(released) == len(set(released))
          and set(released) <= set(pushed)
          and len(released) + held_now == len(pushed),
          f'{len(released)} released + {held_now} held against {len(pushed)} pushed. '
          f'Stated as conservation on purpose: "none released twice" is satisfied by an '
          f'empty list, so a quarantine that dropped every block would have passed it, '
          f'and a dropped block is SMRAM the allocator never sees again')
    check('nothing writes to a block while it is poisoned',
          (re.search(r'bad (\d+)', out2 or '') or [None, '?'])[1] == '0',
          'the release path has to unpoison the header prefix BEFORE InsertHeadList, '
          'or the core reports a use-after-free against its own list insertion')

    # Overflow the BYTE bound, with the largest block the bucket path can produce. The
    # two bounds only disagree up there: 64 slots of MAX_POOL_SIZE is 128KB against a
    # 64KB ceiling, so this run is the only one in which the byte bound is doing any
    # work. Driven with mixed sizes instead -- which this check did first -- the slot
    # count binds first and removing the byte bound entirely still passes.
    ceiling = scalars['ceiling']
    out3, err3 = build_and_run(pool, head, ceil_txt, slots_txt, 'fifo', 120, 2048)
    peak3 = re.search(r'peak bytes (\d+) count (\d+)', out3 or '')
    check('the byte bound holds for MAX_POOL_SIZE blocks',
          peak3 is not None and int(peak3.group(1)) <= ceiling,
          f'peak {peak3.group(1) if peak3 else "?"} against a ceiling of {ceiling}; '
          f'{scalars.get("slots", 0)} slots of 2048 bytes would be '
          f'{scalars.get("slots", 0) * 2048} without it')
    check('both bounds hold at once at that size',
          peak3 is not None and int(peak3.group(2)) <= scalars['slots']
          and int(peak3.group(1)) <= ceiling,
          'stated together on purpose: at MAX_POOL_SIZE the byte bound is the stricter '
          'of the two, so the slot bound alone is unfalsifiable here and only the pair '
          'says anything')

    # And a mixed-size sequence, for the conservation property under eviction churn.
    out3b, err3b = build_and_run(pool, head, ceil_txt, slots_txt, 'mixed', 120, 0)
    peak3b = re.search(r'peak bytes (\d+) count (\d+)', out3b or '')
    check('the byte bound holds under mixed sizes too',
          peak3b is not None and int(peak3b.group(1)) <= ceiling,
          f'peak {peak3b.group(1) if peak3b else "?"} against a ceiling of {ceiling}')
    check('the byte bound is the one that binds, not the slot count',
          ceiling < scalars['slots'] * 2048,
          f'{ceiling} against {scalars.get("slots", 0)} slots of MAX_POOL_SIZE: a '
          f'ceiling above that would never be reached and the real high-water mark '
          f'would be the slot count times the largest block')
    check('mixed sizes still lose no block',
          (re.search(r'bad (\d+)', out3b or '') or [None, '?'])[1] == '0')

    # The ceiling is the knob that turns the quarantine off.
    out4, err4 = build_and_run(pool, head, '0', slots_txt, 'fifo', 6, 256)
    steps4 = parse_steps(out4 or '')
    check('a ceiling of 0 releases every block on the spot',
          steps4 and all(s['held'] == 0 for s in steps4)
          and all(s['bytes'] == 0 for s in steps4),
          'the documented one-line revert has to restore the pre-quarantine behaviour, '
          'not merely shrink the ring')
    # 256 bytes is MIN_POOL_SIZE << 2, so every block belongs on index 2 and every
    # other list must be empty. Pooling all the lists together -- which this check did
    # first -- passes even when the release path puts everything on index 0.
    want = (256 // 64).bit_length() - 1
    occupied = {i: row for i, row in (steps4[-1]['lists'].items() if steps4 else [])
                if row}
    check('and every block released that way is on the free list for its size class',
          list(occupied) == [want]
          and sorted(occupied[want]) == sorted(s['pushed'] for s in steps4),
          f'occupied lists {sorted(occupied)}, expected only {want}; released onto the '
          f'wrong size class the allocator hands out a block of the wrong size, and the '
          f'POOL_TAIL check in SmmInternalFreePool then rejects a valid free')

    # A block larger than the whole ceiling must not be queued.
    out5, err5 = build_and_run(pool, head, '128', slots_txt, 'fifo', 3, 256)
    steps5 = parse_steps(out5 or '')
    check('a block bigger than the ceiling is released rather than queued',
          steps5 and all(s['held'] == 0 for s in steps5),
          'queueing it would hold more than the ceiling allows; refusing to hold it is '
          'a lost detection, never a lost block')

    # The two spans, which is where the detection actually comes from.
    out6, err6 = build_and_run(pool, head, ceil_txt, slots_txt, 'span', 1, 256)
    spans = re.findall(r'(held|released) span (\d+) (\d+) (\d+)', out6 or '')
    got = {k: (int(a), int(b), int(c)) for k, a, b, c in spans}
    check('a held block is poisoned from the keep window to the end of the block',
          got.get('held', (0, 0, 0))[0] == scalars['keep']
          and got['held'][1] == 255,
          f"held span {got.get('held')} -- it has to start before "
          f"{free_hdr} for a use-after-free at Buffer[0] to be caught, and reach the "
          f"tail so an overflow into the slack is caught too")
    check('the held poison is the free magic, not a redzone magic',
          got.get('held', (0, 0, 0))[2] == 0xfd,
          f"got 0x{got.get('held', (0, 0, 0))[2]:02x}; a use-after-free reported as a "
          f'buffer overflow sends triage to the wrong defect')
    check('a released block is poisoned from sizeof (FREE_POOL_HEADER) instead',
          got.get('released', (0, 0, 0))[0] == free_hdr,
          f"released span {got.get('released')} -- once a block is on the free list its "
          f'Link has to be readable again, which is exactly the coverage the quarantine '
          f'buys while it holds it')
    check('a released block is still described to the end',
          got.get('released', (0, 0, 0))[1] == 255,
          'dropping the poison entirely on release would make the pre-quarantine '
          'behaviour worse, not equal')

    # ---------------------------------------------------- the bound, against real TSEG
    print('\nthe memory the quarantine can hold hostage')
    tseg = re.search(r'gUefiOvmfPkgTokenSpaceGuid\.PcdQ35TsegMbytes\|(\d+)', read(DSC))
    check('the platform TSEG size is readable', tseg is not None)
    tseg_bytes = int(tseg.group(1)) * 1024 * 1024 if tseg else 0
    check('the worst case is a small fraction of the smallest TSEG built',
          ceiling + 2048 <= tseg_bytes // 64,
          f'{ceiling} + one MAX_POOL_SIZE block against {tseg_bytes} bytes of TSEG; the '
          f'reference is the DSC\'s PcdQ35TsegMbytes, not the ceiling itself')

    # ------------------------------------------------------------------ Page.c ordering
    print('\nwhere the page poison sits, which is the part that is easy to get backwards')
    free_fn = body(page, 'SmmInternalFreePagesEx')
    poison_at = free_fn.find('PoisonPool (PoisonStart')
    check('SmmInternalFreePagesEx poisons the range', poison_at >= 0)
    last_reject = max(m.start() for m in
                      re.finditer(r'return EFI_INVALID_PARAMETER;', free_fn))
    check('the poison is after every validation return',
          poison_at > last_reject,
          'poisoning a range the function then REJECTS poisons live memory, and every '
          'later access to it reports -- the one way this hook can do real harm')
    # Matched as STATEMENTS, at code indentation. A plain find() lands in the comment
    # above the poison -- which names both of these in order to explain itself -- and the
    # check then compares the poison against its own rationale and always passes.
    def statement(text, pattern):
        found = re.search(r'^ {2,4}%s' % pattern, text, re.M)
        return found.start() if found else -1

    insert_at = statement(free_fn, r'InsertTailList \(Node, &Pages->Link\);')
    check('the poison is before the range is linked into mSmmMemoryMap',
          0 < poison_at < insert_at,
          f'poison at {poison_at}, InsertTailList at {insert_at} -- the node head write '
          f'and the merges read the first bytes of the range')
    convert_at = statement(free_fn, r'ConvertSmmMemoryMapEntry \(EfiConventionalMemory')
    check('the poison is before ConvertSmmMemoryMapEntry',
          0 < poison_at < convert_at,
          'ConvertSmmMemoryMapEntry can call AllocateMemoryMapEntry, which allocates a '
          'page OUT OF THIS RANGE; poisoning afterwards would poison a live allocation '
          'and every read of those MEMORY_MAP descriptors would report. This is where '
          'the DXE core does the opposite, and copying it would be wrong here')
    check('the poison starts one free list node into the range',
          'PoisonStart = (UINTN)Memory + sizeof (FREE_PAGE_LIST);' in free_fn,
          'a start of Memory itself poisons the node the free list is about to use; a '
          'start further in leaves addressable bytes nothing describes')
    check('the poison runs to the end of the page extent',
          'PoisonEnd   = (UINTN)Memory + EFI_PAGES_TO_SIZE (NumberOfPages);' in free_fn)
    check('the page poison uses the free magic',
          'kAsanHeapFreeMagic' in free_fn[poison_at - 200:poison_at + 200]
          if poison_at >= 0 else False)

    alloc_fn = body(page, 'InternalAllocPagesOnOneNode')
    unpoison_node = alloc_fn.find('UnpoisonPool ((UINTN)Node')
    node_write = alloc_fn.find('Node->NumberOfPages =')
    check('the split node head is unpoisoned before it is written',
          0 <= unpoison_node < node_write,
          'the remainder of a split node is inside a poisoned free range, so building a '
          'new node head there is a write to poisoned memory on every allocation that '
          'leaves a remainder -- the core reporting against itself, repeatedly')
    unpoison_alloc = alloc_fn.find('UnpoisonPages (')
    check('the allocated range is unpoisoned before it is returned',
          0 <= unpoison_alloc < alloc_fn.rindex('return'),
          'the range is being handed to a caller; nothing else in SMM unpoisons it, '
          'because there is no SMM equivalent of CoreAddRange')
    check('the unpoison is after the list surgery, not before it',
          unpoison_alloc > alloc_fn.find('RemoveEntryList'),
          'unpoisoning first would be harmless but would hide the split-node write '
          'above, and the next change to this function would re-break it silently')
    callers = len(re.findall(r'InternalAllocPagesOnOneNode \(', read(PAGE_C))) - 1
    guard_callers = len(re.findall(
        r'InternalAllocPagesOnOneNode \(',
        read(os.path.join(SMM, 'HeapGuard.c'))))
    check('every page allocation really does funnel through that one function',
          callers == 2 and guard_callers == 1,
          f'{callers} call sites in Page.c (InternalAllocMaxAddress and '
          f'InternalAllocAddress) and {guard_callers} in HeapGuard.c '
          f'(InternalAllocMaxAddressWithGuard); a fourth allocation path would be '
          f'unpoisoned, and its first write would land on the free poison and report')

    # ------------------------------------------------------------------- Pool.c wiring
    print('\nhow the pool free path is wired to the quarantine')
    by_index = body(pool, 'InternalFreePoolByIndex')
    check('the free path no longer inserts into mSmmPoolLists itself',
          'InsertHeadList' not in by_index,
          'an insert left here would put the block on the list AND in the ring, and the '
          'next allocation would hand out a block the quarantine still owns')
    sig_at = by_index.find('Header.Signature = POOL_QUARANTINE_SIGNATURE')
    tail_at = by_index.find('PoolTail->Size                = 0;')
    push_at = by_index.find('AsanSmmQuarantinePush (')
    check('the block is marked before it is handed to the quarantine',
          0 <= sig_at < push_at,
          'the signature is what the double-free check reads')
    check('the tail is scrubbed before the quarantine poisons it',
          0 <= tail_at < push_at,
          'the quarantine poison covers POOL_TAIL, so a scrub afterwards would be a '
          'write to poisoned memory')

    free_pool = body(pool, 'SmmInternalFreePool')
    report_at = free_pool.find('bug_descr=double-free')
    assert_at = free_pool.find('ASSERT (FreePoolHdr->Header.Signature == POOL_HEAD_SIGNATURE)')
    return_at = free_pool.find('return EFI_INVALID_PARAMETER;')
    tail_read = free_pool.find('PoolTail->Signature == POOL_TAIL_SIGNATURE')
    check('a double free is reported rather than returned in silence',
          report_at >= 0 and 'AsanSignalSolution ()' in free_pool,
          'upstream turns the second free into EFI_INVALID_PARAMETER and says nothing')
    check('the report returns before the ASSERT',
          0 <= report_at < assert_at and 0 <= return_at < assert_at,
          'PcdDebugPropertyMask is 0x2F in this build, so ASSERT takes the deadloop '
          'arm, and a CpuDeadLoop inside an SMI hangs the guest -- the report would '
          'reach the wire and every later iteration of the campaign would be lost')
    check('the report returns before the POOL_TAIL reads',
          0 <= report_at < tail_read,
          'the quarantine poisons the tail, so reading PoolTail->Signature on a '
          'quarantined block would report a use-after-free on top of the double free '
          'and the bug count would double')

    # ------------------------------------------------------- the SMM positive control
    print('\nthe SMM positive control')
    inf = read(os.path.join(BENCH, 'SanBenchSmm.inf'))
    src = read(os.path.join(BENCH, 'SanBenchSmm.c'))
    dsc, fdf = read(DSC), read(FDF)
    check('the control is an SMM driver',
          'MODULE_TYPE              = DXE_SMM_DRIVER' in inf,
          'a DXE driver cannot allocate from the SMM pool, so it cannot exercise any of '
          'this')
    check('it is gated in the DSC and in the FDF',
          re.search(r'!ifdef SAN_BENCH\b[^!]*SanBenchSmm\.inf', dsc, re.S) is not None
          and re.search(r'!ifdef \$\(SAN_BENCH\)\s*\nINF  MdeModulePkg/Universal/'
                        r'SanBenchSmm/SanBenchSmm\.inf', fdf) is not None,
          'the DSC alone builds it without putting it in the image, and the FDF alone '
          'does not build it at all -- both gates have to be there and both have to be '
          'conditional, or a module that is wrong on purpose ships')
    check('it is built with -mllvm -asan-stack=0 like every other SMM arm',
          re.search(r'SanBenchSmm\.inf \{\s*\n\s*<BuildOptions>\s*\n\s*'
                    r'\*_CLANGSAN_X64_SAN_FLAGS == \$\(ASAN_SAN_FLAGS\) '
                    r'-mllvm -asan-stack=0', dsc) is not None,
          'clang writes frame redzones inline, and this module\'s stack is the SMM '
          'stack, in TSEG')
    check('it does not link MemoryAllocationLib',
          'MemoryAllocationLib' not in re.sub(r'#.*', '', inf),
          'that library\'s FreePool ends in ASSERT_EFI_ERROR, and the double-free case '
          'makes a free fail on purpose: the ASSERT would deadloop the guest before the '
          'report could be collected')
    check('the faults are direct loads and stores, not CopyMem',
          'Buffer[Index] = Request->Data[Index];' in src
          and 'mSanBenchSmmSink = Buffer[0];' in src,
          'a fault inside CopyMem reports against the memory wrapper, which is the '
          'result already in hand; the missing result is a report that names this driver')
    check('the use-after-free case reads offset 0',
          'mSanBenchSmmSink = Buffer[0];' in src,
          'offset 0 is the byte only the quarantine can describe, so this case fails if '
          'the quarantine is turned off -- which is what makes it a test of it')
    check('the page case reads past the free list node',
          re.search(r'\)\[64\];', src) is not None,
          'the first sizeof (FREE_PAGE_LIST) bytes of a freed range stay addressable by '
          'construction, so a read at offset 0 would measure that hole, not the hook')
    check('the sink is volatile',
          'STATIC volatile UINT8  mSanBenchSmmSink' in src,
          'a load whose result is discarded is a load the compiler deletes, and a '
          'deleted load is a case that reports nothing while looking like it ran')
    check('nothing is exercised at the entry point',
          'SmiHandlerRegister' in body(src, 'SanBenchSmmEntry')
          and not re.search(r'SanBenchSmm(Control|PoolOverflow|PoolUseAfterFree|'
                            r'DoubleFree|PageUseAfterFree) \(',
                            body(src, 'SanBenchSmmEntry')),
          'a control that fires during DXE poisons every campaign\'s baseline, and the '
          'double-free case would be doing it from inside the allocator the rest of the '
          'boot depends on')
    check('the entry point does not ASSERT on a failed registration',
          'ASSERT' not in body(src, 'SanBenchSmmEntry'),
          'this runs inside the SMM core\'s dispatch, where an ASSERT deadloops')
    check('the handler validates the caller buffer before it copies it',
          body(src, 'SanBenchSmmHandler').find('SmmIsBufferOutsideSmmValid')
          < body(src, 'SanBenchSmmHandler').find('CopyMem (&Request'),
          'a control reachable through an unintended path scores the unintended path')
    check('the narration names no class',
          not re.search(r'SerialOutput \("[^"]*(double-free|use-after-free|overflow)',
                        src),
          'the scoreboard matches class names on this wire, so a line saying "running '
          'double-free" would score itself as a detection')
    check('there is a negative control',
          'SAN_BENCH_SMM_CMD_CONTROL' in src,
          'a board with no control cannot tell a sanitizer that detects faults from one '
          'that reports on everything it is shown')
    check('the request payload is a fixed array, not a trailing Data[1]',
          'UINT8     Data[SAN_BENCH_SMM_DATA_BYTES];' in src,
          'a flexible tail gets sizeof () == 1 in the harness generator, and every '
          'command arm then reads its arguments out of leftovers')

    print(f'\n{PASSED} passed, {FAILED} failed')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
