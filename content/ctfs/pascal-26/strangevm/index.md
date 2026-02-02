---
title: "StrangeVM"
summary: "Reverse a simple VM to understand its character transformation."
date: 2026-01-31
topics: ["rev"]
ctfs: ["pascal-26"]
tags: ["vm", "bytecode"]
difficulty: medium
draft: false
---

> A stranger once built a VM and hid the Forbidden Key, can you uncover it?

---

We get a VM binary and a bytecode file `code.pascal`. Running it asks for input and either accepts or rejects.

## Finding the VM loop

Opening the binary reveals a simple fetch-decode-execute loop:

```c
while (1) {
    opcode = bytecode[pc];
    pc++;

    switch (opcode) {
        case 0:  // HALT
            return;

        case 1:  // ADD
            addr = *(uint32_t*)&bytecode[pc];
            imm = bytecode[pc + 4];
            pc += 5;
            mem[addr] = (mem[addr] + imm) & 0xFF;
            break;

        case 2:  // SUB
            addr = *(uint32_t*)&bytecode[pc];
            imm = bytecode[pc + 4];
            pc += 5;
            mem[addr] = (mem[addr] - imm) & 0xFF;
            break;

        case 3:  // MOD
            addr = *(uint32_t*)&bytecode[pc];
            imm = bytecode[pc + 4];
            pc += 5;
            mem[addr] = mem[addr] % imm;
            break;

        case 4:  // MOV
            addr = *(uint32_t*)&bytecode[pc];
            imm = bytecode[pc + 4];
            pc += 5;
            mem[addr] = imm;
            break;

        case 5:  // IN (read char)
            addr = *(uint32_t*)&bytecode[pc];
            pc += 4;
            mem[addr] = getchar();
            break;

        case 6:  // JZ (jump if zero)
            addr = *(uint32_t*)&bytecode[pc];
            offset = (int8_t)bytecode[pc + 4];  // signed!
            pc += 5;
            if (mem[addr] == 0)
                pc += offset;
            break;
    }
}
```

| Opcode | Mnemonic | Encoding | Description |
|--------|----------|----------|-------------|
| 0x00 | HALT | `00` | Stop execution |
| 0x01 | ADD | `01 <addr:4> <imm:1>` | `mem[addr] += imm` |
| 0x02 | SUB | `02 <addr:4> <imm:1>` | `mem[addr] -= imm` |
| 0x03 | MOD | `03 <addr:4> <imm:1>` | `mem[addr] %= imm` |
| 0x04 | MOV | `04 <addr:4> <imm:1>` | `mem[addr] = imm` |
| 0x05 | IN | `05 <addr:4>` | `mem[addr] = getchar()` |
| 0x06 | JZ | `06 <addr:4> <off:1>` | Jump if `mem[addr] == 0` |

---

## Writing a disassembler

```python
import struct

def disassemble(bytecode):
    pc = 0
    while pc < len(bytecode):
        opcode = bytecode[pc]

        if opcode == 0:
            print(f"{pc:04x}: HALT")
            break

        elif opcode in [1, 2, 3, 4]:
            names = {1: "ADD", 2: "SUB", 3: "MOD", 4: "MOV"}
            addr = struct.unpack('<I', bytecode[pc+1:pc+5])[0]
            imm = bytecode[pc+5]
            print(f"{pc:04x}: {names[opcode]} mem[{addr}], {imm}")
            pc += 6

        elif opcode == 5:
            addr = struct.unpack('<I', bytecode[pc+1:pc+5])[0]
            print(f"{pc:04x}: IN mem[{addr}]")
            pc += 5

        elif opcode == 6:
            addr = struct.unpack('<I', bytecode[pc+1:pc+5])[0]
            offset = bytecode[pc+5]
            if offset > 127:
                offset -= 256  # sign extend
            target = pc + 6 + offset
            print(f"{pc:04x}: JZ mem[{addr}], {offset:+d}  -> {target:04x}")
            pc += 6

with open("code.pascal", "rb") as f:
    disassemble(f.read())
```

---

## Analyzing the bytecode

The disassembled output shows a repeating pattern for each input character:

```
0000: IN mem[0]           ; read char 0
0005: MOV mem[1], 0       ; temp = 0
000b: MOD mem[1], 2       ; temp = 0 % 2 = 0
0011: JZ mem[1], +12      ; if temp == 0, jump to ADD
0017: SUB mem[0], 0       ; (skipped) char -= 0
001d: JZ mem[1023], +6    ; unconditional jump (mem[1023] is always 0)
0023: ADD mem[0], 0       ; char += 0

0029: IN mem[1]           ; read char 1
002e: MOV mem[2], 1       ; temp = 1
0034: MOD mem[2], 2       ; temp = 1 % 2 = 1
003a: JZ mem[2], +12      ; if temp == 0 (false), continue
0040: SUB mem[1], 1       ; char -= 1
0046: JZ mem[1023], +6    ; unconditional jump past ADD
004c: ADD mem[1], 1       ; (skipped)

0052: IN mem[2]           ; read char 2
0057: MOV mem[3], 2       ; temp = 2
005d: MOD mem[3], 2       ; temp = 2 % 2 = 0
0063: JZ mem[3], +12      ; if temp == 0, jump to ADD
0069: SUB mem[2], 2       ; (skipped)
006f: JZ mem[1023], +6    ; unconditional jump
0075: ADD mem[2], 2       ; char += 2
...
```

The pattern:
- Read character into `mem[i]`
- Check if index `i` is odd or even via `i % 2`
- If **even**: `mem[i] += i`
- If **odd**: `mem[i] -= i`

The `JZ mem[1023]` is a clever unconditional jump. Since `mem[1023]` is never written, it stays 0, so the jump always triggers.

---

## Finding the target values

After the bytecode finishes, main compares the result:

```c
if (strcmp(mem, flag))
    puts("Execution failed. The code did not match the expected flag.");
else
    puts("Congratulations! You have successfully executed the code.");
```

Where `flag` points to:

```c
char flag[0x29] = "VLu\\8m9Xl(>W{_?TD[q \x82\x1b\x8bP\x80F~\x15\x8aW}ZPT\x81Q\x8c\x0c\x94D";
```

The target bytes are right there in the binary.

---

## Solving

Reverse the transformation:

```python
target = bytes([
    0x56, 0x4C, 0x75, 0x5C, 0x38, 0x6D, 0x39, 0x58, 0x6C, 0x28,
    0x3E, 0x57, 0x7B, 0x5F, 0x3F, 0x54, 0x44, 0x5B, 0x71, 0x20,
    0x82, 0x1B, 0x8B, 0x50, 0x80, 0x46, 0x7E, 0x15, 0x8A, 0x57,
    0x7D, 0x5A, 0x50, 0x54, 0x81, 0x51, 0x8C, 0x0C, 0x94, 0x44
])

flag = bytearray()
for i, b in enumerate(target):
    if i % 2 == 0:
        flag.append((b - i) & 0xFF)  # reverse of +i
    else:
        flag.append((b + i) & 0xFF)  # reverse of -i

print(flag.decode())
```

---

## Flag

```
pascalCTF{VMs_4r3_d14bol1c4l_3n0ugh_d0nt_y0u_th1nk}
```
