---
title: "Curly Crab"
summary: "Reversing Rust serde deserialization to recover a JSON schema."
date: 2026-01-31
topics: ["rev"]
ctfs: ["pascal-26"]
tags: ["rust", "serde", "json"]
difficulty: medium
draft: false
---

> A crab stole my json schema...

---

The challenge is a Rust binary that reads JSON from stdin and outputs either a crab emoji (success) or a sad face (failure):

```
$ echo '{"test": 1}' | ./curly-crab
Give me a JSONy flag!
😔

$ echo '???' | ./curly-crab
Give me a JSONy flag!
🦀
```

We need to figure out what JSON structure makes the crab happy.

---

## Why Rust reversing is painful

Coming from C reversing, Rust binaries have some extra headaches:

1. **Monomorphization**: Generic functions get duplicated for each concrete type. A simple `Vec<T>` becomes separate code for `Vec<i32>`, `Vec<String>`, etc. The binary bloats with near-identical functions.

2. **Aggressive inlining**: Small functions get inlined everywhere. What would be a clean `call` instruction in C becomes a wall of duplicated code.

3. **Standard library bloat**: Even simple operations pull in tons of library code for error handling, `Result` unwrapping, iterator machinery, etc. A "hello world" in Rust is 300KB+.

4. **Name mangling on steroids**: Function names become monstrosities like `_ZN4core3ptr85drop_in_place$LT$alloc..vec..Vec$LT$u8$GT$$GT$17h3b2c...`

5. **Ownership/borrowing artifacts**: The decompiled code is littered with `drop_in_place` calls, reference counting, and move semantics that obscure the actual logic.

The saving grace here: Rust's `serde` library generates predictable patterns for JSON deserialization.

---

## The reality: what you're actually looking at

Before showing the cleaned-up version, here's what Rust binaries actually look like in a decompiler. This is the real `main` function:

```c
int64_t curly_crab::main::h71b58f7aacf87a44()
{
    std::io::stdio::_print::h526c462071e58c18(&data_7a8b[0x91], 0x2d);
    std::io::stdio::stdin::h11deceff11981680();
    void* var_30 = &std::io::stdio::stdin::INSTANCE::h067a27bca4e07de8;
    int32_t* rax;
    rax = std::io::stdio::Stdin::lock::h1079d43173269675(&var_30);
    // ... 50 more lines of Result unwrapping and panic handling ...

    serde_json::de::from_trait::h1f3bcad3bd3177ac(&var_80, &var_d8);

    if (var_80 != -0x8000000000000000) {
        std::io::stdio::_print::h526c462071e58c18(&data_7b32, 0xb);  // 🦀
    } else {
        std::io::stdio::_eprint::hbab4723ed852db00(&data_7b37, 0xb); // 😔
    }
    // ... 30 more lines of cleanup ...
}
```

The useful bits are buried in noise. Here's how to navigate it.

---

## Practical tips for reversing Rust/serde

### 1. Use function names as landmarks

Even mangled, the names tell you what's happening:
- `serde_json::de::from_trait` → JSON parsing entry point
- `deserialize_struct` → struct field parsing
- `deserialize_bool`, `deserialize_string` → primitive types
- `drop_in_place`, `__rust_dealloc` → cleanup (ignore these)

### 2. Field matching follows a pattern

Serde checks field length first, then compares bytes as integers:

```c
if (rax_3 == 6)  // length == 6
{
    if (!((*(r15_1 + 4) ^ 0x7962) | (*r15_1 ^ 0x62617263)))
        // matched!
}
```

The XOR-and-OR pattern `(a ^ expected1) | (b ^ expected2)` equals zero only if both match.

### 3. Search for concatenated field names

Serde embeds field names in error messages. Search for strings like:
```
"I_crabbycr4bsstruct Crab with 3 elements"
```

This tells you the struct has fields `I_`, `crabby`, `cr4bs` and is called `Crab`.

### 4. Ignore the noise

Most of the code is:
- `Result`/`Option` checking (`-0x8000000000000000` is the `Err`/`None` discriminant)
- Memory cleanup (`__rust_dealloc`, `drop_in_place`)
- Whitespace skipping (the `TEST_BITQ(0x100002600, ...)` pattern)
- Panic handling

Focus on the actual comparisons and function calls.

---

## Identifying serde in the binary

Signs to look for:

1. **String references**: Search for `"expected struct"`, `"missing field"`, `"invalid type"`.

2. **Function name fragments**: Look for `serde`, `deserialize`, `Visitor`, `SeqAccess`.

3. **Concatenated field names**: Serde error messages contain field lists like `"I_crabbycr4bs"`.

Searching strings for "struct" reveals the struct names:
```
"expected struct TopLevel"
"expected struct Crab"
"expected struct Crabby"
```

This tells us the hierarchy. Now we need the field names.

---

## How serde deserialization works

Serde is Rust's serialization framework. When you write:

```rust
#[derive(Deserialize)]
struct Crab {
    I_: bool,
    crabby: Crabby,
    cr4bs: i32,
}
```

The `#[derive(Deserialize)]` macro generates a `deserialize` function that:

1. Expects either `{` (object) or `[` (tuple/array format)
2. Reads field names as strings
3. Matches them against expected field names
4. Recursively deserializes nested types
5. Returns an error if anything doesn't match

The key insight: **field name matching uses integer comparisons on the raw bytes**. Instead of string comparison, serde compares chunks of the field name as integers for speed.

---

## Finding the entry point

Starting from `main`, trace the calls:

```
curly_crab::main::h71b58f7aacf87a44
  │
  └── serde_json::de::from_trait::h1f3bcad3bd3177ac
        │
        └── deserialize_struct::he3c85fe01abee1f1  ← top-level struct
```

The `from_trait` function is just a wrapper. The real work happens in `deserialize_struct`.

---

## What you're actually looking for

Here's a snippet from the real `deserialize_struct` for the top-level struct. I've annotated the important parts:

```c
// Inside deserialize_struct - the actual decompiled mess
// ... skip past the '{' check and 100 lines of setup ...

// THIS IS THE GOLD - field length switch
if (var_148 == 3)  // ← field length check
{
    // Compare bytes: (byte[2] ^ 'F') | (bytes[0:2] ^ 0x5443)
    if ((*(r13_1 + 2) ^ 0x46) | (*r13_1 ^ 0x5443))
        goto label_2c1ab;  // unknown field

    // Matched "CTF"! Now deserialize the value...
}
else if (var_148 == 4)
{
    if (*r13_1 != 0x62617263)  // ← compare as 4-byte int
        goto label_2c1ab;

    // Matched "crab"! Call nested struct deserializer
    _$LT$RF$mut$u20$serde_j...deserialize_struct::hb5c049ded4c5ad6a(&var_158, r15_1);
}
else if (var_148 == 6)
{
    // Two comparisons: 4 bytes + 2 bytes
    if ((*(r13_1 + 4) ^ 0x6c61) | (*r13_1 ^ 0x63736170))
        goto label_2c1ab;

    // Matched "pascal"! Deserialize string
    _$LT$RF$mut$u20$serde_j...deserialize_string::h4c289388cf84ac5d(&var_d8, r15_1);
}
```

The pattern to look for:
1. Length check in an if/switch
2. Byte comparisons using XOR: `(a ^ expected) | (b ^ expected)` (equals 0 if match)
3. Call to another `deserialize_*` function for the value

---

## Mapping the struct hierarchy

Follow the `deserialize_struct` calls to find nested structs. Each one has the same pattern of length checks and hex comparisons.

### Top-level struct

From the code above:
- `CTF` (len=3, `0x5443` + `0x46`) → integer
- `crab` (len=4, `0x62617263`) → nested struct via `deserialize_struct::hb5c049ded4c5ad6a`
- `pascal` (len=6, `0x63736170` + `0x6c61`) → string

### Nested "crab" struct

Following `deserialize_struct::hb5c049ded4c5ad6a`, same pattern:

```c
if (rax_3 == 2)  // "I_"
    if (*r15_1 != 0x5f49) goto unknown;
    // deserialize_bool

else if (rax_3 == 5)  // "cr4bs"
    if ((*(r15_1 + 4) ^ 0x73) | (*r15_1 ^ 0x62347263)) goto unknown;
    // deserialize integer

else if (rax_3 == 6)  // "crabby"
    if ((*(r15_1 + 4) ^ 0x7962) | (*r15_1 ^ 0x62617263)) goto unknown;
    // deserialize_struct::h39718c3ed97ba090 (another nested struct!)
```

Fields: `I_` (bool), `cr4bs` (int), `crabby` (struct)

### Inner "crabby" struct

Following the next `deserialize_struct`:
- `l0v3_` (len=5, `0x7633306c` + `0x5f`) → array
- `r3vv1ng_` (len=8, `0x5f676e3176763372`) → integer

### Visual hierarchy

```
Top-level
├── CTF: integer
├── crab: struct
│   ├── I_: boolean
│   ├── crabby: struct
│   │   ├── r3vv1ng_: integer
│   │   └── l0v3_: array
│   └── cr4bs: integer
└── pascal: string
```

---

## Constructing valid JSON

Based on the schema:

```json
{
  "CTF": 1,
  "crab": {
    "I_": true,
    "crabby": {
      "r3vv1ng_": 1,
      "l0v3_": []
    },
    "cr4bs": 1
  },
  "pascal": "test"
}
```

Testing:

```
$ echo '{"CTF":1,"crab":{"I_":true,"crabby":{"r3vv1ng_":1,"l0v3_":[]},"cr4bs":1},"pascal":"x"}' | ./curly-crab
Give me a JSONy flag!
🦀
```

---

## Extracting the flag

Some people submitted massive JSON documents that happened to work because they included the required fields somewhere. The key is understanding what's actually being validated: just the field names and types, nothing more.

The field names spell out the flag: `I_`, `l0v3_`, `r3vv1ng_`, `cr4bs`.

---

## Flag

```
pascalCTF{I_l0v3_r3vv1ng_cr4bs}
```
