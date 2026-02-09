---
title: "Blogler"
date: 2026-02-08
tags: ["yaml", "path-traversal", "aliasing", "lfi"]
topics: ["web"]
summary: "Early access — password required"
releaseDate: "2026-02-09"
ctfs: ["lactf-26"]
difficulty: medium
draft: false
---

> They call me the blogler.

---

A blogging platform built with Flask. Users register, write blog posts in Markdown, and edit their blog's YAML configuration through a Monaco editor. The flag sits at `/flag` on the server.

The app has explicit path traversal protection. It checks for `../` in filenames, blocks absolute paths, and verifies that resolved paths stay inside the blogs directory. Breaking through requires finding a way to mutate a filename *after* validation has already passed.

---

## Application overview

The app has two main features: uploading blog posts (Markdown files saved to disk) and editing a YAML config that controls how your blog is served.

When you visit `/blog/<username>`, the server reads each blog entry's `name` field and opens that file from the blogs directory:

```python
@app.get("/blog/<string:username>")
def serve_blog(username):
    if username not in users:
        return "username does not exist", 404
    blogs = [
        {"title": blog["title"], "content": mistune.html((blog_path / blog["name"]).read_text())}
        for blog in users[username]["blogs"]
    ]
    return render_template("blog.html", blogs=blogs, name=users[username]["user"]["name"])
```

If we can control `blog["name"]` to be something like `../../flag`, the server will read `/flag` instead of a file inside `blogs/`. But there's validation standing in the way.

---

## The validation

When you submit a new YAML config, `validate_conf` checks every blog entry's `name` field:

```python
def validate_conf(old_cfg: dict, uploaded_conf: str) -> dict | str:
    try:
        conf = yaml.safe_load(uploaded_conf)

        for i, blog in enumerate(conf["blogs"]):
            if not isinstance(blog.get("title"), str):
                return f"please provide a 'title' to the {i+1}th blog"

            # no lfi
            file_name = blog["name"]
            assert isinstance(file_name, str)
            file_path = (blog_path / file_name).resolve()
            if "../" in file_name or file_name.startswith("/") or not file_path.is_relative_to(blog_path):
                return f"file path {file_name!r} is a hacking attempt. this incident will be reported"

        if not isinstance(conf.get("user"), dict):
            conf["user"] = dict()

        conf["user"]["name"] = display_name(conf["user"].get("name", old_cfg["user"]["name"]))
        conf["user"]["password"] = conf["user"].get("password", old_cfg["user"]["password"])
        if not isinstance(conf["user"]["password"], str):
            return "provide a valid password bro"
        return conf
    except Exception as e:
        return f"exception - {e}"
```

Three checks block direct path traversal on each blog's `name`:

1. `"../" in file_name` rejects any filename containing the literal substring `../`
2. `file_name.startswith("/")` rejects absolute paths
3. `not file_path.is_relative_to(blog_path)` resolves the path and checks it stays under `blogs/`

These are solid. There's no way to pass a string like `../../flag` through this gauntlet. But notice what happens *after* the loop: there's a call to `display_name()` that modifies `conf["user"]["name"]`. That's the next piece of the puzzle.

---

## The display_name function

```python
def display_name(username: str) -> str:
    return "".join(p.capitalize() for p in username.split("_"))
```

This is meant to create a display-friendly version of a username. It splits on underscores, capitalizes each part, and joins them back together. For example:

| Input | Split parts | After capitalize | Joined |
|-------|-------------|------------------|--------|
| `john_doe` | `["john", "doe"]` | `["John", "Doe"]` | `JohnDoe` |
| `hello_world` | `["hello", "world"]` | `["Hello", "World"]` | `HelloWorld` |

Seems harmless. But look at what happens with carefully chosen inputs:

| Input | Split parts | After capitalize | Joined |
|-------|-------------|------------------|--------|
| `._._` | `[".", ".", ""]` | `[".", ".", ""]` | `..` |

The string `._._` becomes `..` after processing. The `capitalize()` call on `.` returns `.` (there's nothing to capitalize), and the underscores disappear.

This means `display_name` can produce path traversal sequences from inputs that don't contain `../`.

---

## YAML anchors and aliases

Here's the core trick. YAML supports **anchors** (`&name`) and **aliases** (`*name`), which create shared references to the same object. This is a feature for avoiding repetition in config files:

```yaml
defaults: &defaults
  timeout: 30
  retries: 3

server_a:
  <<: *defaults
  host: a.example.com

server_b:
  <<: *defaults
  host: b.example.com
```

The critical detail: anchors and aliases don't create copies. They create **references to the same object in memory**. In Python terms, after `yaml.safe_load`:

```python
data["defaults"] is data["server_a"]  # same dict object
```

This means mutating one mutates the other. And that's the key to bypassing validation.

---

## Putting it together

The validation loop checks `conf["blogs"][0]["name"]`, and then later the code does:

```python
conf["user"]["name"] = display_name(conf["user"].get("name", ...))
```

If `conf["user"]` and `conf["blogs"][0]` are **the same dict object** (via a YAML alias), then writing to `conf["user"]["name"]` also overwrites `conf["blogs"][0]["name"]`.

The attack config:

```yaml
blogs:
  - &ref
    title: "flag"
    name: "._._/._._/flag"
user: *ref
```

Here's the step-by-step execution:

1. **YAML parsing**: `yaml.safe_load` creates one dict `{"title": "flag", "name": "._._/._._/flag"}`. Both `blogs[0]` and `user` point to this same dict.

2. **Validation loop**: The code checks `blogs[0]["name"]` which is `"._._/._._/flag"`. This passes all three checks:
   - `"../" in "._._/._._/flag"` → `False` (no `../` substring)
   - `"._._/._._/flag".startswith("/")` → `False`
   - The resolved path stays under `blog_path` (since there's no actual `..` yet)

3. **The mutation**: After the loop, the code runs:
   ```python
   conf["user"]["name"] = display_name(conf["user"].get("name", ...))
   ```
   `conf["user"]` is the *same dict* as `blogs[0]`, so `conf["user"].get("name")` returns `"._._/._._/flag"`. Then `display_name` processes it:
   ```python
   display_name("._._/._._/flag")
   # split("_") → [".", ".", "/.", ".", "/flag"]
   # capitalize each → [".", ".", "/.", ".", "/flag"]
   # join → "../../flag"
   ```
   Why does `capitalize()` leave everything unchanged? It uppercases only the first character and lowercases the rest. The first character in each part is either `.` or `/`, and non-alphabetic characters have no uppercase form, so they pass through. The remaining letters (`flag`) are already lowercase, so lowercasing them is a no-op.

   The concatenation builds up `../../flag` piece by piece:

4. **This overwrites `blogs[0]["name"]`** to `"../../flag"`. Validation already passed, so it's too late to catch it.

5. **Reading the blog**: When someone visits `/blog/<username>`, the server does:
   ```python
   (blog_path / blog["name"]).read_text()
   ```
   Which resolves `blogs/../../flag` → `/flag`, and we get the flag.

---

## Exploit

1. **Register** an account with any username and password

2. **Submit the malicious YAML config** via the config editor:
   ```yaml
   blogs:
     - &ref
       title: "flag"
       name: "._._/._._/flag"
   user: *ref
   ```

3. **Visit** `/blog/<your_username>`. The server reads `/flag` and renders it as your blog post

You can do all of this through the web UI. Paste the YAML into the config editor on the left side, hit "Update Config", then click the "blog" link to view your page.

---

## Why the fix is hard

The root cause isn't just the `display_name` function or the YAML aliases individually, it's the combination. The code validates a data structure, then mutates part of it, not realizing that YAML aliasing has linked that part to something already validated.

Defenses that would prevent this:

- **Deep-copy the parsed YAML** before processing, breaking shared references
- **Validate after all mutations**, not before
- **Don't mutate the config in-place**, build a new dict for the validated output

---

## Flag

```
lactf{7m_g0nn4_bl0g_y0u}
```

