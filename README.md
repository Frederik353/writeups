# CTF Writeups

Hugo site for CTF writeups, built with the [Blowfish](https://blowfish.page/) theme and deployed to GitHub Pages.

## Setup

```bash
git clone --recurse-submodules <repo-url>
npm run setup   # install pre-commit hook
```

## Development

```bash
npm run dev     # hugo server with drafts enabled
```

## Early Access

Password-protected writeups that are encrypted in the repo and on the site until their release date. Useful for sharing writeups with teammates during a CTF before making them public.

### How it works

1. Posts with a future `releaseDate` are AES-256-GCM encrypted before committing
2. The encrypted file is what lives in the repo and what Hugo builds — no plaintext leaks
3. On the site, visitors see a password form; entering the team password decrypts client-side
4. A daily CI cron job rebuilds the site — once past the `releaseDate`, the post is decrypted and published normally
5. Links with `?p=<password>` auto-decrypt without needing to type the password

### Initial setup

**1. Create a `.env` file** (gitignored, never committed):

```
EARLY_ACCESS_PASSWORD=your-team-password-here
```

**2. Install the pre-commit hook:**

```bash
npm run setup
```

**3. Set the GitHub repo secret:**

Go to repo Settings > Secrets and variables > Actions > New repository secret:
- Name: `EARLY_ACCESS_PASSWORD`
- Value: same password as in `.env`

### Writing an early-access post

Add `releaseDate` to the frontmatter with the date it should become public:

```yaml
---
title: "Challenge Name"
summary: "Brief description."
date: 2026-02-08
topics: ["web"]
ctfs: ["some-ctf"]
tags: ["tag1", "tag2"]
releaseDate: "2026-02-15"
difficulty: medium
draft: false
---

Your writeup content here...
```

### Encrypting before commit

The pre-commit hook auto-encrypts if `.env` is set up. You can also encrypt manually:

```bash
npm run encrypt
```

This replaces the file contents in-place: the body, tags, topics, ctfs, and summary are all moved into the encrypted blob. The file in the repo will only show the title, date, difficulty, and the encrypted shortcode.

### Decrypting

```bash
npm run decrypt       # only past-dated posts (what CI runs before hugo build)
npm run decrypt-all   # everything, regardless of date (for local testing/recovery)
```

`decrypt` restores the original body, tags, topics, ctfs, and summary for posts past their `releaseDate`. `decrypt-all` does the same but ignores the date — useful if you encrypted locally and want your plaintext back.

### Sharing with teammates

Send them the direct link with the password in the URL:

```
https://frederik353.github.io/writeups/ctfs/some-ctf/challenge/?p=your-team-password-here
```

### After a fresh clone

```bash
npm run setup                                    # install pre-commit hook
echo "EARLY_ACCESS_PASSWORD=yourpass" > .env     # set password
```

### Safety nets

- **Pre-commit hook with password**: auto-encrypts and stages any unencrypted early-access posts
- **Pre-commit hook without password**: blocks the commit if unencrypted early-access posts are staged
- **Running encrypt twice**: safe, already-encrypted files are skipped
- **`npm run dev`**: works without `.env`, renders plaintext locally for editing
