---
title: "Zazastore"
summary: "NaN comparison bypass in a Node.js shopping cart."
date: 2026-01-31
topics: ["web"]
ctfs: ["pascal-26"]
tags: ["javascript", "type-confusion", "NaN"]
difficulty: easy
draft: false
---

> We dont take any responsibility in any damage that our product may cause to the user's health

---

A shop where you can buy various "Za" products. You start with $100 balance, but the flag item "RealZa" costs $1000.

## The vulnerability

Looking at the checkout logic in `server.js`:

```javascript
const prices = { "FakeZa": 1, "ElectricZa": 65, "CartoonZa": 35, "RealZa": 1000 };

app.post('/checkout', (req, res) => {
    const cart = req.session.cart;

    let total = 0;
    for (const product in cart) {
        total += prices[product] * cart[product];
    }

    if (total > req.session.balance) {
        res.json({ "success": true, "balance": "Insufficient Balance" });
    } else {
        // Purchase succeeds, items added to inventory
        // ...
    }
});
```

The problem: the cart can contain any product name, not just valid ones. If `product` doesn't exist in `prices`:

```javascript
prices["RealZa"] * 1      // 1000
prices["anything"] * 1    // undefined * 1 = NaN
1000 + NaN                // NaN
NaN > 100                 // false
```

Since `NaN > 100` is `false`, the balance check passes.

---

## Exploit

Using Burp Suite:

1. **Login** - POST to `/login` with any username/password

2. **Add RealZa to cart** - POST to `/add-cart`:
   ```json
   {"product":"RealZa","quantity":1}
   ```

3. **Add a fake product** - POST to `/add-cart`:
   ```json
   {"product":"anything","quantity":1}
   ```

4. **Checkout** - POST to `/checkout`

5. **Get flag** - Visit `/inventory`

The fake product causes `prices["anything"]` to be `undefined`, making the total `NaN`. The check `NaN > 100` returns `false`, so checkout succeeds despite not having enough balance.

---

## Flag

```
pascalCTF{w3_l1v3_f0r_th3_z4z4}
```
