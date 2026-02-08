// decrypt.js — Client-side AES-256-GCM decryption for early-access posts
(function () {
  "use strict";

  var PBKDF2_ITERATIONS = 600000;
  var STORAGE_KEY = "ea-password";

  document.querySelectorAll(".ea-container").forEach(function (container) {
    var encryptedB64, expectedHash;

    // Read data from JSON element (preferred) or data attributes (fallback)
    var dataEl = container.querySelector(".ea-data");
    if (dataEl) {
      var parsed = JSON.parse(dataEl.textContent);
      encryptedB64 = parsed.encrypted;
      expectedHash = parsed.hash;
    } else {
      encryptedB64 = container.dataset.encrypted;
      expectedHash = container.dataset.hash;
    }

    // Move form to body so it escapes all parent CSS constraints (backdrop-filter etc.)
    var form = container.querySelector(".ea-form");
    var overlay = document.createElement("div");
    overlay.className = "ea-overlay";
    overlay.style.cssText = "position:fixed;inset:0;display:flex;align-items:center;justify-content:center;z-index:9999;padding:1rem;pointer-events:none";
    form.style.pointerEvents = "auto";
    overlay.appendChild(form);
    document.body.appendChild(overlay);

    var input = overlay.querySelector(".ea-password-input");
    var btn = overlay.querySelector(".ea-submit-btn");
    var error = overlay.querySelector(".ea-error");
    var contentDiv = container.querySelector(".ea-content");

    function unlock(password) {
      if (!password) return;

      error.hidden = true;
      btn.disabled = true;
      btn.textContent = "Decrypting\u2026";

      // SHA-256 pre-check for instant wrong-password feedback
      crypto.subtle
        .digest("SHA-256", new TextEncoder().encode(password))
        .then(function (hashBuf) {
          var hashHex = Array.from(new Uint8Array(hashBuf))
            .map(function (b) {
              return b.toString(16).padStart(2, "0");
            })
            .join("");

          if (hashHex !== expectedHash) {
            showError();
            return;
          }

          return decrypt(password, encryptedB64);
        })
        .then(function (plaintext) {
          if (!plaintext) return; // hash check failed, already handled

          // Remember password for this session
          try { sessionStorage.setItem(STORAGE_KEY, password); } catch (e) {}

          // Strip metadata comments (<!--meta:field:value-->) before rendering
          var cleaned = plaintext.replace(/<!--meta:\w+:.+-->\n?/g, "");

          // Render markdown
          var html = marked.parse(cleaned);
          contentDiv.innerHTML = html;
          contentDiv.classList.add("prose", "dark:prose-invert", "max-w-none");

          // Syntax highlighting
          contentDiv.querySelectorAll("pre code").forEach(function (block) {
            hljs.highlightElement(block);
          });

          // Build ToC from headings and inject into page
          buildToc(contentDiv);

          // Remove overlay, show content in original location
          overlay.remove();
          contentDiv.hidden = false;
        })
        .catch(function (err) {
          console.error("[early-access] Decryption error:", err);
          showError();
        });
    }

    function showError() {
      error.hidden = false;
      btn.disabled = false;
      btn.textContent = "Unlock";
      input.value = "";
      input.focus();
    }

    btn.addEventListener("click", function () {
      unlock(input.value);
    });
    input.addEventListener("keydown", function (e) {
      if (e.key === "Enter") unlock(input.value);
    });

    // Try password sources: URL ?p= → sessionStorage → show form
    var urlParams = new URLSearchParams(window.location.search);
    var urlPassword = urlParams.get("p");
    if (urlPassword) {
      history.replaceState(null, "", window.location.pathname + window.location.hash);
      unlock(urlPassword);
    } else {
      try {
        var saved = sessionStorage.getItem(STORAGE_KEY);
        if (saved) unlock(saved);
      } catch (e) {}
    }
  });

  function buildToc(contentEl) {
    var headings = contentEl.querySelectorAll("h2, h3");
    if (headings.length < 2) return;

    // Add ids to headings
    headings.forEach(function (h) {
      if (!h.id) {
        h.id = h.textContent.trim().toLowerCase()
          .replace(/[^\w\s-]/g, "").replace(/\s+/g, "-");
      }
    });

    // Build nested list
    var tocHtml = '<nav id="TableOfContents"><ul>';
    var inSub = false;
    headings.forEach(function (h) {
      if (h.tagName === "H3") {
        if (!inSub) { tocHtml += "<ul>"; inSub = true; }
        tocHtml += '<li><a href="#' + h.id + '">' + h.textContent + "</a></li>";
      } else {
        if (inSub) { tocHtml += "</ul>"; inSub = false; }
        tocHtml += '<li><a href="#' + h.id + '">' + h.textContent + "</a></li>";
      }
    });
    if (inSub) tocHtml += "</ul>";
    tocHtml += "</ul></nav>";

    // Find the article section and inject ToC sidebar
    var section = contentEl.closest("section");
    if (!section) return;
    var tocWrapper = document.createElement("div");
    tocWrapper.className = "order-first lg:ml-auto px-0 lg:order-last lg:ps-8 lg:max-w-2xs";
    tocWrapper.innerHTML =
      '<div class="toc ps-5 print:hidden lg:sticky lg:top-10">' +
      '<details open id="TOCView" class="toc-right mt-0 overflow-y-auto rounded-lg -ms-5 ps-5 pe-2 hidden lg:block">' +
      '<div class="min-w-[220px] py-2 border-dotted border-s-1 -ms-5 ps-5 dark:border-neutral-600">' +
      tocHtml + "</div></details></div>";
    section.insertBefore(tocWrapper, section.firstChild);
  }

  function decrypt(password, b64) {
    var raw = Uint8Array.from(atob(b64), function (c) {
      return c.charCodeAt(0);
    });
    var salt = raw.slice(0, 16);
    var iv = raw.slice(16, 28);
    var ciphertext = raw.slice(28);

    return crypto.subtle
      .importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, [
        "deriveKey",
      ])
      .then(function (baseKey) {
        return crypto.subtle.deriveKey(
          { name: "PBKDF2", salt: salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
          baseKey,
          { name: "AES-GCM", length: 256 },
          false,
          ["decrypt"]
        );
      })
      .then(function (key) {
        return crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, ciphertext);
      })
      .then(function (buf) {
        return new TextDecoder().decode(buf);
      });
  }
})();
