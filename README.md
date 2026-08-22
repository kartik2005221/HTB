# HTB — Answer Verifier

A client-side question/answer verifier: encode questions plus secret answers into
shareable tokens, then let anyone *prove* they know the answers without the tokens
revealing them. No server, no database, no build step — one static HTML file.

**Live site:** <https://htbk.netlify.app/> · direct links: [#encode](https://htbk.netlify.app/#encode) / [#decode](https://htbk.netlify.app/#decode)

> **Screenshot:** placeholder — drop a capture of the app at `docs/screenshot.png` and it
> will render here: `![Answer Verifier screenshot](docs/screenshot.png)`

## Built for making tokens in bulk

- **Batch mode** — switch the Encoder to *Batch*, add rows (or **bulk-paste lines** like
  `question | answer | hint | label`), and hash dozens of questions in one go. Live
  progress while hashing ("Hashing 7/20…").
- **One batch token or many** — combine everything into a single *batch token* (the
  Decoder turns it into a guided quiz with progress bar, skip, hints and a final score),
  or emit N independent classic tokens (one per line) with copy-all / save-all.
- **Send it over** — after generating: native **Share sheet**, or one-click
  **WhatsApp / Telegram / Email** deep links with the token pre-filled, or plain copy /
  save. A webpage can't silently post to chat apps (that needs a backend); deep links are
  the zero-backend equivalent.
- **Sticky modes** — `#encode` and `#decode` URL routes are bookmarkable/shareable, and
  the app remembers your last mode even without the hash.
- **Paste buttons** in every input field; **draft memory** (opt-in under Options)
  restores your half-finished batch after a refresh — leave it off on shared machines,
  since drafts store answer text locally.
- **JSON export** — `Save .json` emits machine-readable payloads (v1 object, v2 batch, or
  an array of items incl. plaintext-free hashes) for CLI pipelines such as `htb-cli`.

## Token formats

### Classic token (v1 — unchanged, fully backward compatible)

| Field  | Contents                                            |
|--------|-----------------------------------------------------|
| `label`| optional display name (ignored by older decoders)   |
| `q`    | question text (plaintext)                           |
| `hint` | optional hint (plaintext)                           |
| `salt` | fresh random 16-byte hex salt, unique per token     |
| `hash` | PBKDF2-SHA256(answer, salt, iter), 256-bit derived key |
| `iter` | PBKDF2 iteration count used for this token          |

Compact JSON, base64-encoded. The plaintext answer is **never** included.

### Batch token (v2)

`{"v":2,"title":"…","items":[{label,q,hint,salt,hash,iter}, …]}` — same per-item fields as
v1, each with its own salt/hash. Requires this web decoder (the Python `decoder.py`
predates v2 and handles classic tokens only).

## Security notes & honest limitations

- Hashing runs in the browser via Web Crypto: PBKDF2-HMAC-SHA256, 256-bit key,
  **600,000 iterations** by default (current OWASP guidance for this primitive).
- Every item embeds its own `iter`, and decoders honor it — tokens issued at the old
  200k default still verify unchanged everywhere.
- Client-side scheme: anyone holding a token can brute-force **short or guessable**
  answers offline. Treat tokens as quiz gating, not cryptographic secrecy — use
  long/uncommon answers; move verification server-side if you need real secrecy.

## Optional CLI tools

`encoder.py` and `decoder.py` predate the web app and implement the **classic token
format** — useful for scripting or fully offline workflows:

```bash
python3 encoder.py --question "What is 2+2?" --answer "4" --hint "simple math"
python3 decoder.py --token "<paste token here>"
```

Tokens generated in the browser (single mode) verify with these tools and vice-versa.

## Development

Single static file, zero dependencies:

```bash
python3 -m http.server 8000    # then open http://localhost:8000
```

Deployed on Netlify straight from this repository — pushes to `main` go live
automatically, and PR branches get preview deploys.

## License

GPL-3.0 — see [LICENSE](LICENSE).
