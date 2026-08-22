# HTB — Answer Verifier

A client-side question/answer verifier: encode a question plus a secret answer into a
shareable token, then let anyone *prove* they know the answer without the token revealing
it. No server, no database, no build step — one static HTML file.

**Live site:** <https://htbk.netlify.app/>

> **Screenshot:** placeholder — drop a capture of the app at `docs/screenshot.png` and it
> will render here: `![Answer Verifier screenshot](docs/screenshot.png)`

## How it works

1. **Encoder tab** — enter a question, the correct answer (normalized to lowercase), and an
   optional hint. Click **Generate Token**.
2. You get a single base64 string (compact JSON by default) containing:

   | Field  | Contents                                            |
   |--------|-----------------------------------------------------|
   | `q`    | question text (plaintext)                           |
   | `hint` | optional hint (plaintext)                           |
   | `salt` | fresh random 16-byte hex salt, unique per token     |
   | `hash` | PBKDF2-SHA256(answer, salt, iter), 256-bit derived key |
   | `iter` | PBKDF2 iteration count used for this token          |

   The plaintext answer is **never** included in the token.
3. Share the token with your audience. The **Decoder tab** (or the Python decoder) shows
   the question and checks typed answers against the salted hash — correct answers get a
   success confirmation; wrong answers never leak how close they were.

## Security notes & honest limitations

- Hashing runs in the browser via Web Crypto: PBKDF2-HMAC-SHA256, 256-bit key,
  **600,000 iterations** by default (current OWASP guidance for this primitive; raised
  from 200,000 in this modernization).
- Every token embeds its own `iter`, and decoders honor it — so tokens issued before the
  iteration bump still verify unchanged, and old decoder versions verify new tokens too.
- This is a client-side scheme: anyone holding a token holds salt + hash + iteration
  count and can brute-force **short or guessable** answers offline. Treat tokens as quiz
  gating, not cryptographic secrecy — use long/uncommon answers, and move verification
  server-side if you need real secrecy.

## Optional CLI tools

`encoder.py` and `decoder.py` predate the web app and implement the **same token format**
— useful for scripting or fully offline workflows:

```bash
python3 encoder.py --question "What is 2+2?" --answer "4" --hint "simple math"
python3 decoder.py --token "<paste token here>"
```

They are not used by the deployed site (which is pure client-side JS), but tokens
generated in the browser verify with these tools and vice-versa.

## Development

Single static file, zero dependencies:

```bash
python3 -m http.server 8000    # then open http://localhost:8000
```

The site is deployed on Netlify straight from this repository — pushes to `main` go live
automatically, and PR branches get preview deploys.

## License

GPL-3.0 — see [LICENSE](LICENSE).
