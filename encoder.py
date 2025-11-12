#!/usr/bin/env python3
"""
secure_encoder.py
Usage:
  python secure_encoder.py --question "What is 2+2?" --answer "4" --hint "simple math"
Or run without args to get interactive prompts.
Output: a single base64 string you can copy/share.
"""
import argparse
import json
import base64
import secrets
import hashlib


def make_payload(question: str, answer: str, hint: str, iterations: int = 200_000):
    # Normalize answer (lowercase + strip)
    normalized = answer.strip().lower()
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac('sha256', normalized.encode('utf-8'), salt, iterations)
    payload = {
        "q": question,
        "hint": hint or "",
        "salt": salt.hex(),
        "hash": dk.hex(),
        "iter": iterations,
    }
    return payload


def encode_payload_to_b64(payload: dict) -> str:
    j = json.dumps(payload, separators=(',', ':'))  # compact
    return base64.b64encode(j.encode('utf-8')).decode('ascii')


def main():
    parser = argparse.ArgumentParser(
        description="Create a base64-encoded question token (salted hash, no plaintext answer).")
    parser.add_argument('--question', '-q', help='Question text', default=None)
    parser.add_argument('--answer', '-a', help='Correct answer (will be lowercased)', default=None)
    # Change default to None so we can detect when the user didn't pass --hint at all
    parser.add_argument('--hint', '-i', help='Optional hint', default=None)
    parser.add_argument('--iter', '-n', type=int, help='PBKDF2 iterations (default 200000)', default=200_000)
    args = parser.parse_args()

    # Detect interactive mode: if question or answer wasn't provided on the command line
    interactive = (args.question is None or args.answer is None)

    if args.question is None:
        args.question = input("Question: ").strip()
    if args.answer is None:
        args.answer = input("Correct answer (will be lowercased and hashed): ").strip()

    # If the user didn't pass --hint, prompt only in interactive mode. If not interactive, set to empty string.
    if args.hint is None and interactive:
        args.hint = input("Hint (press Enter to skip): ").strip()
    elif args.hint is None:
        # Non-interactive run and no hint provided: keep hint blank
        args.hint = ""

    payload = make_payload(args.question, args.answer, args.hint, args.iter)
    token = encode_payload_to_b64(payload)
    print("\n----- TOKEN (share this) -----\n")
    print(token)
    print("\n-------------------------------\n")
    print("Note: This token does not contain the plaintext answer. Use the decoder to check guesses.")


if __name__ == "__main__":
    main()