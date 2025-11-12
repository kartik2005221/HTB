#!/usr/bin/env python3
"""
secure_decoder.py
Usage:
  python secure_decoder.py
Then paste the base64 token when prompted, or pass via --token "..."
Behavior:
  - prints question
  - prompts for answer
  - if answer == "hint" it prints question + hint and continues
  - if guess matches the stored hash it prints "Correct" and exits
  - if wrong it prints question and continues asking
"""
import argparse
import base64
import json
import hashlib
import sys


def decode_b64_token(token: str):
    try:
        raw = base64.b64decode(token)
        payload = json.loads(raw.decode('utf-8'))
        return payload
    except Exception as e:
        raise ValueError("Invalid token or not valid base64/json.") from e


def verify_guess(guess: str, salt_hex: str, expected_hash_hex: str, iterations: int) -> bool:
    guess_norm = guess.strip().lower()
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac('sha256', guess_norm.encode('utf-8'), salt, iterations)
    return dk.hex() == expected_hash_hex


def main():
    parser = argparse.ArgumentParser(description="Decode token and quiz user without revealing the answer.")
    parser.add_argument('--token', '-t', help='base64 token produced by encoder', default=None)
    args = parser.parse_args()

    if not args.token:
        args.token = input("Paste the base64 token: ").strip()

    try:
        payload = decode_b64_token(args.token)
    except ValueError as e:
        print("Error decoding token:", e)
        sys.exit(1)

    q = payload.get('q', '')
    hint = payload.get('hint', '')
    salt = payload.get('salt', '')
    expected_hash = payload.get('hash', '')
    iterations = int(payload.get('iter', 200000))

    if not (q and salt and expected_hash):
        print("Token missing required fields.")
        sys.exit(1)

    print("\nQuestion:")
    print(q)
    while True:
        ans = input("\nYour answer (type 'hint' for hint): ").strip()
        if ans.lower() == "hint":
            if hint:
                print("\nQuestion:", q)
                print("Hint:", hint)
            else:
                print("\nNo hint available. Question:", q)
            continue

        if verify_guess(ans, salt, expected_hash, iterations):
            print("\nCorrect. Exiting.")
            sys.exit(0)
        else:
            # wrong: show only question again
            print("\nWrong. Try again.")
            print("Question:")
            print(q)


if __name__ == "__main__":
    main()