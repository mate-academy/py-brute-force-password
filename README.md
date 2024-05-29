# Brute Force Passwords

**Please note:** read [the guideline](https://github.com/mate-academy/py-task-guideline/blob/main/README.md)
before starting.

Imagine yourself a hacker. You've successfully SQL-injected some website's DB and got hashed passwords of 10 users.
```python
PASSWORDS_TO_BRUTE_FORCE = [
    "b4061a4bcfe1a2cbf78286f3fab2fb578266d1bd16c414c650c5ac04dfc696e1",
    "cf0b0cfc90d8b4be14e00114827494ed5522e9aa1c7e6960515b58626cad0b44",
    "e34efeb4b9538a949655b788dcb517f4a82e997e9e95271ecd392ac073fe216d",
    "c15f56a2a392c950524f499093b78266427d21291b7d7f9d94a09b4e41d65628",
    "4cd1a028a60f85a1b94f918adb7fb528d7429111c52bb2aa2874ed054a5584dd",
    "40900aa1d900bee58178ae4a738c6952cb7b3467ce9fde0c3efa30a3bde1b5e2",
    "5e6bc66ee1d2af7eb3aad546e9c0f79ab4b4ffb04a1bc425a80e6a4b0f055c2e",
    "1273682fa19625ccedbe2de2817ba54dbb7894b7cefb08578826efad492f51c9",
    "7e8f0ada0a03cbee48a0883d549967647b3fca6efeb0a149242f19e4b68d53d6",
    "e5f3ff26aa8075ce7513552a9af1882b4fbc2a47a3525000f6eb887ab9622207",
]
```
Of course, your first thought was to look through rainbow tables and test your luck. 
But you visited that website and understand that its password field accepts only numeric symbols from 0 to 9. 
There is a limitation — the password length always must be 8 symbols (extremely weak security — you must agree). 
Also, it seems that this website doesn't use any additional security while hashing their passwords (like salting).

So, you as a hacker already got a point, that you can easily brute force all possible variants of passwords
and check the corresponding hashes using this `sha256_hash_str` function:
```python
import sha256


def sha256_hash_str(to_hash: str) -> str:
    return sha256(to_hash.encode("utf-8")).hexdigest()
```

Your task is to find these 10 passwords (8-numeric symbols strings) and print them to the console.


Notes:
- you should find `10` passwords (not `9`) — check it;
- you should use setup to speed up this brute forcing as much as possible;
- attach the screenshot of your script results (the console) to the PR.

# Results
![results](passwords.png)
