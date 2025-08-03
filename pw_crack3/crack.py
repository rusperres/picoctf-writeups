import hashlib

# Try guessing the password
for pw in ["password", "123456", "km81088", "ctf123", "admin", "letmein"]:
    h = hashlib.md5(pw.encode()).digest()
    if h.hex() == "16026d60ff9b54410b3435b403afd226":
        print(f"[+] Match found: {pw}")
