# PW Crack 3
Solver: rusperres

## Description
Can you crack the password to get the flag?
Download the password checker here and you'll need the encrypted flag and the hash in the same directory too.
There are 7 potential passwords with 1 being correct. You can find these by examining the password checker script.

## Links
Password checker - https://artifacts.picoctf.net/c/18/level3.py

Flag - https://artifacts.picoctf.net/c/18/level3.flag.txt.enc

Hash - https://artifacts.picoctf.net/c/18/level3.hash.bin

## Solutions
### Solution 1: Bruteforce
1. Open `level3.py`: `cat level3.py`
```python
import hashlib

### THIS FUNCTION WILL NOT HELP YOU FIND THE FLAG --LT ########################
def str_xor(secret, key):
    #extend key to secret length
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c,new_key_c) in zip(secret,new_key)])
###############################################################################

flag_enc = open('level3.flag.txt.enc', 'rb').read()
correct_pw_hash = open('level3.hash.bin', 'rb').read()


def hash_pw(pw_str):
    pw_bytes = bytearray()
    pw_bytes.extend(pw_str.encode())
    m = hashlib.md5()
    m.update(pw_bytes)
    return m.digest()


def level_3_pw_check():
    user_pw = input("Please enter correct password for flag: ")
    user_pw_hash = hash_pw(user_pw)

    if( user_pw_hash == correct_pw_hash ):
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), user_pw)
        print(decryption)
        return
    print("That password is incorrect")



level_3_pw_check()


# The strings below are 7 possibilities for the correct password.
#   (Only 1 is correct)
pos_pw_list = ["8799", "d3ab", "1ea2", "acaf", "2295", "a9de", "6f3d"]
```
2. Analyze the code, notice the last line:
```python
pos_pw_list = ["8799", "d3ab", "1ea2", "acaf", "2295", "a9de", "6f3d"]
```
3. Run `level3.py` and try each password.

<pre>
jairus@LAPTOP-L6ESL8BI:~/picoCTF/pw_crack3$ python3 level3.py

Please enter correct password for flag: 2295

Welcome back... your flag, user:

picoCTF{m45h_fl1ng1ng_6f98a49f}</pre>

### Solution 2: Hash cracking
1. In `level3.py`, analyze the flow of the program, first find which function is first called to find the entry point:
``` python
level_3_pw_check()
```
This is the only function called outside other functions, which means this is the entry point.
2. Analyze the flow inside `level_3_pw_check()`:
```python
def level_3_pw_check():
    user_pw = input("Please enter correct password for flag: ")
    user_pw_hash = hash_pw(user_pw)

    if( user_pw_hash == correct_pw_hash ):
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), user_pw)
        print(decryption)
        return
    print("That password is incorrect")
```
This means that the flow is `user input` --> `hash user input`:
```python
user_pw = input("Please enter correct password for flag: ")
user_pw_hash = hash_pw(user_pw)
```
Next, it checks if the hashed input is equal to the hashed password
```python
if( user_pw_hash == correct_pw_hash ):
```
This means that the password is in `correct_pw_hash`
3. Identify the hashing algorithm used, notice:
```python
def hash_pw(pw_str):
    pw_bytes = bytearray()
    pw_bytes.extend(pw_str.encode())
    m = hashlib.md5()
    m.update(pw_bytes)
    return m.digest()
```
MD5 is used
4. Get the hashed password from `correct_pw_hash` by:
```python
print(correct_pw_hash)
```
This will give a binary string, but MD5 is hex, so convert it to hex first
```python
print(correct_pw_hash.hex())
```
Now run:
<pre>
jairus@LAPTOP-L6ESL8BI:~/picoCTF/pw_crack3$ python3 pass.py
16026d60ff9b54410b3435b403afd226
</pre>

5. Paste hash on crackstation.net:
<img width="1338" height="508" alt="image" src="https://github.com/user-attachments/assets/bcd79d4f-8f89-457f-b63d-50362d06e91f" />
Password is: 2295

6. Run `python3 level3.py` again and answer with the password:
<pre>
  jairus@LAPTOP-L6ESL8BI:~/picoCTF/pw_crack3$ python3 level3.py
Please enter correct password for flag: 2295

Welcome back... your flag, user:

  picoCTF{m45h_fl1ng1ng_6f98a49f}
</pre>
