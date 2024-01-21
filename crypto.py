import requests

# Global values
base = "http://companyurl/{}"
email = "my-email"
auth_token = ""

# Used for authentication
def token(email):
    global auth_token
    if not auth_token:
        url = base.format("api-token-auth/")
        resp = requests.post(url, data={"email":email})
        auth_token = {"Authorization":"JWT " + resp.json()['token']}
        resp.close()
    return auth_token

# Fetch the challenge and hint for level n
def fetch(n):
    url = base.format("challenge/{}/".format(n))
    resp = requests.get(url, headers=token(email))
    resp.close()
    if resp.status_code != 200:
        raise Exception(resp.json()['detail'])
    return resp.json()

# Submit a guess for level n
def solve(n, guess):
    url = base.format("challenge/{}/".format(n))
    data = {"guess": guess}
    resp = requests.post(url, headers=token(email), data=data)
    resp.close()
    if resp.status_code != 200:
        raise Exception(resp.json()['detail'])
    return resp.json()


hashes = {}

#################################################################################

# Fetch level 0
level = 0
data = fetch(level)

# Level 0 is a freebie and gives you the password
level0guess = data['challenge']
h = solve(level, level0guess)

# If we obtained a hash add it to the dict
if 'hash' in h: hashes[level] = h['hash']


#################################################################################

# Fetch level 1
level = 1
data = fetch(level)
print(data)

with open('1_txt.txt', 'w') as f:
    f.write(data['challenge'])

# try all combination to break the Caesar cipher
# 23 is the key
def caesar_cipher_decrypt(ciphertext):
    decrypted_text = ""

    key = 23
    for char in ciphertext:
        if char.isalpha():
            shifted = ord(char) - key
            if char.islower():
                if shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted < ord('A'):
                    shifted += 26

            decrypted_text += chr(shifted)
        else:
            decrypted_text += char

    return decrypted_text

level1guess = caesar_cipher_decrypt(data['challenge'])

print("level1guess = " + level1guess)
with open('1_guess.txt', 'w') as f:
    f.write(level1guess)
h = solve(level, level1guess)

if 'hash' in h: hashes[level] = h['hash']


#################################################################################


# Fetch level 2
level = 2
data = fetch(level)
print(data)

with open('2_txt.txt', 'w') as f:
    f.write(data['challenge'])

import base64
from PIL import Image
import io
import re

# get the image from the base64 string
base64_string = data['challenge'].replace("data:image/png;base64,", "")
image_data = base64.b64decode(base64_string)
with open('2_img.jpg', 'wb') as f:
    f.write(image_data)

# regex pattern to find 3x words starting with 
# HCKR and uppercase letters, submit the guess
pattern = r'HCKR[A-Z][a-z]*[A-Z][a-z]*[A-Z][a-z]*'
matches = re.findall(pattern, str(image_data))

level2guess = matches[0].replace("HCKR","")

print("level2guess = " + level2guess)
with open('2_guess.txt', 'w') as f:
    f.write(level2guess)
h = solve(level, level2guess)

if 'hash' in h: hashes[level] = h['hash']


#################################################################################

# Fetch level 3
level = 3
data = fetch(level)
print(data)

with open('3_txt.txt', 'w') as f:
    f.write(data['challenge'])

# get the image from the base64 string
base64_string = data['challenge'].replace("data:image/png;base64,", "")
image_data = base64.b64decode(base64_string)
image = Image.open(io.BytesIO(image_data)).convert('RGB')

with open('3_img.jpg', 'wb') as f:
    f.write(image_data)

# loop through each pixel and add them together
# to get our secret data out
arry = ""
for y in range(image.height):
    for x in range(image.width):
        r, g, b = image.getpixel((x, y))
        arry += chr(r+g+b)


# regex pattern to find 3x words starting with 
# an uppercase letter, submit the guess
pattern = r'[A-Z][a-z]*[A-Z][a-z]*[A-Z][a-z]*'
level3guess = re.findall(pattern, arry)[0]

print("level3guess = " + level3guess)
with open('3_guess.txt', 'w') as f:
    f.write(level3guess)
h = solve(level, level3guess)

if 'hash' in h: hashes[level] = h['hash']

#################################################################################

from operator import mul
from operator import xor
from functools import reduce
from struct import unpack

# Fetch level 4
level = 4
data = fetch(level)
print(data)

with open('4_txt.txt', 'w') as f:
    f.write(data['challenge'])

# original obfuscated method - very clever!
def hasha_orig(d):
    j=unpack
    y=bytes
    e=mul
    w=bytearray
    n=xor
    i=reduce
    f=map
    l=b'\x3e\x68\x68\x69'
    q=w(b'\x0a'*4)
    r=len
    d=w(d)
    h=b'\x00\x0b\x01\x01\x00\x14\x2a\x2d'
    h=i(e,j(l,h))
    l=b'\x3e\x49'
    k=w(b'\xc0\xf4\xb0\xb4')
    c=h^(h&0x0)
    q=i(e,j(l,y(w(f(n,k,q)))))
    k=r(d)
    y,j=h^c,h
    while (y>>(c^3735928571))<k:
        j=(j^(((2**(4*1<<2)-1)*(y%(c^3736977135)>0))&((d[y>>(c^3735928571)]*q)^(0xface*(y>>(c^3735928571))))))&(2**(4*1<<2)-1)
        y+=(h^(h-0xf+0x2*7))
    return format(j, 'x')


# revised de-obfuscated method
# we can improve the efficiency by 100,000x
# which lets us brute force the hash
def hasha(pw):
    j = 0xBEEF
    for i in range(0, 4):
        j=j^(0xFFFF&((pw[i]*0xBABE)^(0xFACE*(i))))
    return(format(j, 'x'))

# code to create every password (from Stack Overflow)
def baseN(num, b=52, numerals="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"):
    return ((num == 0) and numerals[0]) or (baseN(num // b, b, numerals).lstrip(numerals[0]) + numerals[num % b])

# cycles through every 4 character password
# we pass it through the hash method and if 
# it matches then we submit the password as the guess 
level4guess = ""
for i in range(0,52**4):
    password = str(data['challenge'][-4:])
    result = hasha(bytearray(baseN(i).zfill(4).encode()))
    if str(result) == str(password):
        level4guess = str(baseN(i).zfill(4))
        break
        

print("level4guess = " + level4guess)
with open('4_guess.txt', 'w') as f:
    f.write(level4guess)
h = solve(level, level4guess)

if 'hash' in h: hashes[level] = h['hash']


#################################################################################

# Display all current hash
for k,v in hashes.items():
	print("Level {}: {}".format(k, v))

