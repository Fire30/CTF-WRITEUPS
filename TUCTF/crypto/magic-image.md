
# Magic Image

For this challenge you were given two files encrypt.py and encrypted.png. Presumably encrypted.png was generated with encrypt.py script. Here are the contents of the encrypt.py.

```python
#!/usr/bin/env python

def xor(s1, s2):
    res = [chr(0)]*12
    for i in range(len(res)):
        q = ord(s1[i])
        d = ord(s2[i])
        k = q ^ d
        res[i] = chr(k)
    res = ''.join(res)
    return res

def add_pad(msg):
    l = 12 - len(msg)%12
    msg += chr(l)*l
    return msg

with open('flag.png') as f:
    data = f.read()

data = add_pad(data)

with open('key') as f:
    key = f.read()

enc_data = ''
for i in range(0, len(data), 12):
    enc = xor(data[i:i+12], key)
    enc_data += enc

with open('encrypted.png', 'wb') as f:
    f.write(enc_data)

```

Looking at the code we see that it simply has a twelve byte key that xors every byte of the file with, and we need to recover it to get the original png back.

The [PNG](http://www.libpng.org/pub/png/spec/1.2/PNG-Structure.html) file format has an 8 byte header of [137 80 78 71 13 10 26 10]. So we can obtain the first 8 bytes of the key by finding each byte, b, such that ```b ^ encrypted_header[i] = decrypted_header[i]```

What about the last 4 bytes however? Well looking at the add_pad function it's main job is to pad the decrypted file so that it is divisble by the key length. The way it does it is by padding it with the character value of the number of bytes that need to be added. This is easily reversible though. If it padded over four bytes than that means we will have the key and the encrpyted value. So all we need to do is figure out the pad length. This is done by finding the value such that ```key[i] ^ i == last[i]``` where last is the last 12 bytes of the encrypted file. It turns out that the pad length is seven in this case.

We just use that formula for last four bytes of the key replacing i with the padlength ```key[i] ^ pad_length == last[i]```. Now we will have the full key and can reverse the whole image by running the encryption algorithm on itself.

Here is the full code used to solve it.

```python
#!/usr/bin/env python

def xor(s1, s2):
    res = [chr(0)]*12
    for i in range(len(res)):
        q = ord(s1[i])
        d = ord(s2[i])
        k = q ^ d
        res[i] = chr(k)
    res = ''.join(res)
    return res

# PNG header values
ords = [137, 80, 78, 71, 13, 10, 26, 10]

# Read the whole encrypted file
# and get the first 8 and last 12 bytes for later use
with open('encrypted.png') as f:
    r = f.read()
    enc_ords = r[:8]
    enc_ords = [ord(x) for x in enc_ords]
    last = r[len(r) - 12:]
    last = [ord(x) for x in last]


# Get the first eight bytes of the key
key = []
for i in range(0,len(ords)):
    for x in range(255):
        if ords[i] ^ x == enc_ords[i]:
            key.append(x)
            break

# Get the pad length and value
for x in range(1,8):
    if key[x] ^ x == last[x]:
        pad = x

# Get the last four bytes of the key
for i in range(8,12):
    for x in range(255):
        if x ^ pad == last[i]:
            key.append(x)

# Put the key into a string
key = ''.join([chr(x) for x in key])

# decrypt the file
enc_data = ''
for i in range(0, len(r), 12):
    enc = xor(r[i:i+12], key)
    enc_data += enc

# write the decrypted image out
with open('decrypt.png', 'wb') as f:
    f.write(enc_data)

```

And here is the decrypted image file with the flag

![Flag Image](https://i.imgur.com/JdSTCUz.png) 
