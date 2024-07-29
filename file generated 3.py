#!/usr/bin/env python
# ----------------- Header Files ---------------------#

from __future__ import division, print_function, unicode_literals

import sys
import random
import argparse
import logging
from tkinter import *
import tkinter.filedialog as tkFileDialog
import tkinter.messagebox as tkMessageBox
import os
from PIL import Image
import numpy as np
from Crypto.Cipher import AES
import hashlib
import binascii

# Global variable for password
global password 

def load_image(name):
    return Image.open(name)

# ----------------- Functions for encryption ---------------------#
def prepare_message_image(image, size):
    if size != image.size:
        image = image.resize(size, Image.ANTIALIAS)
    return image

def generate_secret(size, secret_image=None):
    width, height = size
    new_secret_image = Image.new(mode="RGB", size=(width * 2, height * 2))

    for x in range(0, 2 * width, 2):
        for y in range(0, 2 * height, 2):
            color1 = np.random.randint(255)
            color2 = np.random.randint(255)
            color3 = np.random.randint(255)
            new_secret_image.putpixel((x, y), (color1, color2, color3))
            new_secret_image.putpixel((x + 1, y), (255 - color1, 255 - color2, 255 - color3))
            new_secret_image.putpixel((x, y + 1), (255 - color1, 255 - color2, 255 - color3))
            new_secret_image.putpixel((x + 1, y + 1), (color1, color2, color3))

    return new_secret_image

def generate_ciphered_image(secret_image, prepared_image):
    width, height = prepared_image.size
    ciphered_image = Image.new(mode="RGB", size=(width * 2, height * 2))
    for x in range(0, width * 2, 2):
        for y in range(0, height * 2, 2):
            sec = secret_image.getpixel((x, y))
            msssg = prepared_image.getpixel((int(x / 2), int(y / 2)))
            color1 = (msssg[0] + sec[0]) % 256
            color2 = (msssg[1] + sec[1]) % 256
            color3 = (msssg[2] + sec[2]) % 256
            ciphered_image.putpixel((x, y), (color1, color2, color3))
            ciphered_image.putpixel((x + 1, y), (255 - color1, 255 - color2, 255 - color3))
            ciphered_image.putpixel((x, y + 1), (255 - color1, 255 - color2, 255 - color3))
            ciphered_image.putpixel((x + 1, y + 1), (color1, color2, color3))

    return ciphered_image

def generate_image_back(secret_image, ciphered_image):
    width, height = secret_image.size
    new_image = Image.new(mode="RGB", size=(int(width / 2), int(height / 2)))
    for x in range(0, width, 2):
        for y in range(0, height, 2):
            sec = secret_image.getpixel((x, y))
            cip = ciphered_image.getpixel((x, y))
            color1 = (cip[0] - sec[0]) % 256
            color2 = (cip[1] - sec[1]) % 256
            color3 = (cip[2] - sec[2]) % 256
            new_image.putpixel((int(x / 2), int(y / 2)), (color1, color2, color3))

    return new_image

#------------------------Encryption -------------------#
def level_one_encrypt(Imagename):
    message_image = load_image(Imagename)
    size = message_image.size
    width, height = size

    secret_image = generate_secret(size)
    secret_image.save("secret.jpeg")

    prepared_image = prepare_message_image(message_image, size)
    ciphered_image = generate_ciphered_image(secret_image, prepared_image)
    ciphered_image.save("2-share_encrypt.jpeg")

def construct_enc_image(ciphertext, relength, width, height):
    asciicipher = binascii.hexlify(ciphertext).decode()
    
    # Replace characters with numbers
    reps = {'a': '1', 'b': '2', 'c': '3', 'd': '4', 'e': '5', 'f': '6', 'g': '7',
            'h': '8', 'i': '9', 'j': '10', 'k': '11', 'l': '12', 'm': '13', 'n': '14',
            'o': '15', 'p': '16', 'q': '17', 'r': '18', 's': '19', 't': '20', 'u': '21',
            'v': '22', 'w': '23', 'x': '24', 'y': '25', 'z': '26'}
    asciiciphertxt = ''.join(reps.get(c, c) for c in asciicipher)

    # Construct encrypted image
    step = 3
    encimageone = [asciiciphertxt[i:i+step] for i in range(0, len(asciiciphertxt), step)]

    if int(encimageone[-1]) < 100:
        encimageone[-1] += "1"
        
    if len(encimageone) % 3 != 0:
        while len(encimageone) % 3 != 0:
            encimageone.append("101")

    encimagetwo = [(int(encimageone[i]), int(encimageone[i + 1]), int(encimageone[i + 2]))
                   for i in range(0, len(encimageone), step)]
    
    while relength != len(encimagetwo):
        encimagetwo.pop()

    encim = Image.new("RGB", (width, height))
    encim.putdata(encimagetwo)
    encim.save("visual_encrypt.jpeg")

#------------------------- Visual-encryption -------------------------#
def encrypt(imagename, password):
    plaintext = []
    plaintextstr = ""

    im = Image.open(imagename) 
    pix = im.load()

    width = im.size[0]
    height = im.size[1]
    
    # Break up the image into a list of pixel values and append to a string
    for y in range(height):
        for x in range(width):
            plaintext.append(pix[x, y])

    # Add 100 to each tuple value to ensure each is 3 digits long
    for i in range(len(plaintext)):
        for j in range(3):
            aa = int(plaintext[i][j]) + 100
            plaintextstr += str(aa)

    # Length save for encrypted image reconstruction
    relength = len(plaintext)

    # Append dimensions of image for reconstruction after decryption
    plaintextstr += "h" + str(height) + "h" + "w" + str(width) + "w"

    # Ensure plaintextstr length is a multiple of 16 for AES. If not, append "n".
    while len(plaintextstr) % 16 != 0:
        plaintextstr += "n"

    # Encrypt plaintext
    obj = AES.new(password, AES.MODE_CBC, b'This is an IV456')
    ciphertext = obj.encrypt(plaintextstr.encode())  # Encode to bytes

    # Write ciphertext to file
    cipher_name = imagename + ".crypt"
    with open(cipher_name, 'wb') as g:
        g.write(ciphertext)
    
    construct_enc_image(ciphertext, relength, width, height)
    print("Visual Encryption done.......")
    level_one_encrypt("visual_encrypt.jpeg")
    print("2-Share Encryption done.......")
    
def decrypt(ciphername, password):
    secret_image = Image.open("secret.jpeg")
    ima = Image.open("2-share_encrypt.jpeg")
    new_image = generate_image_back(secret_image, ima)
    new_image.save("2-share_decrypt.jpeg")
    print("2-share Decryption done....")
    
    with open(ciphername, 'rb') as cipher:
        ciphertext = cipher.read()

    # Decrypt ciphertext with password
    obj2 = AES.new(password, AES.MODE_CBC, b'This is an IV456')
    decrypted = obj2.decrypt(ciphertext).decode('utf-8')  # Decode from bytes

    # Remove padding characters
    decrypted = decrypted.replace("n", "")

    # Extract dimensions of images
    newwidth = decrypted.split("w")[1]
    newheight = decrypted.split("h")[1]

    # Replace height and width with empty space in decrypted plaintext
    heightr = "h" + str(newheight) + "h"
    widthr = "w" + str(newwidth) + "w"
    decrypted = decrypted.replace(heightr, "")
    decrypted = decrypted.replace(widthr, "")

    # Convert decrypted text into a list of tuples
    newtxt = [int(decrypted[i:i+3]) - 100 for i in range(0, len(decrypted), 3)]
    newtxttwo = [(newtxt[i], newtxt[i+1], newtxt[i+2]) for i in range(0, len(newtxt), 3)]

    newimg = Image.new("RGB", (int(newwidth), int(newheight)))
    newimg.putdata(newtxttwo)
    newimg.save("visual_decrypt.jpeg")
    print("Visual Decryption done....")

# ------------------ Tkinter GUI ---------------------#
def image_open():
    filename = tkFileDialog.askopenfilename(filetypes=[("Image files", "*.jpg;*.jpeg;*.png")])
    if filename:
        password = password_entry.get()
        password = hashlib.sha256(password.encode()).digest()  # Encode before hashing
        encrypt(filename, password)

def image_open2():
    filename = tkFileDialog.askopenfilename(filetypes=[("Encrypted files", "*.crypt")])
    if filename:
        password = password_entry.get()
        password = hashlib.sha256(password.encode()).digest()  # Encode before hashing
        decrypt(filename, password)

# Create main window
root = Tk()
root.title("Image Encryption/Decryption")

# Create and place widgets
password_label = Label(root, text="Password:")
password_label.pack(padx=10, pady=10)
password_entry = Entry(root, show="*")
password_entry.pack(padx=10, pady=10)

encrypt_button = Button(root, text="Encrypt Image", command=image_open)
encrypt_button.pack(padx=10, pady=10)

decrypt_button = Button(root, text="Decrypt Image", command=image_open2)
decrypt_button.pack(padx=10, pady=10)

# Start the GUI event loop
root.mainloop()
