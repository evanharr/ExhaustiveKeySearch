import json
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import time
import argparse
from random import randint
from utils_demo import *

#opening plaintext1
pt1 = open("m1.txt","r")
pt1 = pt1.read()
#encode into utf-8 format
pt1 = pt1.encode('utf-8')
print(pt1)

#opening ciphertext1
ct1 = open("c1.bin","rb")
ct1 = ct1.read()
print(ct1)

#opening nonce1
n1 = open("nonce1.bin","rb")
n1 = n1.read()
print(n1)

#opening plaintext2
pt2 = open("m2.txt","r")
pt2 = pt2.read()
#encode into utf-8 format
pt2 = pt2.encode('utf-8')
print(pt2)

#opening ciphertext2
ct2 = open("c2.bin","rb")
ct2 = ct2.read()
print(ct2)

#opening nonce2
n2 = open("nonce2.bin","rb")
n2 = n2.read()
print(n2)

#opening plaintext3
pt3 = open("m3.txt","r")
pt3 = pt3.read()
#encode into utf-8 format
pt3 = pt3.encode('utf-8')
print(pt3)

#opening ciphertext3
ct3 = open("c3.bin","rb")
ct3 = ct3.read()
print(ct3)

#opneing nonce3
n3 = open("nonce3.bin","rb")
n3 = n3.read()
print(n1)

# create 128 bit key
main_key = bin(2 ** 127 )

print(main_key)





#increment key function
def incKey(s):
    #convert binary key to integer
    int_key = int(s, 2)
    #increment integer key by 1
    int_key+=1
    #convert integer back to binary
    convert_key = bin(int_key)
    #return incremented binary key
    return convert_key



i = 0
#convert binary key to hex bytes
key_ = bitstring_to_bytes(main_key)
#previously found key for testing
"""
decKey = b'\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfd\xea6'
decpt = decryptor_CTR(ctxt=ct1, nonce=n1, key=decKey)
print("here",decpt)

decpt2 = decryptor_CTR(ctxt=ct2, nonce=n2, key=decKey)
print("here2",decpt2)

decpt3 = decryptor_CTR(ctxt=ct3, nonce=n3, key=decKey)
print("here3",decpt3)
"""


#loop while i < 2^24 bit of key since arbituary numbers start at the 24th bit
while(i < 2**24):
    #get nonce and cipher text of plaintext with key to be tested
    nonce1, ctxt1 = encryptor_CTR(message=pt1, key=key_)
    print(main_key)
    print(key_)
    #get plaintext from given ciphertext.bin and nonce.bin with key to be tested
    pt = decryptor_CTR(ctxt=ct1, nonce=n1, key=key_)
    
    #if the given plaintext.bin is equal to decrpted plaintext with key to be tested
    if(pt == pt1):

        #get decrypted plaintexts for each given ciphers and nonces, using current iteration of key. If plaintexts match ouput key
        ptd2 = decryptor_CTR(ctxt=ct2, nonce=n2, key=key_)
        ptd3 = decryptor_CTR(ctxt=ct3, nonce=n3, key=key_)
        #check if the decrpyted plaintexts are equal to the given plaintexts
        if((pt2 == ptd2) & (pt3 == ptd3)):
            print("key: ", key_)
            print("decrypted plaintext 1: ", pt)
            print("decrypted plaintext 2: ", ptd2)
            print("decrypted plaintext 3: ", ptd3)
        break
        
    #if given nonce.bin and ciphertext.bin are equal to encryption with key
    if((nonce1 == n1) & (ctxt1 == ct1)):
        #get decrypted plaintexts for each given ciphers and nonces, using current iteration of key. If plaintexts match ouput key
        pt = decryptor_CTR(ctxt=ct1, nonce=n1, key=key_)
        ptd2 = decryptor_CTR(ctxt=ct2, nonce=n2, key=key_)
        ptd3 = decryptor_CTR(ctxt=ct3, nonce=n3, key=key_)
        if ((pt2 == ptd2) & (pt3 == ptd3) & (pt == pt1)):
            print("key: ", key_)
            print("decrypted plaintext 1: ", pt)
            print("decrypted plaintext 2: ", ptd2)
            print("decrypted plaintext 3: ", ptd3)
        break



    #if nonce.bin and ciphertext.bin are not equal to encryption with key increment the key 
    elif(((nonce1 != n1) & (ctxt1 != ct1))):
        #increment key 
        main_key = incKey(main_key)
        #convert binary key into hex key
        key_ = bitstring_to_bytes(main_key)
        i+=1
    else:
        print("else error")







