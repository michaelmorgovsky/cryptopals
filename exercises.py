import string
import base64
import codecs
import os
import requests

def xor(c, k):
    return bytes([x ^ k for x in c])

def repeating_xor(c, k):
    i = 0
    cipher = []
    for x in c:
        cipher.append(x ^ k[i % len(k)])
        i += 1
    return bytes(cipher)

def score(p):
    score = 0

    if p == None:
        return 0
    
    for char in p:
        if chr(char) not in string.printable:
            return 0
        if char in b"etaoin shrdlu": # Check using letter frequency analysis, 1. e, 2. t, 3. a, ...
            score = score+1
    return score

def max_scorer(plaintexts):
    best_score = 0
    best_plaintext = None
    for plaintext in plaintexts:
        if score(plaintext) > best_score:
            best_score = score(plaintext)
            best_plaintext = plaintext
    return best_plaintext

def xor_against_all_bytes(c):
    best_score = 0
    best_text = None
    for num in range(255):
        p = xor(c, num)
        if score(p) > best_score:
            best_score = score(p)
            best_text = p
    return best_text

def hamming(value1, value2):
    ham_score = 0
    if type(value1) == str:
        value1 = bytes(value1, 'utf-8')
    if type(value2) == str:
        value2 = bytes(value2, 'utf-8')

    bit_string_1 = ""
    for c in value1:
        for shift in range(0, 8, 1):
            bit_string_1 = f"{bit_string_1}{(c >> shift) & 1}"

    bit_string_2 = ""
    for c in value2:
        for shift in range(0, 8, 1):
            bit_string_2 = f"{bit_string_2}{(c >> shift) & 1}"

    for bit1, bit2 in zip(bit_string_1, bit_string_2):
        if bit1 != bit2:
            ham_score += 1
    return ham_score

def exercise1():
    # https://cryptopals.com/sets/1/challenges/1
    hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    b64 = base64.encodebytes(bytes.fromhex(hex))

    assert b64 == b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t\n'

def exercise2():
    # https://cryptopals.com/sets/1/challenges/2
    xor1 = "1c0111001f010100061a024b53535009181c"
    xor2 = "686974207468652062756c6c277320657965"
    xor1 = bytes.fromhex(xor1)
    xor2 = bytes.fromhex(xor2)

    xor_result = bytes(var1 ^ var2 for (var1, var2) in zip(xor1, xor2))
    xor_result = codecs.encode(xor_result, 'hex')

    assert xor_result == b'746865206b696420646f6e277420706c6179'

def exercise3():
    # https://cryptopals.com/sets/1/challenges/3
    encoded_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    cipher = bytes.fromhex(encoded_str)
    
    plaintext = xor_against_all_bytes(cipher)
    assert plaintext.decode("utf-8") == "Cooking MC's like a pound of bacon"

def exercise4():
    # https://cryptopals.com/sets/1/challenges/4
    ciphers = requests.get('https://cryptopals.com/static/challenge-data/4.txt').text.splitlines()
    
    plaintexts = list()
    for cipher in ciphers:
        cipher = bytes.fromhex(cipher)
        plaintexts.append(xor_against_all_bytes(cipher))
    assert max_scorer(plaintexts).decode("utf-8") == "Now that the party is jumping\n"

def exercise5():
    # https://cryptopals.com/sets/1/challenges/5
    plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = b"ICE"
    ciphertext = repeating_xor(plaintext, key).hex()
    assert ciphertext == '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'

def exercise6():
    # https://cryptopals.com/sets/1/challenges/6
    string1 = "this is a test"
    string2 = "wokka wokka!!!"
    ham_score_test = hamming(string1, string2)
    assert ham_score_test == 37

    cipher = requests.get('https://cryptopals.com/static/challenge-data/6.txt').text
    print(cipher)




if __name__ == "__main__":
    exercise1()
    exercise2()
    exercise3()
    exercise4()
    exercise5()
    exercise6()
