# Intermittent Encryption Ransomware

Encrypts x bytes of a file for every x*y bytes.  

Adapted from https://github.com/febimudiyanto/python-project/tree/main/simple-ransomware  

## Added Features
An RSA-2048 key pair is generated for both the server and client. (In a real scenario the ransomware program would be distributed containing the server public key to a victim, and the server private key will be presumably sent to the victim upon payment.)  
The client private key is encrypted using the server public key, making it necessary to obtain the server private key for decryption.  
The program then loops through each of the client's files in the specified directory.  
A new AES-256 key is generated for each file using `os.urandom(32)`. The AES keys are encrypted with the client public key.  
The file is split into `y` chunks of `x` bytes each. (Default values supplied are 4 for each.) The first `x` bytes will be encrypted with AES and written to a new file, along with the encrypted AES key, nonce, and tag.  
The program will pass over the next `y-1` chunks and leave them as plaintext. 

With the default values supplied, each "block" of 16 bytes has only 4 bytes encrypted.  
The breakdown of every sequence of `4` encrypted bytes and `4*3` plaintext bytes in the encrypted file will look like this (not to scale): 
```
+---------------------------+------------+------------+------------+-----------+-----------+-----------+
|     Encrypted AES key     |   Nonce    |    Tag     | Ciphertext | Plaintext | Plaintext | Plaintext |    
|        (256 bytes)        | (16 bytes) | (16 bytes) | (4 bytes)  | (4 bytes) | (4 bytes) | (4 bytes) |
+---------------------------+------------+------------+------------+-----------+-----------+-----------+
```

These values can be verified for the parameters used in `decrypt.py` at line 66. 

For decryption, the program will first decrypt the client private key with the server private key.  
Each encrypted file will then be split into blocks according to the size detailed above (with default parameters, the block size is 300 bytes). 
Only the first 288 bytes of each block are of interest for decryption, since they contain the encrypted AES key, nonce and tag required to decrypt the 4 bytes of ciphertext.  
The AES key is decrypted with the client private key and used to decrypt its corresponding text block, producing the original file.  

## Install Dependencies
```pip install pycryptodome```  

## Run the Program
First run `keys.py` to generate your own (server) private and public keys. For simulation purposes we will assume that the ransomware ships with the server public key.  
Then run `encrypt.py` to encrypt files in the `/Ransomtest` folder (or whichever folder specified). A new key pair will be generated for the "client". There are some editable variables in the file.  
Run `decrypt.py` to decrypt the files. The server private key is required for decryption.  

`encrypt_normal.py` and `decrypt_normal.py` are the original encryption/decryption methods that operate on the entire file, instead of just certain bytes. 