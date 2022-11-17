# Intermittent Encryption Ransomware

Encrypts x bytes of a file for every x*y bytes.  

Adapted from https://github.com/febimudiyanto/python-project/tree/main/simple-ransomware  

## Install Dependencies
```pip install pycryptodome```  

## Run the Program
First run `keys.py` to generate your own private and public keys.   
Then run `encrypt.py` to encrypt files in the `/Ransomtest` folder (or whichever folder specified). There are some editable variables in the file.  
Run `decrypt.py` to decrypt the files. 

`encrypt_normal.py` and `decrypt_normal.py` are the original encryption/decryption methods that operate on the entire file, instead of just certain bytes. 