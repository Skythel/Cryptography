from Crypto.PublicKey import RSA

# generate server's rsa key
key = RSA.generate(2048)
privateKey = key.export_key()
publicKey = key.publickey().export_key()

# save private key to file
with open('server_private.pem', 'wb') as f:
    f.write(privateKey)
    print('Private key saved to server_private.pem')

# save public key to file
with open('server_public.pem', 'wb') as f:
    f.write(publicKey)
    print('Public key saved to server_public.pem')

print('Done')