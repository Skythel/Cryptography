# keys: generates keypair using elliptic curve
# curve: contains different elliptic curves to choose from
# ecdsa: generate and verify signatures
from fastecdsa import keys, curve, ecdsa

# generate a public and private keypair
priv_key, pub_key = keys.gen_keypair(curve.P256) 

# private key is a large number
print(f"private key:\n{priv_key} \n")

# public key contains x and y coordinates in hex and the curve number, e.g. P256
print(f"public key:\n{pub_key} \n")

# have an arbitrary plaintext string
message = "testing message"

# encrypt the message
(r,s) = ecdsa.sign(message, priv_key)
print(f"Signature:\n{(r,s)}\n")

# verify the public key (encrypted message) matches the plaintext message
valid = ecdsa.verify((r,s), message, pub_key)
print(f"The plaintext matches the public key?\n{valid}\n")