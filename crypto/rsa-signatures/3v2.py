import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

# Key Generation
def generate_rsa_key():
	private_key = rsa.generate_private_key(
	public_exponent=65537,
	key_size=3072,
	backend=default_backend()
	)
	public_key = private_key.public_key()
	return private_key, public_key
# Signing
def sign_message(private_key, message):
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(message)
    digest = hasher.finalize()
  
    signature = private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature
# Signature Verification
def verify_signature(public_key, message, signature):
	hasher = hashes.Hash(hashes.SHA256(), default_backend())
	hasher.update(message)
	digest = hasher.finalize()
	try:
		public_key.verify(
			signature,
			digest,
			padding.PSS(
				mgf=padding.MGF1(hashes.SHA256()),
				salt_length=padding.PSS.MAX_LENGTH
			),
			hashes.SHA256()
		)
		return True
	except:
  		return False

# Test
private_key, public_key = generate_rsa_key()
message = b"Hello, world!"
signature = sign_message(private_key, message)
print("Signature verified:", verify_signature(public_key, message, signature))
