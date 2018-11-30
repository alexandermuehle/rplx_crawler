import hashlib
import sha3

def keccak256(s):
	k = sha3.keccak_256()
	k.update(s)
	return k.digest()
