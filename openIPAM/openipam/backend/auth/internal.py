import hashlib
from openipam.config import auth


def hash_password(password):
    """
	Hash a plaintext password using the algorithm described in auth.py
	"""

    hash = hashlib.new(auth.internal_hash)
    hash.update(password)

    return hash.hexdigest()
