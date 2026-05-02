import bcrypt
from auth_tests.config import config


class BcryptHasher:
    def __init__(self, rounds=None):
        self.rounds = rounds or config.bcrypt_rounds

    def hash_password(self, password: str) -> dict:
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=self.rounds))
        return {'hash': hashed.decode(), 'algorithm': 'bcrypt'}

    def verify_password(self, password: str, stored_hash: str) -> bool:
        return bcrypt.checkpw(password.encode(), stored_hash.encode())