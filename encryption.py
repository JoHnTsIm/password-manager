import data
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64

class Enc:
    
    #* Encrypt a message using PBKDF2HMAC.
    def encryptMessage(message: str):
        password = bytes(data.currentUser.password.encode("utf-8"))
        salt = os.urandom(32)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        f = Fernet(key)
        token = f.encrypt(bytes(message.encode("utf-8")))
        return token.hex() + ":" + salt.hex()
    

    #* Decrypt a message using PBKDF2HMAC.
    def decryptMessage(message: str):
        password = bytes(data.currentUser.password.encode("utf-8"))
        salt = bytes.fromhex(message.split(":")[1])
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        f = Fernet(key)
        start_message = f.decrypt(bytes.fromhex(message.split(":")[0]))

        return start_message.decode("utf-8")
