from argon2 import PasswordHasher, exceptions

class Hash:

    #* Returns a hashed message using ARGON2.
    def hashing(message: str):
        ph = PasswordHasher()
        hashed_message = ph.hash(message)
        return hashed_message
    
    #* Verify a plain password against a hash
    def compareHashPlain(hash: str, plainPassword: str):
        ph = PasswordHasher()
        if hash != None:
            try:
                return ph.verify(hash, plainPassword)
            except exceptions.VerifyMismatchError as error:
                print(f"ERROR: {error}")
