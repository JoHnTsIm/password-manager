from dataclasses import dataclass
import encryption
import database

################### data ####################
"""class that stores logged in user's info"""
dataclass
class currentUser:
    id: int
    username: str
    password: str
    entries: list = []
#############################################

    #* Loads passwords from passwords table.
    def loadPasswords():
        entriesArray = database.Db.getAll()

        for array in list(entriesArray):
            dataArray = (encryption.Enc.decryptMessage(array[0]), encryption.Enc.decryptMessage(
                array[1]), encryption.Enc.decryptMessage(array[2]), encryption.Enc.decryptMessage(array[3]))

            currentUser.entries.append(dataArray)
