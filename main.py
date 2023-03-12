from dataclasses import dataclass
import sqlite3
from sqlite3 import Error
from argon2 import PasswordHasher, exceptions
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from getpass import getpass

################### data ####################
"""class that stores logged in user's info"""
dataclass
class currentUser:
    id: int
    username: str
    password: str
    entries: list = []
#############################################



"""creates connection to the database"""
def connectToDatabase(databaseFile : str):
    try:
        connection = sqlite3.connect(databaseFile)
        return connection
    except Error as error:
        print(f"ERROR: {error}")

"""creates query cursor using connection to the database"""
def createCursor(connection : sqlite3.Connection):
    try:
        cursor = connection.cursor()
        return cursor
    except Error as error:
        print(f"ERROR: {error}")

"""creates needed tables if they are not existed to the database"""
def createTables(cursor : sqlite3.Cursor):
    try:
        cursor.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY,
        username VARCHAR(255) NOT NULL,
        password VARCHAR(355) NOT NULL
        )""")
    except Error as error:
        print(f"ERROR: {error}")

    try:
        cursor.execute("""CREATE TABLE IF NOT EXISTS passwords(
        id INTEGER PRIMARY KEY,
        userid INTEGER NOT NULL REFERENCES users(id),
        username VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        password VARCHAR(355) NOT NULL,
        website_app VARCHAR(255) NOT NULL
        )""")
    except Error as error:
        print(f"ERROR: {error}")

"""closes the connection to the database"""
def closeConnection(connection: sqlite3.Connection):
    try:
        connection.close()
    except Error as error:
        print(f"ERROR: {error}")

"""hashes messages, here hashes user password"""
def hashing(message : str):
    '''ARGON 2'''
    ph = PasswordHasher()
    hashed_message = ph.hash(message)
    return hashed_message

"""does a query to the database and gets/returns user's password"""
def getUserPassword(username: str):
    connection = connectToDatabase("password_manager.db")
    cursor = createCursor(connection)

    result = cursor.execute(
        "SELECT password FROM users WHERE username =:name", [username]).fetchone()
    if result != None:
        password = result[0]
        return password
    else:
        return None
    
"""does a query to the database and gets/returns user's id"""
def getUserId(username: str):
    connection = connectToDatabase("password_manager.db")
    cursor = createCursor(connection)

    result = cursor.execute(
        "SELECT id FROM users WHERE username=:name", [username]).fetchone()
    if result != None:
        password = result[0]
        return password
    else:
        return None
    
"""gets all the rows of the user entries"""
def getAll():
    connection = connectToDatabase("password_manager.db")
    cursor = createCursor(connection)

    result = cursor.execute(
        """SELECT username, email, password, website_app 
        FROM passwords WHERE userid=:1""", [currentUser.id]).fetchall()
    
    return result

"""gets all the id's of the user entries"""
def getIds():
    connection = connectToDatabase("password_manager.db")
    cursor = createCursor(connection)

    result = cursor.execute(
        """SELECT id 
        FROM passwords WHERE userid=:1""", [currentUser.id]).fetchall()
    return result

"""compares a hash with a plain text, here compares the hashed password with the plain text one"""
def compareHashPlain(hash: str, plainPassword: str):
    ph = PasswordHasher()
    if hash != None:
        try:
            return ph.verify(hash, plainPassword)
        except exceptions.VerifyMismatchError as error:
            print(f"ERROR: {error}")

"""gets a list of strings and looks inside to see if any string has length 0"""
def checkEmpty(inputs: list):
    for input in inputs:
        if len(input) == 0:
            print(
                "\n----------------------\nempty required field!\n----------------------")
            return True
    else:
        return False

"""gets a string and a list with the allowed characters and checks if any of the characters of the string is not in the list"""
def checkNotAllowedCharacter(string: str, allowedChars: list):
    for char in string:
        if char not in allowedChars:
            return True     
        else:
            return False

"""asks the user to type his info to login"""
def login():
    username = str(input("username(required): "))
    hashedPassword = getUserPassword(username)
    id = getUserId(username)
    dataInput = [username]

    emptyField = checkEmpty(dataInput)
    if emptyField:
        menu()
    elif hashedPassword == None:
        print("\n---------------------\nusername doesn't exists\n---------------------\n")
        login()
    else:
        password = str(getpass("password(required): "))
        passwordCheck =  compareHashPlain(hashedPassword, password)
        if passwordCheck == None:
            print("\n---------------------\nwrong password\n---------------------\n")
            login()

        currentUser.id = id
        currentUser.username = username
        currentUser.password = password
        loadPasswords()
        loggedInMenu()

"""asks the user to type his info to register"""
def register():
    username = str(input("username(required): "))
    password = str(getpass("password(required): ")) # str(input("password(required): "))
    confirmPassword = str(getpass("confirm password(required): ")) # str(input("confirm password(required): "))
    dataInput = [username, password, confirmPassword]

    emptyField = checkEmpty(dataInput)
    if emptyField:
        menu()

    if password != confirmPassword:
        print("\n---------------------------\npasswords does not match\n---------------------------")
        register()
    else:
        insertRowToUsersTable(username, hashing(password))
        menu()

"""logs out the current logged in user"""
def logout():
    currentUser.id = None
    currentUser.username = None
    currentUser.password = None
    os.system("cls")
    menu()

"""inserts a new row to the table users with user's info"""
def insertRowToUsersTable(username : str, password: str):
    connection = connectToDatabase("password_manager.db")
    cursor = createCursor(connection)

    try:
        query = "INSERT INTO users (username, password) VALUES (?, ?)"
        data = (username, password)
        cursor.execute(query, data)
        connection.commit()
    except Error as error:
        print(f"ERROR: {error}")

"""outputs a menu and waits for the user to choose an operation"""
def menu():
    operation = str(input
                    ("\nPre-login Menu\n-------------------\n(1) login\n(2) register\nor leave empty to exit\n\nchoose an operation:"))

    if operation not in ["1", "2"] and operation != "":
        print("\n---------------------\nnot valid operation\n---------------------")
        menu()
        operation = None
    else:
        if operation == "1":
            login()
        elif operation == "2":
            register()

"""outputs a menu and waits for the logged in user to choose an operation"""
def loggedInMenu():
    operation = str(input
                    ("\nLogged in Menu\n-------------------\n(1) show profile\n(2) show password entries\n(3) add password entry\n(4) remove password entry\n(5) logout\nor leave empty to exit\n\nchoose an operation:"))

    if operation not in ["1", "2", "3", "4", "5"] and operation != "":
        print("\n---------------------\nnot valid operation\n---------------------")
        loggedInMenu()
        operation = None
    elif operation == "5":
        logout()
    elif operation != "":
        if operation == "1":
            showUserInfo()
        elif operation == "2":
            showCurrentEntries()
        elif operation == "3":
            addEntry()
        elif operation == "4":
            removeEntry()
        loggedInMenu()
            
"""outputs current logged in user's info"""
def showUserInfo():
    print("\n\nYour Profile\n---------------------------------------------------")
    print(f"username: {currentUser.username}")
    print("---------------------------------------------------\n")

"""inserts a new row to the table passwords with entry info"""
def insertRowToEntries(username : str, email : str, password : str, websiteApp: str):
    connection = connectToDatabase("password_manager.db")
    cursor = createCursor(connection)

    try:
        query = "INSERT INTO passwords (userid, username, email, password, website_app) VALUES (?, ?, ?, ?, ?)"
        data = (currentUser.id, username, email, password, websiteApp)
        cursor.execute(query, data)
        connection.commit()
    except Error as error:
        print(f"ERROR: {error}")

"""gets and id and removes the row with this specific id from the table"""
def removeRowFromEntries(id: str):
    connection = connectToDatabase("password_manager.db")
    cursor = createCursor(connection)

    try:
        cursor.execute("DELETE FROM passwords WHERE id=?", [id])
        connection.commit()
        currentUser.entries.pop(int(id) - 1)
    except Error as error:
        print(f"ERROR: {error}")

"""asks the user to give a username, email, password and a website or an app and inserts a new row to the table"""
def addEntry():
    username = str(input("username: "))
    email = str(input("email(required): "))
    password = str(getpass("password(required): ")) # str(input("password(required): "))
    websiteApp = str(input("website/App(required): "))

    dataInput = [email, password, websiteApp]

    emptyField = checkEmpty(dataInput)
    if emptyField:
        loggedInMenu()


    insertRowToEntries(encryptMessage(username), encryptMessage(
        email), encryptMessage(password), encryptMessage(websiteApp))
    currentUser.entries.append((username, email, password, websiteApp))
    print("Entry added successfully")
    
    # after insert
    username = None
    email = None
    password = None
    websiteApp = None
    #
    print("\n----------------------------\nnew entry added successfully\n----------------------------\n")

"""outpus all the current logged in user entries and waits for user input to remove a specific row"""
def removeEntry():
    idList = []
    iDs = list(getIds())
    for id in iDs:
        idList.append(str(id[0]))

    showCurrentEntries()
    userInputId = str(input("entry to remove: "))
    isNotAllowed = checkNotAllowedCharacter(userInputId, ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0", ""])

    if isNotAllowed:
        print("\n\n---------------------------------------\none or more characters is not allowed\n---------------------------------------\n")
        removeEntry()
    elif userInputId not in idList:
        if userInputId != "":
            print("\n\n------------------\ninvalid entry\n------------------\n")
    else:
        removeRowFromEntries(userInputId)
        print("\n\n---------------------------------------\nentry removed successfully\n---------------------------------------\n")

"""does a for loop in a list and outputs all the current logged in user entries"""
def showCurrentEntries():
    entriesArray = currentUser.entries
    print("\n\nYour Entries\n---------------------------------------------------------------------------------------")
    for array in list(entriesArray):
        print(
            f"{entriesArray.index(array) + 1}) {array[3]}/{array[0]} -> email: {array[1]}, password: {array[2]}")
    print("---------------------------------------------------------------------------------------")

"""loads all the rows from the database and output them"""
def loadPasswords():
    entriesArray = getAll()

    while currentUser.entries:
        currentUser.entries.pop()

    print("\nLogging in...\n")
    for array in list(entriesArray):
        dataArray = (decryptMessage(array[0]), decryptMessage(
            array[1]), decryptMessage(array[2]), decryptMessage(array[3]))
        
        currentUser.entries.append(dataArray)
        

    # print(f"\n\nentries{currentUser.entries}\n\n")

"""gets a message and encryptes the message"""
def encryptMessage(message: str):
    password = bytes(currentUser.password.encode("utf-8"))
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
    return token + salt

"""gets a message and decryptes the message"""
def decryptMessage(message: str):
    password = bytes(currentUser.password.encode("utf-8"))
    salt = bytes(message.split(b"==")[1])
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    start_message = f.decrypt(bytes(message.split(b":")[0]))

    return start_message.decode("utf-8")

'''Main Program'''
if __name__ == "__main__":
    connection = connectToDatabase("password_manager.db")
    cursor = createCursor(connection)
    createTables(cursor)
    menu()