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
import re

################### data ####################
"""class that stores logged in user's info"""
dataclass


class currentUser:
    id: int
    username: str
    password: str
    entries: list = []
#############################################


# Create a SQLite database connection.
def connectToDatabase(databaseFile: str):
    try:
        connection = sqlite3.connect(databaseFile)
        return connection
    except Error as error:
        print(f"ERROR: {error}")


# Creates a new SQLite3 cursor.
def createCursor(connection: sqlite3.Connection):
    try:
        cursor = connection.cursor()
        return cursor
    except Error as error:
        print(f"ERROR: {error}")


# Create tables if they do not exist.
def createTables(cursor: sqlite3.Cursor):
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


# Close a sqlite3 connection.
def closeConnection(connection: sqlite3.Connection):
    try:
        connection.close()
    except Error as error:
        print(f"ERROR: {error}")


# Returns a password hashing for a message.
def hashing(message: str):
    '''ARGON 2'''
    ph = PasswordHasher()
    hashed_message = ph.hash(message)
    return hashed_message


# Get a user s password.
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

# Returns the id of the user with the given username


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


# Fetch all passwords.
def getAll():
    connection = connectToDatabase("password_manager.db")
    cursor = createCursor(connection)

    result = cursor.execute(
        """SELECT username, email, password, website_app 
        FROM passwords WHERE userid=:1""", [currentUser.id]).fetchall()

    return result

# Returns a list of password ids.


def getIds():
    connection = connectToDatabase("password_manager.db")
    cursor = createCursor(connection)

    result = cursor.execute(
        """SELECT id 
        FROM passwords WHERE userid=:1""", [currentUser.id]).fetchall()
    return result


# Verify a plain password against a hash
def compareHashPlain(hash: str, plainPassword: str):
    ph = PasswordHasher()
    if hash != None:
        try:
            return ph.verify(hash, plainPassword)
        except exceptions.VerifyMismatchError as error:
            print(f"ERROR: {error}")

# Check if a list of inputs is empty.


def checkEmpty(inputs: list):
    for input in inputs:
        if len(input) == 0:
            print(
                "\n----------------------\nEmpty required field\n----------------------\n")
            return True
    else:
        return False

# Returns a boolean indicating if a character is allowed in a string.


def checkNotAllowedCharacter(string: str, allowedChars: list):
    for char in string:
        if char not in allowedChars:
            return True
        else:
            return False

# Check if an email address is valid.


def checkEmail(email: str):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
    if (re.fullmatch(regex, email)):
        return True
    else:
        print("\n--------------\nInvalid Email\n--------------\n")
        return False

# Check if a password matches a confirm password.


def checkPasswords(password: str, confirmPassword: str):
    if password != confirmPassword:
        print("\n---------------------------\nPasswords does not match\n---------------------------\n")
        return False
    else:
        return True


# Displays the login menu.
def login():
    username = str(input("username(required): "))
    hashedPassword = getUserPassword(username)
    id = getUserId(username)
    dataInput = [username]

    if checkEmpty(dataInput):
        menu()
    else:
        if hashedPassword == None:
            print(
                "\n-------------------------\nUsername doesn't exist\n-------------------------\n")
            menu()
        else:
            password = str(getpass("password(required): "))
            passwordCheck = compareHashPlain(hashedPassword, password)
            if passwordCheck == None:
                print("\n---------------------\nWrong password\n---------------------\n")
                menu()

            currentUser.id = id
            currentUser.username = username
            currentUser.password = password
            loadPasswords()
            print(
                "\n----------------------\nLogged in successful\n----------------------\n")
            loggedInMenu()

# Registers a new user.


def register():
    username = str(input("username(required): "))
    # str(input("password(required): "))
    password = str(getpass("password(required): "))
    # str(input("confirm password(required): "))
    confirmPassword = str(getpass("confirm password(required): "))
    dataInput = [username, password, confirmPassword]

    if checkEmpty(dataInput):
        menu()
    else:
        if checkPasswords(password, confirmPassword) == False:
            menu()
        else:
            insertRowToUsersTable(username, hashing(password))
            print("\n-------------------\nSigned up successful\n-------------------\n")
            menu()

# Logout the current user.


def logout():
    currentUser.id = None
    currentUser.username = None
    currentUser.password = None
    currentUser.entries = []
    os.system("cls")
    menu()

# Inserts a row to the users table.


def insertRowToUsersTable(username: str, password: str):
    connection = connectToDatabase("password_manager.db")
    cursor = createCursor(connection)

    try:
        query = "INSERT INTO users (username, password) VALUES (?, ?)"
        data = (username, password)
        cursor.execute(query, data)
        connection.commit()
    except Error as error:
        print(f"ERROR: {error}")

# Displays the pre - login menu.


def menu():
    operation = str(input
                    ("\nPre-login Menu\n-------------------\n(1) Login\n(2) Sign up\nor leave empty to exit\n\nchoose an operation:"))

    if operation not in ["1", "2"] and operation != "":
        print("\n---------------------\nNot valid operation\n---------------------")
        menu()
        operation = None
    else:
        if operation == "1":
            login()
        elif operation == "2":
            register()

# Logs in then displays the logged in menu.


def loggedInMenu():
    operation = str(input
                    ("\nLogged in Menu\n-------------------\n(1) Show profile\n(2) Show password entries\n(3) Add password entry\n(4) Remove password entry\n(5) Logout\nor leave empty to exit\n\nchoose an operation:"))

    if operation not in ["1", "2", "3", "4", "5"] and operation != "":
        print("\n---------------------\nNot valid operation\n---------------------")
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

# Displays information about current user.


def showUserInfo():
    print("\n\nYour profile\n---------------------------------------------------")
    print(f"username: {currentUser.username}")
    print("---------------------------------------------------\n")

# Inserts a row to passwords.


def insertRowToPasswords(username: str, email: str, password: str, websiteApp: str):
    connection = connectToDatabase("password_manager.db")
    cursor = createCursor(connection)

    try:
        query = "INSERT INTO passwords (userid, username, email, password, website_app) VALUES (?, ?, ?, ?, ?)"
        data = (currentUser.id, username, email, password, websiteApp)
        cursor.execute(query, data)
        connection.commit()
    except Error as error:
        print(f"ERROR: {error}")

# Removes a row from passwords.


def removeRowFromEntries(id: str):
    connection = connectToDatabase("password_manager.db")
    cursor = createCursor(connection)

    try:
        cursor.execute("DELETE FROM passwords WHERE id=?", [id])
        connection.commit()
        currentUser.entries.pop(int(id) - 1)
    except Error as error:
        print(f"ERROR: {error}")

# adds new entry to the passwords.


def addEntry():
    username = str(input("username: "))
    email = str(input("email(required): "))
    password = str(getpass("password(required): "))
    confirmPassword = str(getpass("Confirm password(required): "))
    websiteApp = str(input("website/App(required): "))

    dataInput = [email, password, websiteApp]

    if checkEmpty(dataInput):
        loggedInMenu()
    else:
        if checkEmail(email) == False:
            loggedInMenu()
        elif checkPasswords(password, confirmPassword) == False:
            loggedInMenu()

    insertRowToPasswords(encryptMessage(username), encryptMessage(
        email), encryptMessage(password), encryptMessage(websiteApp))
    currentUser.entries.append((username, email, password, websiteApp))

    username = None
    email = None
    password = None
    websiteApp = None

    print("\n----------------------------\nNew entry added successfully\n----------------------------\n")


# Removes the current entry from the passwords.
def removeEntry():
    idList = []
    iDs = list(getIds())
    for id in iDs:
        idList.append(str(id[0]))

    showCurrentEntries()
    userInputId = str(input("entry to remove: "))
    isNotAllowed = checkNotAllowedCharacter(
        userInputId, ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0", ""])

    if isNotAllowed:
        print("\n\n---------------------------------------\nOne or more characters is not allowed\n---------------------------------------\n")
        loggedInMenu()
    elif userInputId not in idList:
        if userInputId != "":
            print("\n\n------------------\nInvalid entry\n------------------\n")
    else:
        removeRowFromEntries(userInputId)
        print("\n\n---------------------------------------\nEntry removed successfully\n---------------------------------------\n")

# Display the current user entries.


def showCurrentEntries():
    entriesArray = currentUser.entries
    print("\n\nYour entries\n---------------------------------------------------------------------------------------")
    for array in list(entriesArray):
        print(
            f"{entriesArray.index(array) + 1}) {array[3]}/{array[0]} -> email: {array[1]}, password: {array[2]}")
    print("---------------------------------------------------------------------------------------")

# Load passwords from the database.


def loadPasswords():
    entriesArray = getAll()

    print("\nLogging in...\n")
    for array in list(entriesArray):
        dataArray = (decryptMessage(array[0]), decryptMessage(
            array[1]), decryptMessage(array[2]), decryptMessage(array[3]))

        currentUser.entries.append(dataArray)


# Encrypt a message using PBKDF2HMAC.
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
    return token.hex() + ":" + salt.hex()

# Decrypt a message using PBKDF2HMAC.


def decryptMessage(message: str):
    password = bytes(currentUser.password.encode("utf-8"))
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


'''Main Program'''
if __name__ == "__main__":
    connection = connectToDatabase("password_manager.db")
    cursor = createCursor(connection)
    createTables(cursor)
    menu()
