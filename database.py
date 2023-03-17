import sqlite3
from sqlite3 import Error
import data

class Db:
    
    #* Connect to database and create cursor.
    def startDb():
        connection = Db.connectToDatabase("password_manager.db")
        cursor = Db.createCursor(connection)
        Db.createTables(cursor)
        return connection, cursor


    #* Connect to database.
    def connectToDatabase(databaseFile: str):
        try:
            connection = sqlite3.connect(databaseFile)
            return connection
        except Error as error:
            print(f"ERROR: {error}")


    #* Creates cursor.
    def createCursor(connection: sqlite3.Connection):
        try:
            cursor = connection.cursor()
            return cursor
        except Error as error:
            print(f"ERROR: {error}")


    #* Creates user and passwords tables, if they do not exist.
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


    #* Terminates/Closes connection to the database.
    def closeConnection(connection: sqlite3.Connection):
        try:
            connection.close()
        except Error as error:
            print(f"ERROR: {error}")


    #* Get a user's password.
    def getUserPassword(username: str):
        connection, cursor = Db.startDb()

        result = cursor.execute(
            "SELECT password FROM users WHERE username =:name", [username]).fetchone()
        if result != None:
            password = result[0]
            return password
        else:
            return None


    #* Returns the id of the user with the given username
    def getUserId(username: str):
        connection, cursor = Db.startDb()

        result = cursor.execute(
            "SELECT id FROM users WHERE username=:name", [username]).fetchone()
        if result != None:
            password = result[0]
            return password
        else:
            return None


    #* Get a user's username.
    def getUserUsername(username: str):
        connection, cursor = Db.startDb()

        result = cursor.execute(
            "SELECT username FROM users WHERE username=:name", [username]).fetchone()
        return result
    

    #* Returns a list of password ids.
    def getIds():
        connection, cursor = Db.startDb()

        result = cursor.execute(
            """SELECT id 
            FROM passwords WHERE userid=:1""", [data.currentUser.id]).fetchall()
        return result

    
    #* Fetches usernames, emails, passwords and website_app from passwords table 
    #* for current logged in user and returns it.
    def getAll():
        connection, cursor = Db.startDb()

        result = cursor.execute(
            """SELECT username, email, password, website_app 
            FROM passwords WHERE userid=:1""", [data.currentUser.id]).fetchall()

        return result
    

    #* Gets a username, email, password and websiteApp and 
    #* adds a new row to the passwords database.
    def addRowToPasswords(username: str, email: str, password: str, websiteApp: str):
        connection, cursor = Db.startDb()

        try:
            query = "INSERT INTO passwords (userid, username, email, password, website_app) VALUES (?, ?, ?, ?, ?)"
            dataArray = (data.currentUser.id, username, email, password, websiteApp)
            cursor.execute(query, dataArray)
            connection.commit()
        except Error as error:
            print(f"ERROR: {error}")


    #* Gets an id and removes a row from passwords table.
    def removeRowFromPasswords(id: str):
        connection, cursor = Db.startDb()

        try:
            cursor.execute("DELETE FROM passwords WHERE id=?", [id])
            connection.commit()
            data.currentUser.entries.pop(int(id) - 1)
        except Error as error:
            print(f"ERROR: {error}")


    #* Gets a column name, id and a value and updates specific column on passwords row
    def updatePasswordsRow(column: str, id: str, newvalue: str):
        connection, cursor = Db.startDb()

        cursor.execute(
            f"UPDATE passwords SET {column} = ? WHERE id = ?", [newvalue, id])
        connection.commit()

    #* Gets a username and password and inserts a row to users table.
    def addRowToUsers(username: str, password: str):
        connection, cursor = Db.startDb()

        try:
            query = "INSERT INTO users (username, password) VALUES (?, ?)"
            data = (username, password)
            cursor.execute(query, data)
            connection.commit()
        except Error as error:
            print(f"ERROR: {error}")
