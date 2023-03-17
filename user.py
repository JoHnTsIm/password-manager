import check
import database
import getpass
import data
import hash
import os
import main
from getpass import getpass

class User:

    #* Displays the pre - login menu.
    def menu():
        operation = str(input
                        ("\nPre-login Menu\n-------------------\n(1) Login\n(2) Sign up\nor leave empty to exit\n\nchoose an operation:"))

        if operation not in ["1", "2"] and operation != "":
            print("\n---------------------\nNot valid operation\n---------------------")
            User.menu()
            operation = None
        else:
            if operation == "1":
                User.login()
            elif operation == "2":
                User.signup()


    #* Creates a new user.
    def signup():
        username = str(input("username(required): "))
        password = str(getpass("password(required): "))
        confirmPassword = str(getpass("confirm password(required): "))
        dataInput = [username, password, confirmPassword]

        if check.Check.checkEmpty(dataInput):
            User.menu()
        else:
            if check.Check.checkUsernameExists(username):
                check.Check.menu()
            elif check.Check.checkPasswords(password, confirmPassword) == False:
                User.menu()
            else:
                database.Db.addRowToUsers(username, hash.Hash.hashing(password))
                print("\n-------------------\nSigned up successful\n-------------------\n")
                User.menu()


    #* Logs in a user.
    def login():
        username = str(input("username(required): "))
        hashedPassword = database.Db.getUserPassword(username)
        id = database.Db.getUserId(username)
        dataInput = [username]

        if check.Check.checkEmpty(dataInput):
            User.menu()
        else:
            if hashedPassword == None:
                print(
                    "\n-------------------------\nUsername doesn't exist\n-------------------------\n")
                User.menu()
            else:
                password = str(getpass("password(required): "))
                passwordCheck = hash.Hash.compareHashPlain(hashedPassword, password)
                if passwordCheck == None:
                    print("\n---------------------\nWrong password\n---------------------\n")
                    User.menu()

                data.currentUser.id = id
                data.currentUser.username = username
                data.currentUser.password = password
                print("\nLogging in...\n")
                data.currentUser.loadPasswords()
                print(
                    "\n----------------------\nLogged in successful\n----------------------\n")
                main.Main.loggedInMenu()


    #* Logs out the current logged in user.
    def logout():
        data.currentUser.id = None
        data.currentUser.username = None
        data.currentUser.password = None
        data.currentUser.entries = []
        os.system("cls")
        User.menu()