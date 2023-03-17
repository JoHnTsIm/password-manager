import data
import check
import getpass
import user
import database
import encryption
from getpass import getpass

class Main:


    #* Displays the logged in menu.
    def loggedInMenu():
        operation = str(input
                        ("\nLogged in Menu\n-------------------\n(1) Show profile\n(2) Show password entries\n(3) Add password entry\n(4) Remove password entry\n(5) Edit Entry\n(6) Logout\nor leave empty to exit\n\nchoose an operation:"))

        if operation not in ["1", "2", "3", "4", "5", "6"] and operation != "":
            print("\n---------------------\nNot valid operation\n---------------------")
            Main.loggedInMenu()
            operation = None
        elif operation == "6":
            user.User.logout()
        elif operation != "":
            if operation == "1":
                Main.showUserInfo()
            elif operation == "2":
                Main.showCurrentEntries()
            elif operation == "3":
                Main.addEntry()
            elif operation == "4":
                Main.removeEntry()
            elif operation == "5":
                Main.editEntry()
            Main.loggedInMenu()


    #* Displays information about current user.
    def showUserInfo():
        print("\n\nYour profile\n---------------------------------------------------")
        print(f"username: {data.currentUser.username}")
        print("---------------------------------------------------\n")


    #* Display the current user password entries.
    def showCurrentEntries():
        entriesArray = data.currentUser.entries
        print("\n\nYour entries\n---------------------------------------------------------------------------------------")
        for array in list(entriesArray):
            print(
                f"{entriesArray.index(array) + 1}) {array[3]}/{array[0]} -> email: {array[1]}, password: {array[2]}")
        print("---------------------------------------------------------------------------------------")



    #* Adds new password entry.
    def addEntry():
        username = str(input("username: "))
        email = str(input("email(required): "))
        password = str(getpass("password(required): "))
        confirmPassword = str(getpass("Confirm password(required): "))
        websiteApp = str(input("website/App(required): "))

        dataInput = [email, password, websiteApp]

        if check.Check.checkEmpty(dataInput):
            Main.loggedInMenu()
        else:
            if check.Check.checkUsernameWebAppExists(username, websiteApp):
                Main.loggedInMenu()
            elif check.Check.checkEmail(email) == False:
                Main.loggedInMenu()
            elif check.Check.checkPasswords(password, confirmPassword) == False:
                Main.loggedInMenu()

        database.Db.addRowToPasswords(encryption.Enc.encryptMessage(username), encryption.Enc.encryptMessage(
            email), encryption.Enc.encryptMessage(password), encryption.Enc.encryptMessage(websiteApp))
        data.currentUser.entries.append((username, email, password, websiteApp))

        username = None
        email = None
        password = None
        websiteApp = None

        print("\n----------------------------\nNew entry added successfully\n----------------------------\n")


    #* Removes specific password entry.
    def removeEntry():
        idList = []
        iDs = list(database.Db.getIds())
        for id in iDs:
            idList.append(str(id[0]))

        Main.showCurrentEntries()
        userInputId = str(input("entry to remove: "))
        isNotAllowed = check.Check.checkNotAllowedCharacter(
            userInputId, ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0", ""])

        if isNotAllowed:
            print("\n\n---------------------------------------\nOne or more characters is not allowed\n---------------------------------------\n")
            Main.loggedInMenu()
        elif userInputId not in idList:
            if userInputId != "":
                print("\n\n------------------\nInvalid entry\n------------------\n")
        else:
            database.Db.removeRowFromPasswords(userInputId)
            print("\n\n---------------------------------------\nEntry removed successfully\n---------------------------------------\n")


    #* Edits a password entry.
    def editEntry():
        idList = []
        iDs = list(database.Db.getIds())
        for id in iDs:
            idList.append(str(id[0]))

        Main.showCurrentEntries()
        userInputId = str(input("entry to edit: "))
        isNotAllowed = check.Check.checkNotAllowedCharacter(
            userInputId, ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0", ""])

        if isNotAllowed:
            print("\n\n---------------------------------------\nOne or more characters is not allowed\n---------------------------------------\n")
            Main.loggedInMenu()
        elif userInputId not in idList:
            if userInputId != "":
                print("\n\n------------------\nInvalid entry\n------------------\n")
        else:
            cridentialToEdit = str(input(
                "\navailable cridentials to edit\n------------------------------\n(1) Email\n(2) Password\nChoose cridential: "))
            if cridentialToEdit not in ["1", "2", ""]:
                print("\n\n------------------\nInvalid choice\n------------------\n")
                Main.loggedInMenu()
            else:
                if cridentialToEdit == "1":
                    cridentialInput = str(input("new email: "))
                    if len(cridentialInput) > 0:
                        if check.Check.checkEmail(cridentialInput):
                            database.Db.updatePasswordsRow("email", userInputId,
                                        encryption.Enc.encryptMessage(cridentialInput))
                            data.currentUser.entries = []
                            data.currentUser.loadPasswords()
                            print(
                                "\n\n---------------------------------------\nEntry edited successfully\n---------------------------------------\n")
                            
                elif cridentialToEdit == "2":
                    cridentialInput = str(getpass("new password: "))
                if len(cridentialInput) > 0:
                    cridentialInputConfirm = str(
                        getpass("new password confirm: "))
                    if check.Check.checkPasswords(cridentialInput, cridentialInputConfirm):
                        database.Db.updatePasswordsRow("password", userInputId,
                                       encryption.Enc.encryptMessage(cridentialInput))
                        data.currentUser.entries = []
                        data.currentUser.loadPasswords()
                        print(
                            "\n\n---------------------------------------\nEntry edited successfully\n---------------------------------------\n")
                        

'''Main Program'''
if __name__ == "__main__":
    connection = database.Db.connectToDatabase("password_manager.db")
    cursor = database.Db.createCursor(connection)
    database.Db.createTables(cursor)
    user.User.menu()
