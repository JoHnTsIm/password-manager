import re
import database
import data

class Check:

    #* Gets a list with strings and checks if any of them has length equal to 0 (returns True)
    #* else returns False.
    def checkEmpty(inputs: list):
        for input in inputs:
            if len(input) == 0:
                print(
                    "\n----------------------\nEmpty required field\n----------------------\n")
                return True
        else:
            return False

    #* Gets a string and a list of allowed characters and checks if any character
    #* on the string is not in the list (reutrns True) else returns False.
    def checkNotAllowedCharacter(string: str, allowedChars: list):
        for char in string:
            if char not in allowedChars:
                return True
            else:
                return False

    #* Gets an email address and checks if the email address is valid (returns True)
    #* else returns False.
    def checkEmail(email: str):
        regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
        if (re.fullmatch(regex, email)):
            return True
        else:
            print("\n--------------\nInvalid Email\n--------------\n")
            return False


    #* Gets a password and confirm password and checks if the passwords doesn't match each other 
    #* (returns False) else returns True.
    def checkPasswords(password: str, confirmPassword: str):
        if password != confirmPassword:
            print("\n---------------------------\nPasswords does not match\n---------------------------\n")
            return False
        else:
            return True


    #* Gets a username and checks if the username exists on users table.
    def checkUsernameExists(username: str):
        username = database.Db.getUserUsername(username)
        if username != None:
            print("\n-----------------------------------------\nEntry with this username already exists\n-----------------------------------------\n")
            return True
        else:
            return False

    #* Gets a username and website/app name and checks if a password with those values exists
    #* on passwords table.
    def checkUsernameWebAppExists(username: str, websiteApp: str):
        for entry in data.currentUser.entries:
            if entry[0] == username and entry[3] == websiteApp:
                print("\n---------------------------------------------------------\nEntry with this username and website/app already exists\n---------------------------------------------------------\n")
                return True
            else:
                return False
