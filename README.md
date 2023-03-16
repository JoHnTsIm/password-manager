# password-manager
 a password manager created on python using libraries like: cryptography, sqlite3, base64. No gui.
 
 
 # **How it works**
 
  you need to create a _local_ account, _username_ and _password_. then you login locally using this account. 
 
 Then you can _see_, _add_, _remove_, _edit_ password entries. 
 
 You can create multiple accounts/users, that every user will have his own password entries
 
 account/user _password_ is hashed and entries inside those accounts is _encrypted_
 #
 🔴 **!!! WARNING !!!**
 All the user accounts and passwords entries will be saved **locally** into an sqlite database. if you **delete** the **.db** file that is located inside the **python program files**, you will lost **everything** that was inside that database, users and their password entries 🔴
