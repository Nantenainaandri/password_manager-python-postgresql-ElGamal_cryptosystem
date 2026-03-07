
# impotation the modules and packages needed
import os
import sys
from getpass import getpass   # to hide the password when the user is typing it in the terminal (not like input() function)
import hashlib  # for hashing the password
import binascii
from unittest import result  # for converting the hashed password to hexadecimal format
import bcrypt  # for hashing the password with salt i.e. adding some random characters to the password before hashing it to make it more secure
import psycopg2 # package python for postgresql
from zxcvbn import zxcvbn  # for checking the strength of the password

import result  # for the results of the password strength check

#from rich import print as printc  # to make the result friendly


################################################################################################################
################################################################################################################


# main function
def main():

    db = db_connection()  # connect to the database and create the table if it doesn't exist
    
    # Ask the user to create a master password and store it in the database or enter if it already exists
    try:
        if db is None:
            master_password = getpass("Create your master password: ")
            
            hashed_master_password = hashlib.sha256(master_password.encode()).hexdigest()  # hash the master password with sha256 algorithm
        else:
            while True:
                master_password = getpass("Enter your master password: ")
                hashed_master_password = hashlib.sha256(master_password.encode()).hexdigest()

                if hashed_master_password == stored_hashed_master_password:  # compare the hashed master password with the stored hashed master password in the database
                    print("Master password is correct. Access granted.")
                    break
                else:
                    print("Master password is incorrect. Access denied. Please try again.")


    
    except Exception as error:
        print(error)

    if cur is not None:
        cur.close()

    if conn is not None:
        conn.close()
        


""""
    create_user_MP()  # create the user and the table for the password manager
    get_store_MP()    # ask and store the master password
    verification_PM() # verification of master password
    add_new_passwd()  # add new content in the database
"""



main()  # execute the main function when the script is run


################################################################################################################
################################################################################################################


# DATABASE CONNECTION


# initialise the connection to the database
def db_connection():

    # the parameters for the database
    hostname = 'localhost'
    database = 'demo'
    username = 'postgresql'
    passwd = 'password123'
    port_id = 5432

    # affect connection and cursor as None at the begining
    conn = None
    cur = None

    try:
        conn = psycopg2.connect(
            host = hostname,
            dbname = database,
            user = username,
            password = passwd,
            port = port_id
        )

        cur = conn.cursor()      # = cursor.connect(cursor_factory=psycopg2.extra.DictCursor)

        create_script = '''CREATE TABLE IF NOT EXISTS my_passwd_mngr(
                        id      int PRIMARY KEY,  # order from 1, the id 0 is for the master password
                        domain_name    varchar(40) NOT NULL,
                        username  varchar(35),
                        password_hashed varchar(30))'''

        cur.execute(create_script)
    
        db = cur.commit()

        return db


    except Exception as error:
        print(error)






################################################################################################################
# NEW USER CREATION


def hash_PM(passwd):

    # Hash the password with bcrypt
    salt = bcrypt.gensalt()  # generate a random salt
    hashed_passwd = bcrypt.hashpw(passwd.encode(), salt)  # hash the password with the salt

    return hashed_passwd

def verify_PM(attempted_passwd, hashed_passwd):
    # Verify the password
    if bcrypt.checkpw(attempted_passwd.encode(), hashed_passwd):
        print("Password is correct. Access granted.")
        return True
    else:
        print("Password is incorrect. Try again!")
        return False


def check_strength_PM(passwd):
    # Check the strength of the password
    strength = zxcvbn(passwd)
    score = strength['score']  # score is between 0 and 4, 0 is very weak and 4 is very strong

    if score < 2:
        feedback = result.get('feedback', {})
        warning = feedback.get('warning', '')
        suggestions = feedback.get('suggestions', [])
        reponse = f"Password is weak. {warning} {' '.join(suggestions)}"

        print("Password is weak. Try to make it stronger!")
        return "Weak"
    else:
        print("Password is strong. Good job!")
        return "Strong"


################################################################################################################
# MASTER PASSWORD CREATION AND VERIFICATION


################################################################################################################
# ADD NEW PASSWORD TO THE DATABASE





################################################################################################################


# ask and store the master password
def get_store_MP():
    pass


# verification of master password
def verification_PM(passwd_manager):
    pass




# # add new content in the database
def add_new_passwd(domain, user, passwd):
    insert_script = '''INSERT INTO employee (domain_name, username, password_hashed) VALUES (%s, %s, %s)'''  # for avoid SQL injection(put some code to execute)

    insert_value = (domain, user, passwd)

    cur.execute(insert_script, insert_value)



