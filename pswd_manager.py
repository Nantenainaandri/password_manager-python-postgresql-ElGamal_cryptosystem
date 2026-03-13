"""

    NEED TO KNOW:
    - make sure the database name is correct for your database, (my db name is 'pgpm')
    - the prime number must be large and safe (you can generate in the file 'algoCrypto_S8_for_PM.py')
    - 


"""



# impotation the modules and packages needed:

import os
import sys
import psycopg2 # package python for postgresql
from getpass import getpass   # to hide the password when the user is typing it in the terminal (not like input() function)
from zxcvbn import zxcvbn  # for checking the strength of the password
from prettytable import PrettyTable  # for displaying the stored domain names and usernames in a table format
import pyperclip # for copying the password to the clipboard when the user wants to get a password from the database without showing it in the terminal

# bcrypt: hashing not inreversible,
import bcrypt  # for hashing the password with salt i.e. adding some random characters to the password before hashing it to make it more secure

# import functions from the modules algoCrypto_S8_for_PM
from algoCrypto_S8_for_PM import elgamal_encrypt, elgamal_decrypt, elgamal_keygen, encrypt_number, decrypt_number, decrypt_mapping



################################################################################################################

# NEW USER CREATION:

# Function to ask the user to enter the new password
def ask_new_password():
    # ask the user to enter the new master password and confirm it by entering it two times to avoid typos
    new_password_1 = getpass("Enter the new password: ")
    new_password_2 = getpass("Confirm the new password: ")

    if new_password_1 != new_password_2:
        print("Passwords do not match. Please try again.")
        return ask_new_password()

    return new_password_1

# Function to verify the master password entered by the user
def verify_PM(attempted_passwd, hashed_passwd):
    # Verify the password
    if bcrypt.checkpw(attempted_passwd.encode(), hashed_passwd):
        print("Password is correct. Access granted.")
        return True
    else:
        print("Password is incorrect. Try again!")
        return False


# Function to check the strength of the master password
def check_strength_PM(passwd):
    
    strength = zxcvbn(passwd)
    score = strength['score']  # score is between 0 and 4, 0 is very weak and 4 is very strong

    if score < 2:
        feedback = strength.get('feedback', {})
        warning = feedback.get('warning', '')
        suggestions = feedback.get('suggestions', [])
        resp = f"Password is weak. {warning} {' '.join(suggestions)}"

        print(f"Password is weak. {resp} Try to make it stronger!")
        return "Weak"
    else:
        print("Password is strong. Good job!")
        return "Strong"


# Function to update, hash, and store the master password
def MP_creation_verification(conn, cur):
    while True:
        master_password = ask_new_password()

        # check the strength of the new master password
        res = check_strength_PM(master_password)
        if res == "Strong":
            break
        else:
            continue
                            
    # hash the new master password with bcrypt and salt
    hashed_master_password = bcrypt.hashpw(master_password.encode("utf-8"), bcrypt.gensalt())

    # store the hashed master password in the database with the id 0, the domain name "Master_Password" and the username "MASTER"
    cur.execute(
            "INSERT INTO my_passwd_mngr (id, domain_name, username, password_hashed_1) VALUES (%s, %s, %s, %s)",
           (0, "Master_Password", "MASTER", hashed_master_password.decode("utf-8"))
            )

    return conn.commit()


################################################################################################################

# Function to ask the right input from the user
def ask_user_input(n):
    while True:
        # main menu
        if n == 3:
            sentece = "\n 1 get a password \n 2 add new passwords\n 3 view your stored domain names (update/delete)\n 0 exit program \n\n -> "
        # submenu
        elif n == 2:
            sentece = "\n 1 update \n 2 delete \n 0 menu before \n\n -> "
        # for other submenu
        else:
            sentece = f"\n Enter a number between 0 and {n} : "

        try:
            user_n = int(input(sentece))
            if user_n in list(range(0, n+1)):
                return user_n
            else:
                print(f"Error : The number must be between 0 and {n}.")
        except ValueError:
            print("Error : Please enter a valid integer.")



# Function to chech if a user is existing in a domain name
def get_stored_domain_user_name(cursor, domain_name, username):

     # query to retrieve a domain name and a username in the same row
    query = """
        SELECT COUNT(*) 
        FROM my_passwd_mngr
        WHERE domain_name = %s AND username = %s;
    """
                        
    cursor.execute(query, (domain_name, username))
    # False if the domain name and the user aren't existing
    count = cursor.fetchone()[0]

    return count


################################################################################################################
################################################################################################################


# main function
def main():
    
    # the parameters for the database
    hostname = 'localhost'
    database = 'pgpm'
    username = 'postgres'
    #passwd = 'password123'   # replace the password123 by your database's password ,and put this > password = passwd < above the port_id in the next section,
    port_id = 5432

    # counter to limit the number of attempts to enter the master password to 3,
    ptr = 0

    # keys for the encryption and decryption:  (you generate other safe prime p, and other generator g)
    # 768-bit prime
    p = 208351617316091241234326746312124448251235562226470491514186331217050270460481 
    g = 2


    # connect to the database and create the table my_passwd_mngr if it doesn't exist
    try:
        conn = psycopg2.connect(
            host = hostname,
            dbname = database,
            user = username,
            
            port = port_id
        )

        cur = conn.cursor()

        create_script = '''CREATE TABLE IF NOT EXISTS my_passwd_mngr(
                        id      SERIAL PRIMARY KEY,  
                        domain_name    VARCHAR(100) NOT NULL,
                        username  VARCHAR(50) UNIQUE NOT NULL,
                        password_hashed_1 TEXT NOT NULL,
                        password_hashed_2 TEXT NOT NULL)'''

        cur.execute(create_script)
    
        db = conn.commit()


    except Exception as error:
        print(error)

    


    # Ask the user to create a master password and store it in the database
    # or enter the master password if it already exists
    try:

        # verify if the master password already exists in the database by checking if the id 0 exists in the table,
        
        cur.execute("""
            SELECT EXISTS (
                SELECT password_hashed_1
                FROM my_passwd_mngr
                WHERE id = 0
            );
        """)
       
        exists_id_0 = cur.fetchone()[0]  # True ou False

        # if it doesn't exist, ask the user to create a master password and store it in the database,
        if not exists_id_0:

            # to remind the user to create a strong master password
            print("Welcome to your password manager! Let's start by creating your master password, the password you have to remember!")

            while True:
                master_password = ask_new_password()

                res = check_strength_PM(master_password)
                if res == "Strong":
                    break
                else:
                    continue
            
            # hash the master password with bcrypt and salt
            hashed_master_password = bcrypt.hashpw(master_password.encode("utf-8"), bcrypt.gensalt())

            passwd = hashed_master_password.decode("utf-8")

            # Key generation
            x, y = elgamal_keygen(p, g)

            keys = str(x)+ " " + str(y)
            
            
            # store the hashed master password in the database with the id 0, the domain name "Master_Password" and the username "MASTER" and "0" for psswd_2
            cur.execute(
                "INSERT INTO my_passwd_mngr (id, domain_name, username, password_hashed_1, password_hashed_2) VALUES (%s, %s, %s, %s, %s)",
                (0, "Master_Password", "MASTER", passwd, keys)
            )

            conn.commit()

        # if it already exists, ask the user to enter the master password,
        else:
            while True:
            
                # Ask the user to enter the master password
                master_password = getpass("Enter your master password: ")
                # encode to bytes the master password enter by the user
                hashed_master_password = master_password.encode("utf-8")
                
                # retrieve the stored hashed master password from the database
                cur.execute("SELECT password_hashed_1 FROM my_passwd_mngr WHERE id = 0")
                result = cur.fetchone()

                # convert the stored hashed master password to bytes
                stored_hashed_master_password = result[0].encode("utf-8") 


                # compare the master password entered with the stored hashed master password in the database
                if bcrypt.checkpw(hashed_master_password, stored_hashed_master_password):
                    print("Master password is correct. Access granted.")
                    break

                else:
                    # if the user fails to enter the correct master password after 3 attempts, the program will exit
                    if ptr == 2:
                        print("Master password is incorrect. Access denied. Please try again later.")
                        sys.exit()
                
                    else:
                        ptr += 1
                        print("Master password is incorrect. Access denied. Please try again.")

        # inside of the password manager
        print("Welcome to your password manager!")

        # retrieve the keys
        cur.execute("SELECT password_hashed_2 FROM my_passwd_mngr WHERE domain_name = %s AND username = %s", ("Master_Password", "MASTER"))
        resul = cur.fetchone()

        if not resul:
            print(f"Error: Keys not found !.")
            sys.exit()
        
        else:
            x, y = resul[0].split(" ")
            x = int(x)
            y = int(y)


        while True:
            
            # ask the user to choose an option from the 4 menu
            res = ask_user_input(3) 

            # the four options :

            ## exit the program,
            if res == 0:
                sys.exit()


            ## get a password from the database
            elif res == 1:
                # ask the domain name
                domain_name = input("Enter the domain name: ").strip().lower()

                # show the usernames in this domain name
                cur.execute("SELECT username FROM my_passwd_mngr WHERE domain_name = %s", (domain_name,))
                resul = cur.fetchall()

                if not resul:
                    print(f"No domain name '{domain_name}' found.")
                    continue

                print(f"Username(s) for the domain name '{domain_name}':")
                table = PrettyTable()
                table.field_names = ["Username"]
                    
                for row in resul:
                    table.add_row(row)

                print(table)
                # ask the user to choose a username from the list of usernames for this domain name
                username = input("Enter the username: ").strip()

                # retrieve the hashed password for this domain name and username from the database
                cur.execute("SELECT password_hashed_1, password_hashed_2 FROM my_passwd_mngr WHERE domain_name = %s AND username = %s", (domain_name, username))
                resul = cur.fetchone()

                if not resul:
                    print(f"No username '{username}' found in the domain name '{domain_name}'.")
                    continue

                # algorithm to convert the encrypted password to the original password,
                dec = elgamal_decrypt(int(resul[0]), int(resul[1]), p, x)
                txt = decrypt_number(str(dec), decrypt_mapping)                

                
                # copy the password to the clipboard without showing it in the terminal
                pyperclip.copy(txt)
                print("Password has been copied to the clipboard.")


            ## add new password to the database
            elif res == 2:
                # ask to complete the information for the new password to be stored in the database,
                domain_name = input("Enter the domain name: ").strip().lower()
                username = input("Enter the username: ").strip()

                # check if the domain name and the username already exist in the same row in the database, if yes, ask the user to update the password instead of adding a new one,
                count = get_stored_domain_user_name(cur, domain_name, username)
                if count > 0:
                    print(f"The domain name '{domain_name}' and the username '{username}' already exist in the database. Please update the password instead of adding a new one.")
                    continue

                # ask the user to enter the password,
                new_password = ask_new_password()

 ################ ALGO ENCRYPTAGE ################

                seq_num = encrypt_number(new_password, decrypt_mapping)

                c1, c2 = elgamal_encrypt(int(seq_num), p, g, y)
                

                cur.execute(
                    "INSERT INTO my_passwd_mngr (domain_name, username, password_hashed_1, password_hashed_2) VALUES (%s, %s, %s, %s) RETURNING id",
                (domain_name, username, str(c1), str(c2))
                )

                conn.commit()
                print(f"Password for {username} added successfully!")


            ## view the stored domain names and usernames in table format
            # and get the options to update or delete the stored passwords
            else:
                cur.execute("SELECT domain_name,username FROM my_passwd_mngr WHERE id != 0")
                result = cur.fetchall()
                
                # Create a table to display the stored domain names and usernames in a table format
                table = PrettyTable()
                table.field_names = ["Domain name", "Username"]
                    
                for row in result:
                    table.add_row(row)

                print(table)

                print("End of the list of stored domain names.\n")

                while True:

                    # ask the user to choose an option from the 3 menu
                    res2 = ask_user_input(2)

                    # the 3 options from the menu:

                    ## update or modify a password in database
                    if res2 == 1:
                        
                        # ask the user to enter the domain name and the username for the password they want to update in the database
                        domain_name = input("Enter the domain name of the password you want to update: ").strip().lower()
                        username = input("Enter the username of the password you want to update: ").strip()

                        if domain_name == "" or username == "":
                            print("Domain name and username cannot be empty. Please try again.")
                            continue
                        
                        # don't show in the menu, but the user can update the master password by entering "master_password" as the domain name and "master" as the username,
                        """
                        elif domain_name == "master_password" or username == "master":
                            domain_name = "Master_Password"
                            username = "MASTER"

                            print("Let's change your master password, the password you have to remember!")

                            # ask the user to create a new master password and store it in the database
                            password = MP_creation_verification(conn, cur)
                            #  check if return commit is work

                            print("Master password has been updated successfully!")
                            
                            break
                        """

                        count = get_stored_domain_user_name(cur, domain_name, username)
                        
                        if count > 0:
                            print(f"The password for the domain name '{domain_name}' and the username '{username}' is going to be updated!")
                            
                        else:
                            print(f"The domain '{domain_name}' and username '{username}' are not found in the same row, so not existed.")
                            break

                         # ask the user to enter the new password
                        new_password = ask_new_password()

                        # algorithm to encrypting the new password
                        seq_num = encrypt_number(new_password, decrypt_mapping)

                        c1, c2 = elgamal_encrypt(int(seq_num), p, g, y)    

                        # update the password in the database
                        cur.execute("UPDATE my_passwd_mngr SET password_hashed_1 = %s, password_hashed_2 = %s WHERE domain_name = %s AND username = %s", (c1, c2, domain_name, username))
                       
                        conn.commit()
                        print(f"Password for {username} in the domain name '{domain_name}' has been updated successfully!")

                        # to stay in submenu
                        continue

                    ## delete a content in the database
                    elif res2 == 2:
                        
                        # ask the user to enter the domain name and the username for the password they want to delete from the database
                        domain_name = input("Enter the domain name of the password you want to delete: ").strip().lower()
                        username = input("Enter the username of the password you want to delete: ").strip()

                        # check if the domain name and the username exist in the same row in the database
                        count = get_stored_domain_user_name(cur, domain_name, username)
                        if count == 0:
                            print(f"The domain name '{domain_name}' and the username '{username}' are not found in the same row, so not existed.")
                            continue

                        # delete the password from the database
                        cur.execute("DELETE FROM my_passwd_mngr WHERE domain_name = %s AND username = %s", (domain_name, username))
                        conn.commit()
                        print(f"Password for {username} in the domain name '{domain_name}' has been deleted successfully!")

                    ## return to the main menu
                    else:
                        break

    
    except Exception as error:
        print(error)

    finally:
        if cur:
            cur.close()

        if conn:
            conn.close()




################################################################################################################


# execute the main function when the script is run
if __name__ == "__main__":
    main()



