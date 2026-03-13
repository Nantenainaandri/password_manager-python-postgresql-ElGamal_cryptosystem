###########################################################################################################################################################################POSTGRESQL############################################################################################################################################################################################

# importation (postgresql)
import psycopg2

hostname = 'localhost'
database = 'demo'
username = 'postgresql'
passwd = 'admin'
port_id = 5432

conn = None
cur = None  # no need with thew best code

try:
    """
    BEST CODE: open and close, with close; no need to close manually cursor, BUT YOU NEED TO CLOSE THE CONNECTION manually
    with psycopg2.connect(...) as conn:
        with cursor.connect() as cur:
            ALL PROGRAMMS
            NO NEED commit



            # creation the user i.e. create a database if it doesn't exist
def create_user_MP():
    mp = getpass("MASTER PASSWORD: ")
    hashed_mp = hashlib.sha256(mp.encode()).hexdigest()

    try:
        with psycopg2.connect(
            host = hostname,
            dbname = database,
            user = username,
            password = passwd,
            port = port_id
        ) as conn:
            with conn.cursor() as cur:
                create_script = '''CREATE TABLE IF NOT EXISTS my_passwd_mngr(
                        id      int PRIMARY KEY,  # order from 1
                        domain_name    varchar(40) NOT NULL,
                        username  varchar(35),
                        password_hashed varchar(30))'''

                cur.execute(create_script)


    except Exception as error:
        print(error)


    finally:    # have error or not, this is always excecuting to close the connection with database

        if conn is not None:
            conn.close()

            







            try:
                res = int(input("\n 1 get a password \n 2 add new passwords\n 3 view your stored domain names (update/delete)\n 0 exit program \n\n ->"))
            
                if res not in [0, 1, 2, 3]:
                    print("Invalid input. Please enter a number between 0 and 3.")
                    continue
                else:
                    res = res # return res (in function)
                
            except ValueError:
                print("Invalid input. Please enter a number between 0 and 3.")




                    try:
                        res = int(input("\n 1 update \n 2 delete \n 0 menu before \n\n -> "))

                        if res not in [0, 1, 2]:
                            print("Invalid input. Please enter a number between 0 and 2.")
                            continue
                        else:
                            res = res # return res (in function)

                    except ValueError:
                        print("Invalid input. Please enter a number.")




    """
    conn = psycopg2.connect(
        host = hostname,
        dbname = database,
        user = username,
        password = passwd,
        port = port_id
    )

    cur = cursor.connect()      # = cursor.connect(cursor_factory=psycopg2.extra.DictCursor)

    # for insert_values
    cur.execute(DROP TABLE IF EXISTS employee)

    create_script = '''CREATE TABLE IF NOT EXISTS employee(
                        id      int PRIMARY KEY,
                        name    varchar(40) NOT NULL,
                        salary  int,
                        dept_id varchar(30))'''

    cur.execute(create_script)

    insert_script = '''INSERT INTO employee (id, name, salary, dept_id) VALUES (%s, %s, %s, %s)'''
    #insert_value = (1, 'James', 1200, 'D1')
    insert_values = [(1, 'James', 1200, 'D1'), (5, 'Daniel', 1250, 'D3'), (42, 'Jeremy', 2200, 'D8')]
    #cur.execute(insert_script, insert_value)
    for record in insert_values:
        cur.execute(insert_script, record)

    cur.execute('SELECT * FROM EMLPOYEE')
    for record in  cur.fetchall():
        print(record[1], record[2])     #for access to column's name(record['name']), you have to import psycopg2.extra and cursor.connect(cursor_factory=psycopg2.extra.DictCursor)

    update_script = 'UPDATE employee SET salary = salary + (salary * 0.5)'
    cur.execute(update_script)


    delete_script = 'DELETE FROM employee WHERE name = %s'
    delete_record = ('Daniel',)
    cur.execute(delete_script, delete_record)

    cur.commit()


except Exception as error:
    print(error)


finally:    # have error or not, this is always excecuting
    if cur is not None:
        cur.close()

    if conn is not None:
        conn.close()




###########################################################################################################################################################################SQLITE3##############################################################################################################################################################################################

# import sqlite3 for create database
import sqlite3

""""
# create the db if it isn't exist or connect if the db was exist
connection = sqlite3.connect('my_database.db')

# CURSOR : like an interface to execute query in the db
# connect or get the CURSOR   , we need to deconnect it
cursor = connection.cursor()
"""



class Person:

    def __init__(self, id_nbr=-1, first="", last="", age=-1):
        self.id_nbr = id_nbr
        self.first = first
        self.last = last
        self.age = age
        self.connection = sqlite3.connect('my_database.db')
        self.cursor = self.connection.cursor()

    # unique for each Person
    def load_person(self, id_nbr):
        self.cursor.execute("""
        SELECT * FROM persons
        WHERE id_nbr = []
        """.format(id_nbr))

        # to get the results
        results = cursor.fetchone()

        #
        self.id_nbr = id_nbr
        self.first = results[1]
        self.last = results[2]
        self.age = results[3]


    def insert_person(self):
        self.cursor.execute("""
        INSERT TO persons VALUES
        ([], '[]', '[]', [])        # specify with "" if it is a string
        """.format(self.id_nbr, self.first, self.last, self.age))

        self.connection.commit()
        self.connection.close()


#=================================================================================================
# # the db already exists so we comment this section
# # execute query with cursor
# cursor.execute(""""  # the query code here, SQL statement
# CREATE TABLE IF NOT EXISTS persons(    # IF NOT EXISTS for not having an error when the table name exist
#     id_nbr INTEGER PRIMARY KEY,   # unicity
#     first_name TEXT,  #or VARCHAR(32)
#     last_name TEXT,
#     age INTEGER
# )
# """)
#
# # other query to insert variable in the table
# cursor.execute("""
# INSERT INTO persons VALUES
# (1, 'Paul', 'Smith', 24),
# (2, 'Mark', 'Jonhson', 45),
# (3, 'Anna', 'Smith', 33)
# """)
#
# # select
# cursor.execute("""
# SELECT * FROM pesrons
# WHERE last_name = 'Smith'
# """)
#
# #to have the results
# rows = cursor.fetchall()
#
#
# # commit the query to the database
# connection.commit()
#
# # CLOSE the connection
# connection.close()

#======================================================================================================================

# load person from the db already existed
p1 = Person()
p1.load_person(1)
print(p1.first, p1.last, p1.age, p1.id_nbr)


# insert s new person to the db
p2 = (7, 'Paul', 'Pascal', 54)
p2.insert_person()

# create the db if it isn't exist or connect if the db was exist
connection = sqlite3.connect('my_database.db')

# connect or get the CURSOR   , we need to deconnect it
cursor = connection.cursor()

cursor.execute("SELECT * FROM persons")
results = cursor.fetchall()
print(results)

connection.close()
