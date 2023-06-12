import os
import re
import sys
import json
import base64
import sqlite3
import shutil
import csv
from Cryptodome.Cipher import AES
import keyring

# GLOBAL CONSTANT
CHROME_PATH_LOCAL_STATE = os.path.expanduser("~/.config/google-chrome/Local State")
CHROME_PATH = os.path.expanduser("~/.config/google-chrome")

def get_secret_key():
    try:
        # (1) Get secret key from Chrome local state
        with open(CHROME_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        # Remove suffix DPAPI
        secret_key = secret_key[5:]
        secret_key = keyring.win32CryptoCryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except Exception as e:
        print("%s" % str(e))
        print("[ERR] Chrome secret key cannot be found")
        return None
        
if __name__ == '__main__':
    try:
        #Create Dataframe to store passwords
        with open('decrypted_password.csv', mode='w', newline='', encoding='utf-8') as decrypt_password_file:
            csv_writer = csv.writer(decrypt_password_file, delimiter=',')
            csv_writer.writerow(["index","url","username","password"])
            #(1) Get secret key
            secret_key = get_secret_key()
            #Search user profile or default folder (this is where the encrypted login password is stored)
            folders = [element for element in os.listdir(CHROME_PATH) if re.search("^Profile*|^Default$",element)!=None]
            for folder in folders:
            	#(2) Get ciphertext from sqlite database
                chrome_path_login_db = os.path.normpath(r"%s\%s\Login Data"%(CHROME_PATH,folder))
                conn = get_db_connection(chrome_path_login_db)
                if(secret_key and conn):
                    cursor = conn.cursor()
                    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                    for index,login in enumerate(cursor.fetchall()):
                        url = login[0]
                        username = login[1]
                        ciphertext = login[2]
                        if(url!="" and username!="" and ciphertext!=""):
                            #(3) Filter the initialisation vector & encrypted password from ciphertext 
                            #(4) Use AES algorithm to decrypt the password
                            decrypted_password = decrypt_password(ciphertext, secret_key)
                            print("Sequence: %d"%(index))
                            print("URL: %s\nUser Name: %s\nPassword: %s\n"%(url,username,decrypted_password))
                            print("*"*50)
                            #(5) Save into CSV 
                            csv_writer.writerow([index,url,username,decrypted_password])
                    #Close database connection
                    cursor.close()
                    conn.close()
                    #Delete temp login db
                    os.remove("Loginvault.db")
    except Exception as e:
        print("[ERR] "%str(e))
        
        
