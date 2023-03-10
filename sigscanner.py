#! /usr/bin/env python
import sqlite3
import pathlib
import hashlib
import datetime
import sys
import os
import requests
import json
from pathlib import Path
from sqlite3 import Error
from dotenv import load_dotenv


dotenv_path = Path(".env")
load_dotenv(dotenv_path=dotenv_path)

MALWARE_BAZAAR_API_KEY = os.getenv("MALWARE_BAZAAR_API_KEY")

COLOUR = {
    "HEADER": "\033[95m",
    "BLUE": "\033[94m",
    "GREEN": "\033[92m",
    "RED": "\033[91m",
    "YELLOW": "\033[93m",
    "ENDC": "\033[0m",
}


# Database class
class database:
    def __init__(self, name, table):
        self.name = name
        self.table = table

    def exists(self):
        # Check database exists
        print(f"Checking for database: {self.name}")
        file = Path(f"./{self.name}")  # Create database Path object

        if file.is_file():  # Check database exists in path
            print(f"{COLOUR['GREEN']}Database {self.name} exists.{COLOUR['ENDC']}")
            return True
        else:
            print(
                f"{COLOUR['YELLOW']}Database {self.name} does NOT exist. Trying to create.{COLOUR['ENDC']}"
            )
            if database.create(self):
                return True
            return False

    def create(self):
        try:
            print("Creating database")
            conn = sqlite3.connect(self.name)  # Try to open database
            conn.close()  # Close connection
            if database.create_tables(self):
                print(
                    f"{COLOUR['GREEN']}Database {self.name} successfully created{COLOUR['ENDC']}"
                )
                return True
        except:
            print(f"{COLOUR['RED']}Database {self.name} not formed.{COLOUR['ENDC']}")
            return False

    def create_tables(self):
        print(f"Creating table: {self.table.upper()}")
        db = database.connect(self)
        print("Creating cursor")
        cursor = db.cursor()  # Create database cursor
        # Drop table if it exists (Flush)
        try:
            cursor.execute(f"DROP TABLE IF EXISTS {self.table.upper()}")
        except:
            print(
                f"{COLOUR['RED']}Error query: DROP TABLE IF EXISTS {self.table.upper()}{COLOUR['ENDC']}"
            )

        # Create new table
        try:
            create_table = f""" CREATE TABLE {self.table.upper()} (
            file_name VARCHAR(255) NOT NULL,
            sha256_hash VARCHAR(255) NOT NULL,
            submission_date TIMESTAMP NOT NULL,
            malware VARCHAR(255) NOT NULL
        ); """
            cursor.execute(create_table)
            print(
                f"{COLOUR['GREEN']}Table {self.table.upper()} successfully created{COLOUR['ENDC']}"
            )
            return True
        except:
            print(
                f""" CREATE TABLE {self.table.upper()} (
            file_name VARCHAR(255) NOT NULL,
            sha256_hash VARCHAR(255) NOT NULL,
            submission_date VARCHAR(255) NOT NULL,
            malware VARCHAR(255) NOT NULL
        ); """
            )

    def connect(self):
        try:
            conn = sqlite3.connect(self.name)

            print(f"{COLOUR['GREEN']}Connected to database{COLOUR['ENDC']}")
            return conn
        except:
            print(f"{COLOUR['RED']}Connection failed{COLOUR['ENDC']}")

    def insert_query(self, query):
        db = database.connect(self)
        cursor = db.cursor()
        insert = f"""INSERT INTO {self.table.upper()}
    VALUES (?, ?, ?, ?);"""
        tuple = (
            query["file_name"],
            query["file_hash"],
            query["file_date"],
            query["malware"],
        )
        cursor.execute(insert, (tuple))
        db.commit()
        print("Committed successfully")

    def value_exists(self, field, value):
        db = database.connect(self)
        cursor = db.cursor()
        insert = f"""SELECT IFF ( {field.upper()} == {value.upper()}, TRUE, FALSE ) * FROM {self.table.upper()};"""
        cursor.execute(insert)
        result = cursor.fetchall()
        print(result)

    def hash_exists(self, field, value):
        # return False
        # Check hash exists in database
        print("Checking database for duplicate hash")
        db = database.connect(self)
        cursor = db.cursor()
        insert = cursor.execute(
            "SELECT * FROM LOCAL_HASHES WHERE sha256_hash=?", (value,)
        )
        rows = cursor.fetchall()
        for row in rows:
            return True
        return False


def hash_file(filename):
    hash = hashlib.sha256()
    with open(filename, "rb") as file:
        while True:
            chunk = file.read(hash.block_size)
            if not chunk:
                break
            hash.update(chunk)
    return hash.hexdigest()


def query_malware_bazaar(filename, sha_256_hash):
    data = {"query": "get_info", "hash": sha_256_hash}
    response = requests.post(f"https://mb-api.abuse.ch/api/v1/", data=data)
    response_data = response.json()
    if response_data["query_status"] == "ok":
        filedata = {
            "file_name": filename,
            "file_hash": sha_256_hash,
            "file_date": datetime.datetime.now(),
            "malware": "True",
        }
        insert_file(filename, filedata)
        print(
            f"{COLOUR['RED']}File {filename} found in Malware Bazaar database.{COLOUR['ENDC']}"
        )
        print(
            f"{COLOUR['RED']}File scanned\nNAME: {filedata['file_name']}\nSHA_256: {filedata['file_hash']}\nDate: {filedata['file_date']}\nMalware: {filedata['malware']}{COLOUR['ENDC']}"
        )
    else:
        filedata = {
            "file_name": filename,
            "file_hash": sha_256_hash,
            "file_date": datetime.datetime.now(),
            "malware": "False",
        }
        insert_file(filename, filedata)
        print(
            f"{COLOUR['GREEN']}File {filename} not found in Malware Bazaar database.{COLOUR['ENDC']}"
        )
        print(
            f"{COLOUR['GREEN']}File scanned\nNAME: {filedata['file_name']}\nSHA_256: {filedata['file_hash']}\nDate: {filedata['file_date']}\nMalware: {filedata['malware']}{COLOUR['ENDC']}"
        )


def insert_file(filename, filedata):
    print(filedata)
    # local_database.value_exists("sha256_hash",filedata['file_hash'])
    local_database.insert_query(filedata)
    return True


def scan_file(filename):
    sha_256_hash = hash_file(filename)
    if local_database.hash_exists("sha256_hash", str(sha_256_hash)):
        print(f"{COLOUR['BLUE']}Already in database, skipping{COLOUR['ENDC']}")
    else:
        query_malware_bazaar(filename, sha_256_hash)


def current_dir_scan(target):
    print("Scanning current directory")
    arr_files = os.listdir(target)
    for i in range(len(arr_files)):
        print("Scanning file: " + arr_files[i])
        if Path(arr_files[i]).is_dir():
            print("Ignore directory: ", arr_files[i])
        else:
            scan_file(target + "/" + arr_files[i])


def recursive_dir_scan():
    for root, dirs, files in os.walk("./", topdown=False):
        for filename in files:
            print("Scanning file: " + os.path.join(root, filename))
            scan_file(os.path.join(root, filename))
        for dirname in dirs:
            print("Scanning directory: " + dirname)


# Main function
if __name__ == "__main__":
    local_database_name = "local_database.db"
    local_database = database(local_database_name, "LOCAL_HASHES")
    print(f"Initialising local hash database: {local_database_name}")
    if not local_database.exists():
        local_database.create()

    if len(sys.argv) > 1:
        # Scan current directory
        if sys.argv[1] == "-dirscan":
            # Check recursive flag
            current_dir_scan("./")
            if ((sys.argv[2]) == "-r") and len(sys.argv) >= 2:
                recursive_dir_scan()

        # Scan single file
        elif ((sys.argv[1]) == "-scan") and len(sys.argv) > 2:
            scan_file(sys.argv[2])
        else:
            print("Invalid command line arguments")
    else:
        print("Supply command line arguments")

## TO DO: 
#
#   Change file executable status if categorised as malware
#