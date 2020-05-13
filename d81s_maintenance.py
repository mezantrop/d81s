#!/usr/bin/python3
# -*- coding: utf-8 -*-

# ------------------------------------------------------------------------------
# Deck 8 One Step - Maintenance utility
# ------------------------------------------------------------------------------

import configparser

import mysql.connector
from mysql.connector import errorcode

import time

# ------------------------------------------------------------------------------
# Connect with the MySql Database
# ------------------------------------------------------------------------------
def connect_db(host, database, user, password):
    try:
        cnx = mysql.connector.connect(host=host, database=database,
                                      user=user, password=password)

    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print(time.ctime(time.time()) + ":",
                "Fatal: Wrong DB user/password specified in the INI-file")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print(time.ctime(time.time()) + ":",
                "Fatal: Database does not exists")
        else:
            print(err)

    return cnx


# ------------------------------------------------------------------------------
# Read configuration parameters from the INI-file
# Gets the 'ini-filename' as the parameter, returns the 'config' object
# ------------------------------------------------------------------------------
def read_ini(inifile):

    config = configparser.ConfigParser()
    if inifile not in config.read(inifile):
        print(time.ctime(time.time()) + ":", "Fatal: Unable to find INI-file")
        exit(1)

    # Read the [MAINTENANCE] section
    if 'MAINTENANCE' in config.sections():
        if not config['MAINTENANCE']['sessions_storage_depth']:
            print(time.ctime(time.time()) + ":",
                  "Fatal: Missing [MAINTENANCE][essions_storage_depth] variable of the INI-file")
            exit(1)
    else:
        print(time.ctime(time.time()) + ":",
              "Fatal: [MAINTENANCE] section is NOT present in the INI-file")
        exit(1)

    # Fetch variables of the [DATABASE] section or die
    if 'DATABASE' in config.sections():
        if not config['DATABASE']['host']:
            print(time.ctime(time.time()) + ":",
                  "Fatal: Missing [DATABASE][host] variable of the INI-file")
            exit(1)
        if not config['DATABASE']['database']:
            print(time.ctime(time.time()) + ":",
                  "Fatal: Missing [DATABASE][database] variable of the INI-file")
            exit(1)
        if not config['DATABASE']['user']:
            print(time.ctime(time.time()) + ":",
                  "Fatal: Missing [DATABASE][user] variable of the INI-file")
            exit(1)
        if not config['DATABASE']['password']:
            print(time.ctime(time.time()) + ":",
                  "Fatal: Missing [DATABASE][password] variable of the INI-file")
            exit(1)
    else:
        print(time.ctime(time.time()) + ":",
              "Fatal: [DATABASE] section is NOT present in the INI-file")
        exit(1)

    return config


# ------------------------------------------------------------------------------
# Connect to the database and delete old records based on the 
# "sessions_storage_depth" value from the INI-file
# ------------------------------------------------------------------------------
def delete_old_sessions(sessions_storage_depth):
    cnx = connect_db(config['DATABASE']['host'], config['DATABASE']['database'],
                     config['DATABASE']['user'], config['DATABASE']['password'])
    cursor = cnx.cursor()

    delete_sessions = ("DELETE FROM `d81s`.`sessions` "
                            "WHERE `session_id` < "
                                "(SELECT min(s1.session_id) FROM "
                                    "(SELECT session_id FROM d81s.sessions "
                                        "ORDER BY session_id DESC LIMIT " + sessions_storage_depth + " ) "
                                    "as s1)")
    cursor.execute(delete_sessions, "")
    cnx.commit()

    cursor.close()
    cnx.close()


# ------------------------------------------------------------------------------
# Deck 8 One Step - Maintenance utility - main()
# ------------------------------------------------------------------------------
print(time.ctime(time.time()) + ":", "Starting Maintenance")

# Read INI-file
print(time.ctime(time.time()) + ":", "Read INI-file")
config = read_ini('d81s.ini')

print(time.ctime(time.time()) + ":", "Deleting old sessions: Start")
delete_old_sessions(config['MAINTENANCE']['sessions_storage_depth'])
print(time.ctime(time.time()) + ":", "Deleting old sessions: End")

print(time.ctime(time.time()) + ":", "Rest Avatar, you need it")
exit(0)

