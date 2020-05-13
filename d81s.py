#!/usr/bin/python3
# -*- coding: utf-8 -*-

# ------------------------------------------------------------------------------
# Deck 8 One Step - Main Explorer
# ------------------------------------------------------------------------------

import threading
import configparser
import re

import mysql.connector
from mysql.connector import errorcode

import paramiko

import base64
import http.client
import xml.etree.ElementTree as ET

import subprocess

import time

# ------------------------------------------------------------------------------
# Default variables (Overrided by INI-file)
# ------------------------------------------------------------------------------
db_connections_limit = 32


# ------------------------------------------------------------------------------
# Execute a command via SSH and read results
# ------------------------------------------------------------------------------
def ssh_exec(host, user, password, port, command):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, username=user, password=password, port=port)
    stdin, stdout, stderr = client.exec_command(command)

    data = stdout.read()
    # TO-DO: Check error = stderr.read() for errors
    client.close()
    
    try:
        data = data.decode('utf-8')
    except UnicodeDecodeError:
        data = data.decode('cp1251')

    return data


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
# Gets the field 'what' from the 'table' where the 'key' like 'value' 
# SELECT %1 FROM %2 WHERE %3 LIKE "$%" LIMIT 1;
# ------------------------------------------------------------------------------
def get_valbykey(cursor, session_id, what, table, key, value):

    select = ("SELECT " + what + 
              " FROM " + table + 
              " WHERE session_id=" + str(session_id) + 
              " AND " + str(key) + 
              " LIKE %s LIMIT 1")

    cursor.execute(select, (value,))

    try:
        return tuple(cursor)[0][0]
    except IndexError:
        return 'NULL'


# ------------------------------------------------------------------------------
# Insert the new row to the 'sources' table 
# ------------------------------------------------------------------------------
def insert_source(cursor, session_id, explorer, host, login, password, proto, 
                  port, url):

    add_source = ("INSERT INTO sources "
                  "(session_id, explorer, host, login, password, proto, "
                  "port, url) "
                  "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)")

    data_source = (session_id, explorer, host, login, password, 
                   proto, port, url)
    cursor.execute(add_source, data_source)

    return cursor.lastrowid


# ------------------------------------------------------------------------------
# Connect with Hitachi Command Suite (HDVM) to send XML Request and get Response
# ------------------------------------------------------------------------------
def hdvm_getstoragearray(host, login, password, request, serial, arraytype):
    b64lp = base64.b64encode((login + ':' + password).encode('ascii'))

    headers = {'Content-Type': 'text/xml',
               'User-Agent': 'Deck Eight:One Step:0',
               'Authorization': 'Basic ' + b64lp.decode('utf-8')}

    body_up = """\
<?xml version="1.0" encoding="UTF-8"?>
<HiCommandServerMessage>
    <APIInfo version="7.1" />
        <Request>
               <StorageManager>
"""

    body_down = """\
                </StorageManager>
        </Request>
</HiCommandServerMessage>"""

    if request == 'GetAllArrays':
        body_middle = """\
                    <Get target="StorageArray" option="all">
                        <StorageArray />
                    </Get>
"""
    elif request == 'GetArray_LUNs':
        body_middle = """\
                    <Get target="StorageArray">
                        <StorageArray objectID="ARRAY.""" + arraytype + """.""" + serial + """">
                            <LogicalUnit>
                                <Filter>
                                    <Condition type="ALL" />
                                </Filter>
                                <Path>
                                    <HostInfo />
                                    <WorldWideName />
                                </Path>
                            </LogicalUnit>
                        </StorageArray>
                    </Get>
"""
    elif request == 'GetArray_Ports':
        body_middle = """\
                    <Get target="StorageArray">
                        <StorageArray objectID="ARRAY.""" + arraytype + """.""" + serial + """">
                            <Port>
                                <HostStorageDomain />
                            </Port>
                        </StorageArray>
                    </Get>
"""
    elif request == 'GetArray_RGs':
         body_middle = """\
                    <Get target="StorageArray">
                        <StorageArray objectID="ARRAY.""" + arraytype + """.""" + serial + """">
                            <ArrayGroup />
                        </StorageArray>
                    </Get>

"""
    elif request == 'GetArray_Pools':
        body_middle = """\
                    <Get target="StorageArray">
                        <StorageArray objectID="ARRAY.""" + arraytype + """.""" + serial + """">
                            <JournalPool />
                        </StorageArray>
                    </Get>
"""

    elif request == 'GetArray_LDEVs':
        body_middle = """\
                    <Get target="StorageArray">
                        <StorageArray objectID="ARRAY.""" + arraytype + """.""" + serial + """">
                            <LDEV>
                                <ObjectLabel />
                            </LDEV>
                        </StorageArray>
                    </Get>
"""


    body = body_up + body_middle + body_down

    httpc = http.client.HTTPConnection(host, 2001, timeout = 120)
    httpc.request('POST', '/service/ServerAdmin', body, headers)
    resp = httpc.getresponse()
    
    data = resp.read()
    data = data.decode('utf-8')

    httpc.close()

    return data


# ------------------------------------------------------------------------------
# Split the string 'ln' by colon and return the second part
# ------------------------------------------------------------------------------
def split_colon(ln):
    return ln.split(':')[1].strip()


# ------------------------------------------------------------------------------
# Normalize WWNs format: 50014380029FD42A > 50:01:43:80:02:9f:d4:2a
# ------------------------------------------------------------------------------
def wwn_up2brocade(raw_wwn):

    return ':'.join([raw_wwn[x:x+2] for x in range(0, len(raw_wwn), 2)]).lower()


# ------------------------------------------------------------------------------
# Read configuration parameters from the INI-file
# Gets the 'ini-filename' as the parameter, returns the 'config' object
# ------------------------------------------------------------------------------
def read_ini(inifile):
    global sources_bfcs
    global sources_hdvm
    global sources_3par
    global sources_ibts
    global sources_heva

    config = configparser.ConfigParser()
    if inifile not in config.read(inifile):
        print(time.ctime(time.time()) + ":", "Fatal: Unable to find INI-file")
        exit(1)

    # Read the [SOURCES] section
    if 'SOURCES' in config.sections():
        # Parse and save BFCS Sources configuration
        sources_bfcs = []
        try:
            for ln in config['SOURCES']['BFCS'].splitlines():
                fields = re.split("[ \t]+", ln)
                sources_bfcs.append(dict(host=fields[0],
                                         login=fields[1],
                                         password=fields[2]))
        except(IndexError, KeyError):
            print(time.ctime(time.time()) + ":",
                "Fatal: Unable to process [SOURCES][BFCS] value of the INI-file")
            exit(1)

        # Parse and save HDVM Sources configuration
        sources_hdvm = []
        try:
            for ln in config['SOURCES']['HDVM'].splitlines():
                fields = re.split("[ \t]+", ln)
                sources_hdvm.append(dict(host=fields[0],
                                         login=fields[1],
                                         password=fields[2]))
        except(IndexError, KeyError):
            print(time.ctime(time.time()) + ":",
                "Fatal: Unable to process [SOURCES][HDVM] value of the INI-file")
            exit(1)

        # Parse and save 3PAR Sources configuration
        sources_3par = []
        try:
            for ln in config['SOURCES']['3PAR'].splitlines():
                fields = re.split("[ \t]+", ln)
                sources_3par.append(dict(host=fields[0],
                                         login=fields[1],
                                         password=fields[2]))
        except(IndexError, KeyError):
            print(time.ctime(time.time()) + ":",
                "Fatal: Unable to process [SOURCES][3PAR] value of the INI-file")
            exit(1)

        # Parse and save IBTS (IBM TS Tape Libraries) Sources configuration
        sources_ibts = []
        try:
            for ln in config['SOURCES']['IBTS'].splitlines():
                fields = re.split("[ \t]+", ln)
                sources_ibts.append(dict(host=fields[0], model=fields[1]))
        except(IndexError, KeyError):
            print(time.ctime(time.time()) + ":",
                "Fatal: Unable to process [SOURCES][IBTS] value of the INI-file")
            exit(1)

        # Parse and save HEVA Sources configuration
        sources_heva = []
        try:
            for ln in config['SOURCES']['HEVA'].splitlines():
                fields = re.split("[ \t]+", ln)
                sources_heva.append(dict(host=fields[0],
                                         login=fields[1],
                                         password=fields[2]))
        except(IndexError, KeyError):
            print(time.ctime(time.time()) + ":",
                "Fatal: Unable to process [SOURCES][HEVA] value of the INI-file")
            exit(1)

        if not config['TOOLS']['sssu']:
            print(time.ctime(time.time()) + ":",
                 "Fatal: Unable to process [TOOLS][sssu] value of the INI-file")
            exit(1)

    else:
        print(time.ctime(time.time()) + ":",
              "Fatal: [SOURCES] section is NOT present in the INI-file")
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
# Start the new discovery session
# Returns the Session ID
# ------------------------------------------------------------------------------
def start_session():
    # Connect with the database
    cnx = connect_db(config['DATABASE']['host'], config['DATABASE']['database'],
                     config['DATABASE']['user'], config['DATABASE']['password'])
    cursor = cnx.cursor()

    add_session = ("INSERT INTO sessions (time_start, state) VALUES (now(), 1)")
    cursor.execute(add_session, "")
    session_id = cursor.lastrowid
    cnx.commit()

    cursor.close()
    cnx.close()

    return session_id


# ------------------------------------------------------------------------------
# End the discovery session
# ------------------------------------------------------------------------------
def end_session():
    # Connect with the database
    cnx = connect_db(config['DATABASE']['host'], config['DATABASE']['database'],
                     config['DATABASE']['user'], config['DATABASE']['password'])
    cursor = cnx.cursor()

    session = ("UPDATE sessions SET time_end=now(), state=%s WHERE session_id=%s")
    data_session = (0, session_id)
    cursor.execute(session, data_session)
    cnx.commit()

    cursor.close()
    cnx.close()

    return session_id


# ------------------------------------------------------------------------------
# Scan BFCS-sources for the Fabrics and fill in the appropriate tables 
# 1: Fabric. Create the fabric entry in the database ('bfcf'-table) then
#    populate the 'bfcf-members'-table with all fabric members;
# 2: Zoning. Get from the source BFCS-switch and store in the database zoning
#    information for the fabric;
# 3: Name Service. Scan the fabric name service for the active device WWNs 
#    and store them within database.
# ------------------------------------------------------------------------------
def explore_bfcs(scr_bfcs):

    # Open connection with the database
    cnx = connect_db(config['DATABASE']['host'], config['DATABASE']['database'],
                     config['DATABASE']['user'], config['DATABASE']['password'])
    cursor = cnx.cursor()

    print(time.ctime(time.time()) + ":",
          "Debug: BFCS:", scr_bfcs['host']+":", "Start scan")

    # Add the source for the current BFCF/BFCS discovery
    source_id_bfcs = insert_source(cursor, session_id, 'BFCS', scr_bfcs['host'],
                                   scr_bfcs['login'], scr_bfcs['password'],
                                   'SSH', '22', 'NA')
    cnx.commit()

    # - 1: Fabric --------------------------------------------------------------

    print(time.ctime(time.time()) + ":",
          "Debug: BFCS:", scr_bfcs['host']+":", "Fabric")

    # Get the 'fabricshow' output from the switch
    fshow_raw = ssh_exec(host=scr_bfcs['host'],
                         user=scr_bfcs['login'],
                         password=scr_bfcs['password'],
                         port=22,
                         command='fabricshow')

    # Split fabricshow output into lines and parse fields
    fabricshow = []
    principal_wwn = 'NULL'
    fabric_name = ''
    for ln in fshow_raw.splitlines():
        if 'fffc' in ln:                                # Found the fabric switch
            is_principal = 0
            
            fields = re.split("[ \t]+", ln.lstrip())    # Parse the fields
            switch_name = fields[5].strip('"')
            if '>' in switch_name:                      # Principal switch detection
                is_principal = 1
                switch_name = switch_name.lstrip('>"')
                # Save the Principal switch info
                principal_name = switch_name            # Principal switchname
                principal_wwn = fields[2]               # Principal WWN
                principal_domain = fields[0].rstrip(':')# Principal Domain ID
                principal_ip = fields[3]                # Principal IP address

            fabricshow.append(dict(did_dec = fields[0].rstrip(':'), # Remove ':' from the DID field
                                   did_hex = fields[1],             # Switch address in hex 
                                   wwn = fields[2],                 # Switch WWN
                                   ip = fields[3],                  # Switch IP
                                   name = switch_name,              # Switch name
                                   principal = is_principal))       # Principal switch marker

        if 'Fabric Name:' in ln:                # Save the name of the Fabric ...
            fabric_name = re.split(": ", ln)[1]
            fabricname_on = 1
    
    if fabric_name == '':                       # ... or let it be the name
        fabric_name = principal_name            # of principal switch

    # Search for the Fabric entry in the BFCF table of the database
    bfcf_id = get_valbykey(cursor, session_id, 'bfcf_id', 'bfcf', 
                                'principal_wwn', principal_wwn)

    if bfcf_id != 'NULL':
    # This fabric is already exists in the database
        print(time.ctime(time.time()) + ":",
              "Info: Skip the Fabric: " + 
              principal_wwn + ": it is already exists in the database")
        return 0
#        continue

    if principal_wwn == 'NULL':
        # We did not detected Fabric
        print(time.ctime(time.time()) + ":",
              "Info: Skip Fabric exploration of the Source", 
              scr_bfcs['host'], ": unable to detect Principal switch")
        return 0
#        continue

    # Add the new Fabric to the 'bfcf' table
    add_bfcf = ("INSERT INTO bfcf "
                    "(session_id, source_id, principal_wwn, principal_domain, "
                    "principal_ip, principal_name, fabric_name) "
                "VALUES "
                    "(%s, %s, %s, %s, %s, %s, %s)")

    data_bfcf = (session_id, source_id_bfcs, principal_wwn, principal_domain,
                 principal_ip, principal_name, fabric_name)
    cursor.execute(add_bfcf, data_bfcf)

    cnx.commit()

    # Save the new Fabric ID 
    bfcf_id = cursor.lastrowid

    # Fill in Brocade Fabric Member switches - 'bfcf_members' table
    for fab_bfcs in fabricshow:
        add_bfcf_members = ("INSERT INTO bfcf_members "
                                "(bfcf_id, domain, switchid, wwn, ip, name, "
                                "principal) "
                            "VALUES "
                                "(%s, %s, %s, %s, %s, %s, %s)")
        data_bfcf_members = (bfcf_id, fab_bfcs['did_dec'], fab_bfcs['did_hex'], 
                             fab_bfcs['wwn'], fab_bfcs['ip'], fab_bfcs['name'], 
                             fab_bfcs['principal'])
        cursor.execute(add_bfcf_members, data_bfcf_members)

    cnx.commit()

    # - 2: Zoning --------------------------------------------------------------

    print(time.ctime(time.time()) + ":",
          "Debug: BFCS:", scr_bfcs['host']+":", "Zoning")

    # Get the BFCF zoning information from the switch
    zshow_raw = ssh_exec(host = scr_bfcs['host'],
                         user = scr_bfcs['login'],
                         password = scr_bfcs['password'],
                         port = 22,
                         command = 'cfgactvshow')
#                        command = 'zoneshow')


    # Parse and format raw 'zoneshow' data
    cfg_state = 0
    record_type = ''
    in_record = 0
    zoneshow = []
    rcnt = 0
    zshow_list = re.split("[;\t\n\r]+", zshow_raw)
    for field in zshow_list:
        if field == ' ':
            continue

        field = field.strip()
        if field == 'Defined configuration:':
            cfg_state = 0
            continue
        if field == 'Effective configuration:':
            cfg_state = 1
            continue
        if field == 'zone:':
            in_record = 1
            record_type = 'z'                               # zone
            continue
        if field == 'alias:':
            in_record = 1
            record_type = 'a'                               # alias
            continue
        if field == 'cfg:':
            in_record = 1
            record_type = 'c'                               # configuration
            continue

        if in_record == 0 and cfg_state == 1:   # Only Effective configuration
                                                # so we will omit 'record_type'
                                                # because it's always 'zone'
            zoneshow.append(dict(cfg_state = cfg_state,
#           zoneshow.append(dict(cfg_state = cfg_state,
#                                record_type = record_type,
                                 record_name = name,
                                 record_member = field,
                                 record_count = rcnt))
        else:
            name = field
            in_record = 0
            rcnt = rcnt + 1

    # Fill in the 'bfcf_zoning' table with formatted 'zoneshow' data
    for rc in zoneshow:
        add_bfcf_members = ("INSERT INTO bfcf_zoning "
#                               "(bfcf_id, record_count, record_type, "
                                "(bfcf_id, record_count, "
#                               " record_name, record_member, cfg_state) "
                                " record_name, record_member) "
                            "VALUES "
#                               "(%s, %s, %s, %s, %s, %s)")
                                "(%s, %s, %s, %s)")
#       data_bfcf_members = (bfcf_id, rc['record_count'], rc['record_type'], 
        data_bfcf_members = (bfcf_id, rc['record_count'], 
                             rc['record_name'], rc['record_member'])
#                            rc['cfg_state'])
        cursor.execute(add_bfcf_members, data_bfcf_members)

    cnx.commit()

    # - 3: Name Service --------------------------------------------------------

    print(time.ctime(time.time()) + ":",
          "Debug: BFCS:", scr_bfcs['host']+":", "Name Service")

    # Get the nameserver information from the switch
    nsshow_raw = ssh_exec(host = scr_bfcs['host'],
                          user = scr_bfcs['login'],
                          password = scr_bfcs['password'],
                          port = 22,
                          command = 'nsshow -t && nscamshow -t')

    # Parse and format raw 'nsshow' data to get ports
    port_type = address = cos = port_name = node_name = did = aid = alpa = ''
    fabric_port_name = device_type = port_symb = node_symb = ''
    for ln in nsshow_raw.splitlines():
        # Find all blocks of Nx_ports in the fabric
        nx_ports = re.compile('^ +N  |^ +NL  |^ +U  ')
        if nx_ports.match(ln):
            # Yes, this is a first line of the Nx_port segment
            if port_type != '':
                # We found the Next Nx_port segment, that means we are finished
                # to parse the Previous one and must push it to the database
                add_bfcf_ns = ("INSERT INTO bfcf_ns "
                                    "(bfcf_id, port_type, address, cos, "
                                    "port_name, node_name, did, aid, alpa, "
                                    "fabric_port_name, device_type, "
                                    "port_index, port_symb, node_symb) "
                                "VALUES "
                                    "(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
                                    "%s, %s, %s, %s)")
                add_bfcf_data = (bfcf_id, port_type, address, cos, port_name,
                                    node_name, did, aid, alpa,
                                    fabric_port_name, device_type, port_index,
                                    port_symb, node_symb)
                cursor.execute(add_bfcf_ns, add_bfcf_data)
                # Clean the buffer values for the next iteration
                port_type = address = cos = port_name = node_name = '' 
                did = pid = loop = fabric_port_name = device_type = '' 
                port_symb = node_symb = ''
            # Parse the remains of the first string
            fields = re.split("[; \t]+", ln.strip())
            port_type = fields[0]                   # Port type
            address = fields[1]                     # FC-address
            cos = fields[2]                         # COS
            port_name = fields[3]                   # PWWN
            node_name = fields[4]                   # NWWN
            did = int(address[:2], 16)              # Domain ID in decimal
            aid = int(address[2:-2], 16)            # Area ID in decimal
            alpa = int(address[-2:], 16)            # AL_PA in decimal
        else:
            # No, we are already inside of the Nx_port segment, so
            # process all remained strings as the fields of Nx_port segment
            fields = re.split(":[ \t]+", ln.strip())
            if fields[0] == 'Fabric Port Name':
                fabric_port_name = fields[1]

            if fields[0] == 'Device type':
                device_type = fields[1]

            if fields[0] == 'Port Index':
                port_index = fields[1]

            if fields[0] == 'PortSymb':
                port_symb = fields[1]

            if fields[0] == 'NodeSymb':
                node_symb = fields[1]

    cnx.commit()

    cursor.close()
    cnx.close()

    print(time.ctime(time.time()) + ":",
          "Debug: BFCS:", scr_bfcs['host']+":", "End scan")

    return 0


# ------------------------------------------------------------------------------
# Scan HDVM-sources and fill in the appropriate tables
# 1: HDVM Arrays. Get all Storage arrays from every HDVM-source;
# 2: HDVM LUNs. Get LUNs (+ LDEVs, WWNs) from every Storage array of the all
#    HDVM-sources;
# 3: HDVM Ports. Get all storage ports (names, WWNs);
# 4: HDVM RG. Get arrays raid-groups (collected but not analized);
# 5: HDVM LDEVS. Must to get LDEVs to fill in missing raid-level info of the 
#    THP Pools on the R600 arrays on the old HDVM-servers;
# 6: HDVM THP Pools. DP Pools.
# ------------------------------------------------------------------------------
def explore_hdvm(scr_hdvm):

    # Open connection with the database
    cnx = connect_db(config['DATABASE']['host'], config['DATABASE']['database'],
                             config['DATABASE']['user'],
                             config['DATABASE']['password'])
    cursor = cnx.cursor()

    # Populate the 'sources' table from the INI-file with the HDVM-systems
    print(time.ctime(time.time()) + ":",
          "Debug: HDVM:", scr_hdvm['host']+":", "Start scan")

    source_id_hdvm = insert_source(cursor, session_id, 'HDVM', scr_hdvm['host'],
                                   scr_hdvm['login'], scr_hdvm['password'], 
                                   'NA', 0, 'NA')
    cnx.commit()


    # - 1: HDVM Arrays ---------------------------------------------------------

    print(time.ctime(time.time()) + ":",
          "Debug: HDVM:", scr_hdvm['host']+":", "Arrays")

    # Get all storage arrays info from the HDVM source
    hdvm_array_data = hdvm_getstoragearray(scr_hdvm['host'], scr_hdvm['login'],
                                           scr_hdvm['password'],
                                           'GetAllArrays', 0, 0)

    # Parse an XML-output...
    xml_hdvm_array = ET.fromstring(hdvm_array_data)
    for hdvm_array in xml_hdvm_array.iter('StorageArray'):
        name = hdvm_array.get('name')
        serialNumber = hdvm_array.get('serialNumber')
        arrayType = hdvm_array.get('arrayType')
        displayArrayType = hdvm_array.get('displayArrayType')
        capacityInKB = hdvm_array.get('capacityInKB')
        allocatedCapacityInKB = hdvm_array.get('allocatedCapacityInKB')
        freeCapacityInKB = hdvm_array.get('freeCapacityInKB')
        totalFreeSpaceInKB = hdvm_array.get('totalFreeSpaceInKB')
        numberOfControllers = hdvm_array.get('numberOfControllers')
        cacheInMB = hdvm_array.get('cacheInMB')
        hardwareRevision = hdvm_array.get('hardwareRevision')
        controllerVersion = hdvm_array.get('controllerVersion')

        # Search for this array in the hdvm_arrays
        array_id = get_valbykey(cursor, session_id, 'array_id', 'hdvm_arrays',
                                'serial', serialNumber)

        if array_id != 'NULL':
            # This HDVM-array is already exists in the database (skip it)
            print(time.ctime(time.time()) + ":",
                  "Debug: HDVM:", scr_hdvm['host'] + ":", name + ":",
                  "Skip the duplicated entry")
            continue;

        print(time.ctime(time.time()) + ":",
              "Debug: HDVM:", scr_hdvm['host']+":", name)

        # ... and save arrays info to the database 'arrays' table
        add_hdvm_array = ("INSERT INTO hdvm_arrays "
                            "(session_id, source_id, name, serial, array_type, "
                            "display_array_type, capacity, allocated_capacity, "
                            "free_capacity, total_free_space, "
                            "number_of_controllers, cache, hardware_revision, "
                            "controller_version) "
                          "VALUES (" +
                            str(session_id) + ", " + str(source_id_hdvm) + 
                            ", \'" + str(name) + "\', \'" + str(serialNumber) +
                            "\', \'" + str(arrayType) + "\', \'" +
                            str(displayArrayType) + "\', " + str(capacityInKB) +
                            ", " + str(allocatedCapacityInKB) + ", " + 
                            str(freeCapacityInKB) + ", " + 
                            str(totalFreeSpaceInKB) + ", " + 
                            str(numberOfControllers) + ", " + str(cacheInMB) + 
                            ", \'" + str(hardwareRevision) + "\', \'" + 
                            str(controllerVersion) + "\')")
        
        cursor.execute(add_hdvm_array, ())
        cnx.commit()

        # Save 'array_id' to use in the dependent tables
        array_id_hdvm = cursor.lastrowid

        # - 2: HDVM LUNs -------------------------------------------------------

        print(time.ctime(time.time()) + ":",
              "Debug: HDVM:", scr_hdvm['host']+":", name+":", "LUNs")

        # From the HDVM source get all ...
        hdvm_lun_data = hdvm_getstoragearray(scr_hdvm['host'],
                                             scr_hdvm['login'],
                                             scr_hdvm['password'],
                                             'GetArray_LUNs',
                                             serialNumber,
                                             arrayType)

        xml_hdvm_lun = ET.fromstring(hdvm_lun_data)
        # ... LDEVs info by LUN ...
        for hdvm_lun in xml_hdvm_lun.iter('LogicalUnit'):
            devNum = hdvm_lun.get('devNum')                                 # LDEV ordinal number

            if arrayType in ['R500', 'R600', 'R700', 'HM700']:              # -- Hitach/HP HI-ENDs --
                culdev_hex = str("{:06x}".format(int(hdvm_lun.get('devNum')))).upper()
                devNumDisplay = re.sub(r'(?<=.)(?=(..)+\b)', ':', culdev_hex)      # devNum is CLPR:CU:LDEV
                emulation = hdvm_lun.get('emulation')                       # Emulation
                devCount = hdvm_lun.get('devCount')                         # Offset in LUSE

            else:                                                           # -- Hitachi Midrange --
                devNumDisplay = devNum                                      # LDEV
                emulation = ''                                              # Not available
                devCount = ''                                               # N/A

            raidType = hdvm_lun.get('raidType')                             # Raid-level
            capacityInKB = hdvm_lun.get('capacityInKB')                     # capacityInKB
            consumedCapacityInKB = hdvm_lun.get('consumedCapacityInKB')     # consumedCapacityInKB
            commandDevice = hdvm_lun.get('commandDevice')                   # commandDevice 0 or 1
            rg_number = hdvm_lun.get('arrayGroup')                          # Raid-group ordinal number
                                                                            # for details see "4: RGs"
                                                                            # section below
            dpPoolID = hdvm_lun.get('dpPoolID')                             # DP Pool ID
            dpType = hdvm_lun.get('dpType')                                 # Pool type:
                                                                            #   0  - normal
                                                                            #   -1 - absent
            # ... LUNs ...
            for hdvm_lun_path in hdvm_lun.findall("Path"):
                portID = hdvm_lun_path.get('portID')        # Storage array Port ID
                domainID = hdvm_lun_path.get('domainID')    # Hostgroup ID
                lun = hdvm_lun_path.get('lun')              # LUN. Real lun number
                # ... Host WWNs ...
                for hdvm_lun_path_wwn in hdvm_lun_path.findall("WorldWideName"):
                    wwn = hdvm_lun_path_wwn.get('wwn').lower().replace(".", ":")    # Host WWN
                    nickname = hdvm_lun_path_wwn.get('nickname')                    # Host nickname
                    # ... and save them to the database
                    add_hdvm_lun = ("INSERT INTO hdvm_lun "
                                        "(array_id, dev_num, dev_num_display, "
                                        "capacity, emulation, device_count, "
                                        "rg_number, raid_type, consumed_capacity, "
                                        "command_device, dp_pool_id, dp_type, "
                                        "port_id, domain_id, lun, wwn, nickname) "
                                    "VALUES "
                                        "(%s, %s, %s, %s, %s, %s, "
                                        "%s, %s, %s, %s, %s, %s, %s, "
                                        "%s, %s, %s, %s)")
                    data_hdvm_lun = (array_id_hdvm, devNum, devNumDisplay,
                                     capacityInKB, emulation, devCount,
                                     rg_number, raidType, consumedCapacityInKB,
                                     commandDevice, dpPoolID, dpType,
                                     portID, domainID, lun, wwn, nickname)
                    cursor.execute(add_hdvm_lun, data_hdvm_lun)
                    cnx.commit()

        # - 3: HDVM Ports ------------------------------------------------------

        print(time.ctime(time.time()) + ":",
              "Debug: HDVM:", scr_hdvm['host']+":", name+":", "Ports")

        hdvm_port_data = hdvm_getstoragearray(scr_hdvm['host'],
                                              scr_hdvm['login'],
                                              scr_hdvm['password'],
                                              'GetArray_Ports',
                                              serialNumber,
                                              arrayType)

        xml_hdvm_port = ET.fromstring(hdvm_port_data)
        for hdvm_port in xml_hdvm_port.iter('Port'):
            portID = hdvm_port.get('portID')
            portType = hdvm_port.get('portType')
            portRole = hdvm_port.get('portRole')
            topology = hdvm_port.get('topology')
            port_displayName = hdvm_port.get('displayName')
            lunSecurity = hdvm_port.get('lunSecurityEnabled')
            controllerID = hdvm_port.get('controllerID')
            pwwn = hdvm_port.get('worldWidePortName').lower().replace(".", ":")
            channelSpeed = hdvm_port.get('channelSpeed')
            portOption = hdvm_port.get('portOption')

            for hdvm_port_hg in hdvm_port.findall("HostStorageDomain"):
                domainID = hdvm_port_hg.get('domainID')
                hostMode = hdvm_port_hg.get('hostMode')
                hostMode2 = hdvm_port_hg.get('hostMode2')
                # Hi-Ends uses hostModeOption but not hostMode2 so:
                try:
                    hostModeOption = dvm_port_hg.get('hostModeOption')
                except NameError:
                    hostModeOption = ''
                hostMode2 = str(hostMode2) + str(hostModeOption)
                hg_displayName = hdvm_port_hg.get('displayName')
                domainType = hdvm_port_hg.get('domainType')
                nickname = hdvm_port_hg.get('nickname')

                add_hdvm_port = ("INSERT INTO hdvm_port "
                                    "(array_id, port_id, port_type, port_role, "
                                    "topology, port_display_name, lun_security, "
                                    "controller_id, pwwn, channel_speed, "
                                    "port_option, domain_id, host_mode, "
                                    "host_mode2, hg_display_name, domain_type, "
                                    "nickname) "
                                 "VALUES "
                                    "(%s, %s, %s, %s, %s, %s, %s, %s, %s, "
                                    "%s, %s, %s, %s, %s, %s, %s, %s)")
                data_hdvm_port = (array_id_hdvm, portID, portType, portRole,
                                  topology, port_displayName, lunSecurity,
                                  controllerID, pwwn, channelSpeed,
                                  portOption, domainID, hostMode, hostMode2,
                                  hg_displayName, domainType, nickname)
                cursor.execute(add_hdvm_port, data_hdvm_port)
        
        # - 4: HDVM RGs --------------------------------------------------------

        print(time.ctime(time.time()) + ":",
              "Debug: HDVM:", scr_hdvm['host']+":", name+":", "Raid Groups")

        hdvm_rg_data = hdvm_getstoragearray(scr_hdvm['host'],
                                            scr_hdvm['login'],
                                            scr_hdvm['password'],
                                            'GetArray_RGs',
                                            serialNumber,
                                            arrayType)

        xml_hdvm_rg = ET.fromstring(hdvm_rg_data)
        for hdvm_rg in xml_hdvm_rg.iter('ArrayGroup'):
            displayName = hdvm_rg.get('displayName')
            chassis = hdvm_rg.get('chassis')
            controllerID = hdvm_rg.get('controllerID')
            number = hdvm_rg.get('number')                  # Ordinal number
            rt = hdvm_rg.get('raidType')
            if rt != '-': raidType = rt
            diskSizeInKB = hdvm_rg.get('diskSizeInKB')
            diskType = hdvm_rg.get('diskType')
            totalCapacity = hdvm_rg.get('totalCapacity')
            allocatedCapacity = hdvm_rg.get('allocatedCapacity')
            freeCapacity = hdvm_rg.get('freeCapacity')
            totalFreeSpace = hdvm_rg.get('totalFreeSpace')
            emulation = hdvm_rg.get('emulation')
            rg_type = hdvm_rg.get('type')                   # -1: Pools not supported
                                                            #  0: RG  on any
                                                            #  1: Ext on R600/R700/HM700
                                                            #  3: ThP on R600/R700/HM700
                                                            #  4: ThP on HUS150/AMS2500


            volumeType = hdvm_rg.get('volumeType')          #  4: Ext volume with rg_type: 4
            encrypted = hdvm_rg.get('encrypted')
            protectionLevel = hdvm_rg.get('protectionLevel')
            dpPoolID = hdvm_rg.get('dpPoolID')
            formFactor = hdvm_rg.get('formFactor')

            add_hdvm_rg = ("INSERT INTO hdvm_rg "
                                "(array_id, number, display_name, disk_size, "
                                "disk_type, total_capacity, allocated_capacity, "
                                "free_capacity, total_free_space, dp_pool_id, "
                                "emulation, chassis, controller_id, "
                                "raid_type, rg_type, volume_type, encrypted, "
                                "protection_level, form_factor) "
                           "VALUES "
                                "(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
                                "%s, %s, %s, %s, %s, %s, %s, %s, %s)")
            data_hdvm_rg = (array_id_hdvm, number, displayName, diskSizeInKB,
                            diskType, totalCapacity, allocatedCapacity,
                            freeCapacity, totalFreeSpace, dpPoolID, emulation,
                            chassis, controllerID, raidType, rg_type, 
                            volumeType, encrypted, protectionLevel, formFactor)
            cursor.execute(add_hdvm_rg, data_hdvm_rg)

        # - 5: HDVM LDEVs ------------------------------------------------------

        print(time.ctime(time.time()) + ":",
              "Debug: HDVM:", scr_hdvm['host']+":", name+":", "LDEVs")

        hdvm_ldev_data = hdvm_getstoragearray(scr_hdvm['host'],
                                              scr_hdvm['login'],
                                              scr_hdvm['password'],
                                              'GetArray_LDEVs',
                                              serialNumber,
                                              arrayType)

        xml_hdvm_ldev = ET.fromstring(hdvm_ldev_data)
        for hdvm_ldev in xml_hdvm_ldev.iter('LDEV'):
            status = hdvm_ldev.get('status')
            quorumDisk = hdvm_ldev.get('quorumDisk')
            encrypted = hdvm_ldev.get('encrypted')
            threshold = hdvm_ldev.get('threshold')
            dpPoolID = hdvm_ldev.get('dpPoolID')
            consumedSizeInKB = hdvm_ldev.get('consumedSizeInKB')
            dpType = hdvm_ldev.get('dpType')
            chassis = hdvm_ldev.get('chassis')
            arrayGroup = hdvm_ldev.get('arrayGroup')
            devNum = hdvm_ldev.get('devNum')                               # LDEV ordinal number

            if arrayType in ['R500', 'R600', 'R700', 'HM700']:             # -- Hitach/HP HI-ENDs --
                culdev_hex = str("{:06x}".format(int(hdvm_ldev.get('devNum')))).upper()
                devNumDisplay = re.sub(r'(?<=.)(?=(..)+\b)', ':', culdev_hex)      # devNum is CLPR:CU:LDEV
                emulation = hdvm_ldev.get('emulation')
            else:
                devNumDisplay = devNum                                      # LDEV display
                emulation = ''                                              # Not available

            raidType = hdvm_ldev.get('raidType')
            volumeKind = hdvm_ldev.get('volumeKind')
            sizeInKB = hdvm_ldev.get('sizeInKB')

            add_hdvm_ldev = ("INSERT INTO hdvm_ldev "
                                "(array_id, ldev_status, quorum_disk, "
                                "encrypted, threshold, dp_pool_id, "
                                "consumed_size, dp_type, chassis, "
                                "array_group_number, dev_num, dev_num_display, "
                                "raid_type, volume_kind, emulation, size) "
                             "VALUES "
                                "(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
                                "%s, %s, %s, %s, %s, %s)")
            data_hdvm_ldev = (array_id_hdvm, status, quorumDisk, encrypted,
                              threshold, dpPoolID, consumedSizeInKB, dpType,
                              chassis, arrayGroup, devNum, devNumDisplay, 
                              raidType, volumeKind, emulation, sizeInKB)
            cursor.execute(add_hdvm_ldev, data_hdvm_ldev)

        # - 6: HDVM THP Pools --------------------------------------------------

        print(time.ctime(time.time()) + ":",
              "Debug: HDVM:", scr_hdvm['host']+":", name+":", "THP Pools") 

        hdvm_pool_data = hdvm_getstoragearray(scr_hdvm['host'],
                                              scr_hdvm['login'],
                                              scr_hdvm['password'],
                                              'GetArray_Pools',
                                              serialNumber,
                                              arrayType)

        xml_hdvm_pool = ET.fromstring(hdvm_pool_data)
        for hdvm_pool in xml_hdvm_pool.iter('JournalPool'):
            poolFunction = hdvm_pool.get('poolFunction')
            poolID = hdvm_pool.get('poolID')
            controllerID = hdvm_pool.get('controllerID')
            poolType = hdvm_pool.get('poolType')
            status = hdvm_pool.get('status')
            threshold = hdvm_pool.get('threshold')
            threshold2 = hdvm_pool.get('threshold2')
            capacityInKB = hdvm_pool.get('capacityInKB')
            freeCapacityInKB = hdvm_pool.get('freeCapacityInKB')
            usageRate = hdvm_pool.get('usageRate')
            numberOfVVols = hdvm_pool.get('numberOfVVols')
            capacityOfVVolsInKB = hdvm_pool.get('capacityOfVVolsInKB')
            raidLevel = hdvm_pool.get('raidLevel')
            combination = hdvm_pool.get('combination')
            diskType = hdvm_pool.get('diskType')
            rpm = hdvm_pool.get('rpm')

            if raidLevel == '-':
                # Get missing DP Pool Raidlevel value based on LDEVs info
                select_raid_level_comb = ("SELECT raid_type FROM hdvm_ldev "
                                            "WHERE array_id = %s "
                                            "AND dp_pool_id = %s "
                                            "AND raid_type != '-' LIMIT 1")
                cursor.execute(select_raid_level_comb, (array_id_hdvm, poolID))

                try:
                    raid_revel_comb = tuple(cursor)[0][0]
                except IndexError:
                    # Let it be nul if we can't find RaidLevel/Combination
                    raid_revel_comb = "()"

                fields = re.split("[()]", raid_revel_comb)
                raidLevel = fields[0]   # Raid Level for example: RAID5
                combination = fields[1] # Raid Combination for example: 3D+1P

            add_hdvm_pool = ("INSERT INTO hdvm_pool "
                                "(array_id, pool_function, dp_pool_id, "
                                "controller_id, pool_type, status, threshold, "
                                "threshold2, capacity, free_capacity, "
                                "usage_rate, number_of_vvols, "
                                "capacity_of_vvols, raid_level, combination, "
                                "disk_type, rpm) "
                             "VALUES "
                                "(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
                                "%s, %s, %s, %s, %s, %s, %s)")
            data_hdvm_pool = (array_id_hdvm, poolFunction, poolID, controllerID,
                              poolType, status, threshold, threshold2,
                              capacityInKB, freeCapacityInKB, usageRate,
                              numberOfVVols, capacityOfVVolsInKB, raidLevel,
                              combination, diskType, rpm)
            cursor.execute(add_hdvm_pool, data_hdvm_pool)

    cnx.commit()

    cursor.close()
    cnx.close()

    print(time.ctime(time.time()) + ":",
          "Debug: HDVM:", scr_hdvm['host']+":", "End scan")

    return 0


# ------------------------------------------------------------------------------
# Scan 3PAR Source and fill in the appropriate tables
# 1: 3PAR Array. Top level information of the source array: showsys -d;
# 2: 3PAR Ports. Storage ports information: "showport";
# 3: 3PAR Vluns. VLUN information: "showvlun -lvw -a";
# 4: 3PAR Vvols. Vvol information: 
# "showvv -showcols Id,Name,Rd,Mstr,VV_WWN,Prov,Type,UsrCPG,SnpCPG,Tot_Rsvd_MB,VSize_MB"
# 5: 3PAR CPGs. CPG information: "howcpg -sdg".
# 6: 3PAR Hosts. Hosts info mainly for "Persona" column: "showhost -d"
# ------------------------------------------------------------------------------
def explore_3par(scr_3par):

    # Connect with the database
    cnx = connect_db(config['DATABASE']['host'], config['DATABASE']['database'],
                     config['DATABASE']['user'], config['DATABASE']['password'])
    cursor = cnx.cursor()


    # - 1: 3PAR Array ----------------------------------------------------------

    print(time.ctime(time.time()) + ":",
          "Debug: 3PAR:", scr_3par['host']+":", "Array")

    # Execute 'showsys -d' on the 3PAR system and save the raw output

    showsys_raw = ssh_exec(host=scr_3par['host'], user=scr_3par['login'],
                           password=scr_3par['password'], port=22, 
                           command='showsys -d')

    # Initialize some variables before parsing the data
    system_name = system_model = serial_number = system_id = ''
    number_of_nodes = master_node = 0
    total_capacity = allocated_capacity = free_capacity = failed_capacity = 0
    location = owner = contact = comment = ''

    # Parse 'showsys -d' into the fields
    for ln in showsys_raw.splitlines():
        if 'System Name' in ln:
            system_name = split_colon(ln)
            continue
        if 'System Model' in ln:
            system_model = split_colon(ln)
            continue
        if 'Serial Number' in ln:
            serial_number = split_colon(ln)
            continue
        if 'System ID' in ln:
            system_id = split_colon(ln)
            continue
        if 'Number of Nodes' in ln:
            number_of_nodes = split_colon(ln)
            continue
        if 'Master Node' in ln:
            master_node = split_colon(ln)
            continue
        if 'Total Capacity' in ln:
            total_capacity = int(split_colon(ln)) * 1024     # Result in KBytes
            continue
        if 'Allocated Capacity' in ln:
            allocated_capacity = int(split_colon(ln)) * 1024 # In KB
            continue
        if 'Free Capacity' in ln:
            free_capacity = int(split_colon(ln)) * 1024      # In KB
            continue
        if 'Failed Capacity' in ln:
            failed_capacity = int(split_colon(ln)) * 1024    # In KB
            continue
        if 'Location' in ln:
            location = split_colon(ln)
            continue
        if 'Owner' in ln:
            owner = split_colon(ln)
            continue
        if 'Contact' in ln:
            contact = split_colon(ln)
            continue
        if 'Comment' in ln:
            comment = split_colon(ln)

    # Search for this array in the 3par_arrays
    array_id = get_valbykey(cursor, session_id, 'array_id', '3par_arrays',
                                'serial_number', serial_number)

    if array_id != 'NULL':
        # This 3PAR-array is already exists in the database (skip it)
        print(time.ctime(time.time()) + ":", "Debug: 3PAR:", scr_3par['host'] +
              ": ", "Skip the duplicated entry")
        return;

    # Populate the 'sources' table from the INI-file with the 3PAR-systems
    print(time.ctime(time.time()) + ":",
          "Debug: 3PAR:", scr_3par['host']+":", "Start scan")

    source_id_3par = insert_source(cursor, session_id, '3PAR', scr_3par['host'],
                                   scr_3par['login'], scr_3par['password'],
                                   'SSH', 22, 'NA')
    cnx.commit()

    # Fill in '3par_arrays' table with the parsed data
    add_3par_arrays = ("INSERT INTO 3par_arrays "
                            "(session_id, source_id, system_name, "
                            "system_model, serial_number, system_id, "
                            "number_of_nodes, master_node, total_capacity, "
                            "allocated_capacity, free_capacity, "
                            "failed_capacity, location, owner, "
                            "contact, comment) "
                       "VALUES "
                            "(%s, %s, %s, %s, %s, %s, %s, %s, "
                            "%s, %s, %s, %s, %s, %s, %s, %s)")
    data_3par_arrays = (session_id, source_id_3par, system_name, system_model, 
                        serial_number, system_id, number_of_nodes, master_node,
                        total_capacity, allocated_capacity, free_capacity,
                        failed_capacity, location, owner, contact, comment)
    cursor.execute(add_3par_arrays, data_3par_arrays)

    cnx.commit()

    # Save 'array_id_3par' to use in the dependent tables
    array_id_3par = cursor.lastrowid

    # - 2: 3PAR Ports ----------------------------------------------------------

    print(time.ctime(time.time()) + ":",
          "Debug: 3PAR:", scr_3par['host']+":", "Ports")

    # Get Port information from the 3PAR system
    showport_raw = ssh_exec(host=scr_3par['host'], user=scr_3par['login'],
                            password=scr_3par['password'], port=22, 
                            command='showport')

    for ln in showport_raw.splitlines():
        if 'N:S:P      Mode' in ln: continue
        if '----' in ln: break

        lns = ' '.join(ln.split()).split(' ')

        nsp = lns[0]            # Node:Slot:Port
        mode = lns[1]           # Portmode: initiator/target/peer
        state = lns[2]          # Port state: ready/loss_sync/offline
        nwwn = wwn_up2brocade(lns[3])  # Node WWN
        pwwn = wwn_up2brocade(lns[4])  # Port WWN
        port_type = lns[5]      # Type: disk/host/free/rcip/etc
        protocol = lns[6]       # FC/SAS/IP/etc
        label = lns[7]          # -/DP-1/RCIP0
        partner = lns[8]        # Partner addressin N:S:P format
        failoverstate = lns[9]  # -/none/etc

        if 'FC' in protocol :
            add_3par_ports = ("INSERT INTO 3par_port "
                                "(array_id, nsp, mode, state, nwwn, pwwn, "
                                "port_type, protocol, label, partner) "
                              "VALUES "
                                "(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")
            data_3par_ports = (array_id_3par, nsp, mode, state, nwwn, pwwn,
                               port_type, protocol, label, partner)
            cursor.execute(add_3par_ports, data_3par_ports)

        
    # - 3: 3PAR VLUNs ----------------------------------------------------------

    print(time.ctime(time.time()) + ":",
          "Debug: 3PAR:", scr_3par['host']+":", "VLUNs")

    # Get info about VLUNs
    showvlun_raw = ssh_exec(host=scr_3par['host'], user=scr_3par['login'],
                            password=scr_3par['password'], port=22,
                            command='showvlun -lvw -a')

    lun = vvname = vv_wwn = hostname = host_wwniscsi = port = ''

    for ln in showvlun_raw.splitlines():
        if 'Lun VVName' in ln: continue
        if '----' in ln: break

        lns = ' '.join(ln.split()).split(' ')

        lun = lns[0]             # LUN
        vvname = lns[1]          # VVName
        vv_wwn = lns[2]          # VV_WWN
        hostname = lns[3]        # HostName
        host_wwniscsi = wwn_up2brocade(lns[4]) # Host_WWN; iSCSI_Name not supported
        port = lns[5]            # Port

        add_3par_vluns = ("INSERT INTO 3par_vlun "
                                "(array_id, lun, vvname, vv_wwn, hostname, "
                                "host_wwniscsi, port) "
                          "VALUES "
                                "(%s, %s, %s, %s, %s, %s, %s)")
        data_3par_vluns = (array_id_3par, lun, vvname, vv_wwn, hostname, 
                           host_wwniscsi, port)
        cursor.execute(add_3par_vluns, data_3par_vluns)

    # - 4: 3PAR VVOLs ----------------------------------------------------------

    print(time.ctime(time.time()) + ":",
          "Debug: 3PAR:", scr_3par['host']+":", "VVOLs")

    # Get VVOLs data
    showvv_raw = ssh_exec(host=scr_3par['host'], user=scr_3par['login'],
        password=scr_3par['password'], port=22,
        command='showvv -showcols Id,Name,Rd,Mstr,VV_WWN,Prov,Type,UsrCPG,SnpCPG,Tot_Rsvd_MB,VSize_MB')

    vv_id = vvname = rd = mstr = vv_wwn = prov = vv_type = usrcpg = snpcpg = ''
    tot_rsvr_kb = vsize_kb = ''

    for ln in showvv_raw.splitlines():
        if 'Id Name' in ln: continue
        if '----' in ln: break

        lns = ' '.join(ln.split()).split(' ')

        vv_id = lns[0]       # VVol ID
        vvname = lns[1]      # VVName
        rd = lns[2]          # Read/Write: RO/RW
        mstr = lns[3]        # Master node?
        vv_wwn = lns[4]      # VV_WWN
        prov = lns[5]        # Provisioning: full/tpvv/cpvv/tpsd/snp/peer
        vv_type = lns[6]     # Type: base/pcopy/vcopy
        usrcpg = lns[7]      # User CPG
        snpcpg = lns[8]      # Snapshot CPG
        try:
            tot_rsvr_kb = 1024 * int(lns[9]) # Total Reserved (Used) in MB
        except ValueError:
            tot_rsvr_kb = 0
        try:
            vsize_kb = 1024 * int(lns[10])   # VVol size in MB
        except ValueError:
            vsize_kb = 0

        add_3par_vvols = ("INSERT INTO 3par_vvol "
                                "(array_id, vv_id, vvname, rd, mstr, "
                                "vv_wwn, prov, vv_type, usrcpg, snpcpg, "
                                "tot_rsvr_kb, vsize_kb) "
                           "VALUES "
                                "(%s, %s, %s, %s, %s, %s, %s, %s, %s, "
                                "%s, %s, %s)")
        data_3par_vvols = (array_id_3par, vv_id, vvname, rd, mstr, vv_wwn, prov,
                           vv_type, usrcpg, snpcpg, tot_rsvr_kb, vsize_kb)
        cursor.execute(add_3par_vvols, data_3par_vvols)

    # - 4: 3PAR VVOLs ----------------------------------------------------------

    print(time.ctime(time.time()) + ":", 
          "Debug: 3PAR:", scr_3par['host']+":", "CPGs")

    # Collect CPGs information
    showcpg_raw = ssh_exec(host=scr_3par['host'], user=scr_3par['login'],
                           password=scr_3par['password'], port=22,
                           command='showcpg -sdg')

    cpg_id = cpgname = warn = lim = grow = t = 0
    ssz = rs = ss = ha = nd = devtype = rpm = 0

    for ln in showcpg_raw.splitlines():
        if 'Id Name' in ln or '----' in ln: continue

        lns = ' '.join(ln.split()).split()

        cpg_id = int(lns[0])        # CPG ID
        cpgname = lns[1]            # CPG Name
        warn = lns[2]               # The CPG’s allocation warning threshold
        lim = lns[3]                # Limit
        grow = lns[4]               # Grow

        for i in range(5, len(lns), 1):
            if '-t' in lns[i]:
                t = lns[i+1]        # RAID Type
                continue
            if '-ssz' in lns[i]:
                ssz = int(lns[i+1]) # Size Number Chunklets
                continue
            if '-rs' in lns[i]:
                rs = int(lns[i+1])  # Number of sets in a row
                continue
            if '-ss' in lns[i]:
                ss = int(lns[i+1])  # Step size from 32 KB to 512 KB
                continue
            if '-ha' in lns[i]:
                ha = lns[i+1]       # Layout: port|cage|mag
                continue
            if '-nd' in lns[i]:
                nd = lns[i+1]       # Nodes
                continue
            if '-devtype' in lns[i]:
                devtype = lns[i+1]  # Device Type
                continue
            if '-rpm' in lns[i]:
                rpm = lns[i+1]      # Device RPM

        add_3par_cpgs = ("INSERT INTO 3par_cpg "
                            "(array_id, cpg_id, cpgname, warn, lim, "
                            "grow, raid, rs, ssz, ss, ha, nd, devtype, rpm) "
                         "VALUES "
                            "(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
                            "%s, %s, %s, %s)")
        data_3par_cpgs = (array_id_3par, cpg_id, cpgname, warn, lim, grow, t,
                          rs, ssz, ss, ha, nd, devtype, rpm)
        cursor.execute(add_3par_cpgs, data_3par_cpgs)
                        
    # - 5: 3PAR Hosts ----------------------------------------------------------

    print(time.ctime(time.time()) + ":", 
          "Debug: 3PAR:", scr_3par['host']+":", "Hosts")

    # Collect CPGs information
    showhost_raw = ssh_exec(host=scr_3par['host'], user=scr_3par['login'],
                            password=scr_3par['password'], port=22,
                            command='showhost -d')

    host_id = host_name = persona = host_wwniscsi = port = ip_addr = ''

    for ln in showhost_raw.splitlines():
        if 'Id Name' in ln or '--' in ln: continue

        lns = ' '.join(ln.split()).split()

        host_id = int(lns[0])       # Host ID
        host_name = lns[1]          # Host Name
        persona = lns[2]            # Host Persona
        host_wwniscsi = wwn_up2brocade(lns[3])  # Host WWN in normal format
        port = lns[4]               # Port
        ip_addr = lns[5]            # IP Address

        add_3par_hosts = ("INSERT INTO 3par_host "
                            "(array_id, host_id, host_name, persona, "
                            "host_wwniscsi, port, ip_addr) "
                          "VALUES "
                            "(%s, %s, %s, %s, %s, %s, %s)")
        data_3par_hosts = (array_id_3par, host_id, host_name, persona,
                           host_wwniscsi, port, ip_addr)
        cursor.execute(add_3par_hosts, data_3par_hosts)


    cnx.commit()

    cursor.close()
    cnx.close()

    print(time.ctime(time.time()) + ":",
          "Debug: 3PAR:", scr_3par['host'] + ":", "End scan")

    return 0

# ------------------------------------------------------------------------------
# Scan IBTS (IBM Tape storage TS) Source and fill in the appropriate tables.
# 1: IBTS Config download. Grab the Fibre Port Statistics(.csv) from the library
# 2: IBTS Tape library. Top level information of the source library: name, type
#    snipped from explorer source variable of the INI file
# 3: IBTS Drives. WWWNs, Models, SN, validation, of the library drives
# ------------------------------------------------------------------------------
def explore_ibts(scr_ibts):
    http_headers = {'User-Agent': 'Deck Eight:One Step',
                    'Accept': '*/*'}
    fps_file_csv = '/FS/LIBLG_01_PS.csv'
    wwn = model = serial = ''
    valid = error = abort = reset = recovery = 0


    # Connect with the database
    cnx = connect_db(config['DATABASE']['host'], config['DATABASE']['database'],
                     config['DATABASE']['user'], config['DATABASE']['password'])
    cursor = cnx.cursor()

    # Search for this tape library in the ibts_libraries
    library_id = get_valbykey(cursor, session_id, 'library_id', 'ibts_libraries',
                              'name', scr_ibts['host'])

    if library_id != 'NULL':
        # This tape-library is already exists in the database (skip it)
        print(time.ctime(time.time()) + ":", "Debug: IBTS:", scr_ibts['host'] +
              ": ", "Skip the duplicated entry")
        return;

    # Populate the 'sources' table from the INI-file with the IBTS-systems
    print(time.ctime(time.time()) + ":",
          "Debug: IBTS:", scr_ibts['host'] + ":", "Start scan")

    source_id_ibts = insert_source(cursor, session_id, 'IBTS',
                                   scr_ibts['host'], 'NA', 'NA',
                                   'HTTP', 80, 'NA')
    cnx.commit()

    # - 1: IBTS Config download ------------------------------------------------

    print(time.ctime(time.time()) + ":",
          "Debug: IBTS:", scr_ibts['host'] + ":", "Config Download")

    httpc = http.client.HTTPConnection(scr_ibts['host'], 80, timeout=30)
    httpc.request('GET', fps_file_csv, body=None, headers=http_headers)
    resp = httpc.getresponse()

    data = resp.read()
    data = data.decode('cp1251')

    httpc.close()

    # - 2: IBTS Tape library ---------------------------------------------------

    print(time.ctime(time.time()) + ":",
            "Debug: IBTS:", scr_ibts['host'] + ":", "Tape library")

    # Register the IBTS library
    add_ibts_library = ("INSERT INTO ibts_libraries "
                            "(session_id, source_id, name, model) "
                        "VALUES "
                            "(%s, %s, %s, %s)")
    data_ibts_library = (session_id, source_id_ibts, scr_ibts['host'], 
                         scr_ibts['model'])
    cursor.execute(add_ibts_library, data_ibts_library)
    cnx.commit()

    # Save 'library_id_ibts' to use in the dependent tables
    library_id_ibts = cursor.lastrowid

    # - 3: IBTS Drives ---------------------------------------------------------
    print(time.ctime(time.time()) + ":",
            "Debug: IBTS:", scr_ibts['host'] + ":", "Drives")
    for ln in data.splitlines():
        if '_' in ln:
            fields = ln.split(',')

            wwn = wwn_up2brocade(fields[0].lstrip('\0_\0'))
            model = fields[1].lstrip('\0_\0').rstrip()
            serial = fields[2].lstrip('\0_\0')

            valid = fields[8].strip('\0')
            error = fields[9].strip('\0')
            abort = fields[10].strip('\0')
            reset = fields[11].strip('\0')
            try:
                recovery = fields[12].lstrip('\0')
            except IndexError:
                recovery = 0

            add_ibts_drives = ("INSERT INTO ibts_drives "
                                    "(library_id, wwn, model, serial, valid, "
                                    "error, abort, reset, recovery) "
                                "VALUES "
                                    "(%s, %s, %s, %s, %s, %s, %s, %s, %s)")
            data_ibts_drives = (library_id_ibts, wwn, model, serial, valid,
                                error, abort, reset, recovery)
            cursor.execute(add_ibts_drives, data_ibts_drives)

    cnx.commit()

    cursor.close()
    cnx.close()

    print(time.ctime(time.time()) + ":",
            "Debug: IBTS:", scr_ibts['host'] + ":", "End Scan")

    return 0


# ------------------------------------------------------------------------------
# Form the true XML structure from the EVA sssu "LS ..." command output
# ------------------------------------------------------------------------------
def heva_xml(ls_raw):
    # Prepare XML header/footer
    ls_xml_head='<?xml version="1.0"?>\n<CEVA>\n'
    ls_xml_body=''
    ls_xml_tail='</CEVA>\n'

    for ln in ls_raw.splitlines():
        # We need only XML-tags from the output
        if '<' in ln:
            ls_xml_body = ls_xml_body + ln + '\n'

    # Form the true XML-structure
    ls_xml = ls_xml_head + ls_xml_body + ls_xml_tail

    return ls_xml


# ------------------------------------------------------------------------------
# Scan HEVA (HP EVA) Source with sssu utility and fill in the appropriate tables
# 1: HEVA Arrays. Collect top-level arrays data from the Command View EVA server
#   run: "LS SYSTEM FULL XML" command. The futher steps are executed for each
#   HP EVA array.
# 2: HEVA Ports. Run: "LS CONTROLLER FULL XML";
# 3: HEVA Disk Groups. Run: "LS DISK_GROUP FULL XML";
# 4: HEVA Hosts. Run: "LS HOST FULL XML";
# 5: HEVA VDisks. Run: "LS VDISK FULL XML"
# ------------------------------------------------------------------------------
def explore_heva(scr_heva):
    # Connect with the database
    cnx = connect_db(config['DATABASE']['host'], config['DATABASE']['database'],
                     config['DATABASE']['user'], config['DATABASE']['password'])
    cursor = cnx.cursor()


    # Populate the 'sources' table from the INI-file with the HEVA-systems
    print(time.ctime(time.time()) + ":",
          "Debug: HEVA:", scr_heva['host']+":", "Start scan")

    source_id_heva = insert_source(cursor, session_id, 'HEVA', scr_heva['host'],
                                   scr_heva['login'], scr_heva['password'],
                                   'NA', 'NA', 'NA')


    # - 1: HEVA Arrays ---------------------------------------------------------

    print(time.ctime(time.time()) + ":",
          "Debug: HEVA:", scr_heva['host']+":", "Arrays")

    ls_system_raw = subprocess.check_output([config['TOOLS']['sssu'],
        "select manager " + scr_heva['host'] + " username=" + scr_heva['login'] 
            + " password=" + scr_heva['password'],
        "LS SYSTEM FULL XML", "exit"], universal_newlines=True)

    # Create XML-structure from the sssu output
    ls_system_xml = heva_xml(ls_system_raw)

    root = ET.fromstring(ls_system_xml)
    # Gather data and fill DB for every HP EVA array registered by the HEVA source
    for obj in root.findall('object'):
        eva_name = obj.find('objectname').text
        eva_wwn = obj.find('objectwwn').text
        operationalstate = obj.find('operationalstate').text
        operationalstatedetail = obj.find('operationalstatedetail').text
        licensestate = obj.find('licensestate').text
        comments = obj.find('comments').text
        uid = obj.find('uid').text
        hexuid = obj.find('hexuid').text
        systemtype = obj.find('systemtype').text
        totalstoragespace = int(float(obj.find('totalstoragespace').text) 
                            * 1024 * 1024)          # In Kbytes
        usedstoragespace = int(float(obj.find('usedstoragespace').text)
                            * 1024 * 1024)          # In Kbytes
        availablestoragespace = int(float(obj.find('availablestoragespace').text)
                            * 1024 * 1024)          # In Kbytes
        firmwareversion = obj.find('firmwareversion').text
        nscfwversion = obj.find('nscfwversion').text
        storagesystemcontrollermemory = obj.find('storagesystemcontrollermemory').text
        storagesystemcontrollercachememory = obj.find('storagesystemcontrollercachememory').text

        # Search for this array in the hheva_arrays
        array_id = get_valbykey(cursor, session_id, 'array_id', 'heva_arrays',
                                'wwn', eva_wwn)

        if array_id != 'NULL':
            # This HEVA-array is already exists in the database (skip it)
            print(time.ctime(time.time()) + ":",
                  "Debug: HEVA:", scr_heva['host'] + ":", eva_name + ":",
                  "Skip the duplicated entry")
            continue;

        # Fill in 'heva_arrays' table with the parsed data
        add_heva_arrays = ("INSERT INTO heva_arrays "
                            "(session_id, source_id, name, wwn, "
                            "operationalstate, operationalstatedetail, "
                            "licensestate, comments, uid, hexuid, systemtype, "
                            "totalstoragespace, usedstoragespace, "
                            "availablestoragespace, firmwareversion, "
                            "nscfwversion, storagesystemcontrollermemory, "
                            "storagesystemcontrollercachememory) "
                           "VALUES "
                            "(%s, %s, %s, %s, %s, %s, %s, %s, %s, "
                            "%s, %s, %s, %s, %s, %s, %s, %s, %s)")
        data_heva_arrays = (session_id, source_id_heva, eva_name, eva_wwn,
                            operationalstate, operationalstatedetail, 
                            licensestate, comments, uid, hexuid, systemtype,
                            totalstoragespace, usedstoragespace,
                            availablestoragespace, firmwareversion, 
                            nscfwversion, storagesystemcontrollermemory,
                            storagesystemcontrollercachememory)
        cursor.execute(add_heva_arrays, data_heva_arrays)

        # Save 'array_id_heva' to use in the dependent tables
        array_id_heva = cursor.lastrowid
    
        cnx.commit()

        # - 2: HEVA Ports ------------------------------------------------------

        print(time.ctime(time.time()) + ":",
              "Debug: HEVA:", scr_heva['host'] + ":", eva_name + ":", "Ports")

        ls_ports_raw = subprocess.check_output([config['TOOLS']['sssu'],
            "select manager " + scr_heva['host'] + " username=" +
            scr_heva['login'] + " password=" + scr_heva['password'],
            " SELECT SYSTEM " + eva_name, 
            " LS CONTROLLER FULL XML", "exit"], universal_newlines=True)

        # Create XML-structure from the sssu output
        ls_ports_xml = heva_xml(ls_ports_raw)

        root = ET.fromstring(ls_ports_xml)
        for obj in root.findall('object'):
            controller_uid = obj.find('uid').text                   # Controller UID
            controller_name = obj.find('controllername').text

            for h_port in obj.iter('hostport'):                    # Array-side port
                portname = h_port.find('portname').text             # Portname
                # format WWNs to normal style: 
                # 50014380 1139CDFC -> 50:01:43:80:11:39:cd:fc
                wwid = wwn_up2brocade(''.join((h_port.find('wwid').text).split()))      # PWWN
                nodeid = wwn_up2brocade(''.join((h_port.find('nodeid').text).split()))  # NWWN

                hostportaddress = h_port.find('hostportaddress').text
                operationalstate = h_port.find('operationalstate').text
                speed = h_port.find('speed').text
                portcondition = h_port.find('portcondition').text
                topology = h_port.find('topology').text

                # Fill in 'heva_port' table with the parsed data
                add_heva_port = ("INSERT INTO heva_port "
                                    "(array_id, controller_uid, "
                                    "controller_name, portname, wwid, nodeid, "
                                    "hostportaddress, operationalstate, "
                                    "speed, portcondition, topology) "
                                 "VALUES "
                                    "(%s, %s, %s, %s, %s, %s, %s, %s, %s, "
                                    "%s, %s)")
                data_heva_port = (array_id_heva, controller_uid,
                                  controller_name, portname, wwid, nodeid,
                                  hostportaddress, operationalstate, speed,
                                  portcondition, topology)
                cursor.execute(add_heva_port, data_heva_port)

        # - 3: HEVA Disk Groups ------------------------------------------------

        print(time.ctime(time.time()) + ":",
              "Debug: HEVA:", scr_heva['host'] + ":",
              eva_name + ":", "Disk Groups")

        ls_dg_raw = subprocess.check_output([config['TOOLS']['sssu'],
            "select manager " + scr_heva['host'] + " username=" +
            scr_heva['login'] + " password=" + scr_heva['password'],
            " SELECT SYSTEM " + eva_name, 
            " LS DISK_GROUP FULL XML", "exit"], universal_newlines=True)

        # Create XML-structure from the sssu output
        ls_dg_xml = heva_xml(ls_dg_raw)

        root = ET.fromstring(ls_dg_xml)
        # Scan for Disk Groups within the array
        for obj in root.findall('object'):
            uid = obj.find('uid').text
            diskgroupname = obj.find('diskgroupname').text
            operationalstate = obj.find('operationalstate').text
            operationalstatedetail = obj.find('operationalstatedetail').text
            totaldisks = obj.find('totaldisks').text
            levelingstate = obj.find('levelingstate').text
            levelingprogress = obj.find('levelingprogress').text
            diskdrivetype = obj.find('diskdrivetype').text
            requestedsparepolicy = obj.find('requestedsparepolicy').text
            currentsparepolicy = obj.find('currentsparepolicy').text
            totalstoragespace_raw = obj.find('totalstoragespace').text
            totalstoragespace = int(float(obj.find('totalstoragespacegb').text)
                                * 1024 * 1024)      # In KBytes
            usedstoragespace_raw = obj.find('usedstoragespace').text
            usedstoragespace =  int(float(obj.find('usedstoragespacegb').text)
                                * 1024 * 1024)      # In KBytes
            occupancyalarmlevel = obj.find('occupancyalarmlevel').text
            diskgrouptype = obj.find('diskgrouptype').text
            try:
                dgwarningalarmlevel = obj.find('dgwarningalarmlevel').text
            except AttributeError:
                dgwarningalarmlevel = 0

            # Fill in 'heva_dg' table with the parsed data
            add_heva_dg = ("INSERT INTO heva_dg "
                            "(array_id, uid, diskgroupname, operationalstate, "
                            "operationalstatedetail, totaldisks, "
                            "levelingstate, levelingprogress, diskdrivetype, "
                            "requestedsparepolicy, currentsparepolicy, "
                            "totalstoragespace_raw, totalstoragespace, "
                            "usedstoragespace_raw, usedstoragespace, "
                            "occupancyalarmlevel, diskgrouptype, "
                            "dgwarningalarmlevel) "
                           "VALUES "
                            "(%s, %s, %s, %s, %s, %s, %s, %s, %s, "
                            "%s, %s, %s, %s, %s, %s, %s, %s, %s)")
            data_heva_dg = (array_id_heva, uid, diskgroupname,
                            operationalstate, operationalstatedetail,
                            totaldisks, levelingstate, levelingprogress,
                            diskdrivetype, requestedsparepolicy,
                            currentsparepolicy, totalstoragespace_raw,
                            totalstoragespace, usedstoragespace_raw,
                            usedstoragespace, occupancyalarmlevel,
                            diskgrouptype, dgwarningalarmlevel)
            cursor.execute(add_heva_dg, data_heva_dg)

        # - 4: HEVA Hosts ------------------------------------------------------

        print(time.ctime(time.time()) + ":",
              "Debug: HEVA:", scr_heva['host'] + ":",
              eva_name + ":", "Hosts")

        ls_hosts_raw = subprocess.check_output([config['TOOLS']['sssu'],
            "select manager " + scr_heva['host'] + " username=" +
            scr_heva['login'] + " password=" + scr_heva['password'],
            " SELECT SYSTEM " + eva_name, 
            " LS HOST FULL XML", "exit"], universal_newlines=True)

        # Create XML-structure from the sssu output
        ls_hosts_xml = heva_xml(ls_hosts_raw)

        root = ET.fromstring(ls_hosts_xml)
        # Scan for Hosts within the array
        for obj in root.findall('object'):
            uid = obj.find('uid').text                                          # Host UID
            hostname = obj.find('hostname').text
            operationalstate = obj.find('operationalstate').text
            operationalstatedetail = obj.find('operationalstatedetail').text
            osmode = obj.find('osmode').text
            osmodebitmask = obj.find('osmodebitmask').text
            hosttype = obj.find('hosttype').text
            osmodeindex = obj.find('osmodeindex').text

            # Array ID
            for suid in obj.iter('parentstoragecellinfo'):
                storagecellid = suid.find('storagecellid').text

            # LUN Presentation
            for pr in obj.iter('presentation'):
                lunnumber = pr.find('lunnumber').text
                virtualdiskid = pr.find('virtualdiskid').text

                # Host WWNS
                for port in obj.iter('port'):
                    # Convert WWN to normal view and save:
                    # 1000-0000-C96C-C699 --> 10:00:00:00:c9:6c:c6:99
                    portwwn = wwn_up2brocade(''.join((port.find('portwwn').text).split('-')))

                    # Fill in 'heva_host' table with the parsed data
                    add_heva_host = ("INSERT INTO heva_host "
                                        "(array_id, uid, hostname, "
                                        "virtualdiskid, storagecellid, "
                                        "portwwn, operationalstate, "
                                        "operationalstatedetail, osmode, "
                                        "osmodebitmask, hosttype, osmodeindex) "
                                     "VALUES "
                                        "(%s, %s, %s, %s, %s, %s, "
                                        "%s, %s, %s, %s, %s, %s)")
                    data_heva_host = (array_id_heva, uid, hostname,
                                      virtualdiskid, storagecellid, portwwn, 
                                      operationalstate, operationalstatedetail,
                                      osmode, osmodebitmask, hosttype, 
                                      osmodeindex)
                    cursor.execute(add_heva_host, data_heva_host)

        # - 5: HEVA VDisks -----------------------------------------------------

        print(time.ctime(time.time()) + ":",
              "Debug: HEVA:", scr_heva['host'] + ":",
              eva_name + ":", "VDisks")

        ls_vdisk_raw = subprocess.check_output([config['TOOLS']['sssu'],
            "select manager " + scr_heva['host'] + " username=" +
            scr_heva['login'] + " password=" + scr_heva['password'],
            " SELECT SYSTEM " + eva_name, 
            " LS VDISK FULL XML", "exit"], universal_newlines=True)

        # Create XML-structure from the sssu output
        ls_vdisk_xml = heva_xml(ls_vdisk_raw)

        root = ET.fromstring(ls_vdisk_xml)
        # Scan for VDisks within the array
        for obj in root.findall('object'):
            uid = obj.find('uid').text                                          # VDisk UID
            familyname  = obj.find('familyname').text                           # VDisk Name
            creationdatetime = obj.find('creationdatetime').text
            timestampmodify = obj.find('timestampmodify').text
            try:
                istpvdisk = obj.find('istpvdisk').text
            except AttributeError:
                istpvdisk = 0
            wwlunid = obj.find('wwlunid').text
            dirtyblockcount = obj.find('dirtyblockcount').text
            try:
                migrationinprogress = obj.find('migrationinprogress').text
            except AttributeError:
                migrationinprogress = 0
            operationalstate = obj.find('operationalstate').text
            operationalstatedetail = obj.find('operationalstatedetail').text
            allocatedcapacity = int(float(obj.find('allocatedcapacityblocks').text) / 2)    # In KBytes
            virtualdisktype = obj.find('virtualdisktype').text
            requestedcapacity = int(float(obj.find('requestedcapacityblocks').text) / 2)    # In KBytes
            redundancy = obj.find('redundancy').text
            writecacheactual = obj.find('writecacheactual').text
            writecache = obj.find('writecache').text
            mirrorcache = obj.find('mirrorcache').text
            readcache = obj.find('readcache').text
            virtualdiskpresented = obj.find('virtualdiskpresented').text
            writeprotect = obj.find('writeprotect').text
            diskgroupid = obj.find('diskgroupid').text
            preferredpath = obj.find('preferredpath').text
            restoreprogress = obj.find('restoreprogress').text
            hostaccess = obj.find('hostaccess').text

            # Online Controller ID
            for oc_id in obj.iter('onlinecontroller'):
                controllerid = oc_id.find('controllerid').text

                # Host presentation
                for pr in obj.iter('presentation'):
                    hostid = pr.find('hostid').text
                    lunnumber = pr.find('lunnumber').text

                    # Fill in 'heva_vdisk' table with the parsed data
                    add_heva_vdisk = ("INSERT INTO heva_vdisk "
                                        "(array_id, uid, familyname, "
                                        "creationdatetime, timestampmodify, "
                                        "istpvdisk, wwlunid, dirtyblockcount, "
                                        "migrationinprogress, "
                                        "operationalstate, "
                                        "operationalstatedetail, "
                                        "allocatedcapacity, virtualdisktype, "
                                        "requestedcapacity, redundancy, "
                                        "writecacheactual, writecache, "
                                        "mirrorcache, readcache, "
                                        "virtualdiskpresented, writeprotect, "
                                        "diskgroupid, preferredpath, "
                                        "restoreprogress, hostaccess, "
                                        "controllerid, hostid, lunnumber) "
                                      "VALUES "
                                        "(%s, %s, %s, %s, %s, %s, %s, %s, "
                                        "%s, %s, %s, %s, %s, %s, %s, %s, "
                                        "%s, %s, %s, %s, %s, %s, %s, %s, "
                                        "%s, %s, %s, %s)")
                    data_heva_vdisk = (array_id_heva, uid, familyname, 
                                       creationdatetime, timestampmodify,
                                       istpvdisk, wwlunid, dirtyblockcount,
                                       migrationinprogress, operationalstate,
                                       operationalstatedetail, 
                                       allocatedcapacity, virtualdisktype,
                                       requestedcapacity, redundancy,
                                       writecacheactual, writecache,
                                       mirrorcache, readcache,
                                       virtualdiskpresented, writeprotect,
                                       diskgroupid, preferredpath,
                                       restoreprogress, hostaccess, 
                                       controllerid, hostid, lunnumber)
                    cursor.execute(add_heva_vdisk, data_heva_vdisk)

    cnx.commit()
 
    cursor.close()
    cnx.close()

    print(time.ctime(time.time()) + ":",
            "Debug: HEVA:", scr_ibts['host'] + ":", "End Scan")

    return 0

# ------------------------------------------------------------------------------
# Create it's own lun-map for each explorer
# ------------------------------------------------------------------------------
def exp_lunmap(explorer):
    print(time.ctime(time.time()) + ":", "Debug: LMAP:", explorer)

    # Open connection with the database
    cnx = connect_db(config['DATABASE']['host'], config['DATABASE']['database'],
                     config['DATABASE']['user'], config['DATABASE']['password'])
    cursor = cnx.cursor()

    if explorer in 'HDVM':
        add_hdvm_lunmap_data = ("INSERT INTO lun_map_hdvm "
                "(`Fabric Zone`, `Host-WWN`, `Array Host-alias`, `Host OS / Mode`, "
                "`LDEV / VVOL WWN`, "
                "`LUN Capacity`, `LUN Consumed Capacity`, "
                "`RAID`, "
                "`Pool ID`, "
                "`Raid-Group`, "
                "`Raid-Group type`, "
                "`SAN Switch Host-side`, `SAN Switch Host-side Port`, "
                "`SAN Switch Array-side`, `SAN Switch Array-side Port`, "
                "`Array-WWN`, `Array Port`, `Array Host-group`, "
                "`Array Name`, `Array Serial Number / Array ID`, `Array Model`, `session_id`) "
            "SELECT "
                "bfcf_zoning.record_name, "
                "hdvm_lun.wwn, hdvm_lun.nickname, "
#                "TRIM(CONCAT(coalesce(hdvm_port.host_mode, ' '), ' ', coalesce(hdvm_port.host_mode2, ' '))), "
                "hdvm_port.host_mode, "
                "hdvm_lun.dev_num_display, "
                "hdvm_lun.capacity, "
                "hdvm_lun.consumed_capacity, "
                "IFNULL(hdvm_rg.raid_type, trim(concat(coalesce(hdvm_pool.raid_level, ' '), coalesce(concat('(', hdvm_pool.combination, ')'), ' ')))), "
                "hdvm_pool.dp_pool_id,  "
                "hdvm_rg.display_name, "
                "hdvm_rg.rg_type, "
                "bfcf_members.name, "
                "bfcf_ns.port_index, "
                "arr_bfcf_members.name, "
                "arr_bfcf_ns.port_index, "
                "hdvm_port.pwwn, hdvm_port.port_display_name, "
                "hdvm_port.nickname, "
                "hdvm_arrays.name, hdvm_arrays.serial, hdvm_arrays.display_array_type, "
                "sessions.session_id "
            "FROM sessions "
                "JOIN bfcf ON sessions.session_id = bfcf.session_id "
                "JOIN bfcf_zoning ON bfcf_zoning.bfcf_id = bfcf.bfcf_id "
                "JOIN bfcf_zoning bz ON bfcf_zoning.record_count = bz.record_count AND "
                    "bfcf_zoning.bfcf_id = bz.bfcf_id AND "
                    "bfcf_zoning.record_member != bz.record_member AND "
                    "bfcf_zoning.bfcf_id = bfcf.bfcf_id AND "
                    "bz.bfcf_id = bfcf.bfcf_id "
                "JOIN hdvm_port ON hdvm_port.pwwn = bfcf_zoning.record_member "
                "JOIN hdvm_lun ON hdvm_lun.array_id = hdvm_port.array_id AND "
                    "hdvm_lun.wwn = bz.record_member AND "
                    "hdvm_lun.port_id = hdvm_port.port_id AND "
                    "hdvm_lun.domain_id = hdvm_port.domain_id "
                "JOIN bfcf_ns ON bfcf_ns.port_name = hdvm_lun.wwn AND "
                    "bfcf_ns.bfcf_id = bfcf_zoning.bfcf_id AND "
                    "bfcf_ns.bfcf_id = bz.bfcf_id "
#                    "AND bfcf_ns.device_type LIKE '%nitiator' "
                "JOIN bfcf_ns arr_bfcf_ns ON arr_bfcf_ns.port_name = hdvm_port.pwwn AND "
                    "arr_bfcf_ns.bfcf_id = bfcf_ns.bfcf_id AND "
                    "arr_bfcf_ns.bfcf_id = bfcf_zoning.bfcf_id AND "
                    "arr_bfcf_ns.bfcf_id = bz.bfcf_id "
                "LEFT JOIN hdvm_rg ON hdvm_rg.array_id = hdvm_lun.array_id AND "
                    "hdvm_rg.array_id = hdvm_port.array_id AND "
                    "hdvm_rg.number = hdvm_lun.rg_number "
                "LEFT JOIN hdvm_pool ON hdvm_pool.array_id = hdvm_lun.array_id AND "
                    "hdvm_pool.array_id = hdvm_port.array_id AND "
                    "hdvm_pool.dp_pool_id = hdvm_lun.dp_pool_id "
                "JOIN hdvm_arrays ON hdvm_arrays.array_id = hdvm_port.array_id AND "
                    "hdvm_arrays.array_id = hdvm_lun.array_id AND "
                    "hdvm_arrays.session_id = bfcf.session_id AND "
                    "hdvm_arrays.session_id = sessions.session_id "
                "JOIN bfcf_members ON bfcf_members.bfcf_id = bfcf_zoning.bfcf_id AND "
                    "bfcf_members.bfcf_id = bz.bfcf_id AND "
                    "bfcf_members.bfcf_id = bfcf_ns.bfcf_id AND "
                    "bfcf_members.bfcf_id = arr_bfcf_ns.bfcf_id AND "
                    "bfcf_members.domain = bfcf_ns.did "
                "JOIN bfcf_members arr_bfcf_members ON arr_bfcf_members.bfcf_id = bfcf_zoning.bfcf_id AND "
                    "arr_bfcf_members.bfcf_id = bz.bfcf_id AND "
                    "arr_bfcf_members.bfcf_id = bfcf_ns.bfcf_id AND "
                    "arr_bfcf_members.bfcf_id = arr_bfcf_ns.bfcf_id AND "
                    "arr_bfcf_members.bfcf_id = bfcf_members.bfcf_id AND "
                    "arr_bfcf_members.domain = arr_bfcf_ns.did "
            "WHERE sessions.session_id = %s AND "
                    "(hdvm_rg.rg_type != 0 OR "
                    "hdvm_lun.dp_pool_id IS NULL OR "
                    "hdvm_rg.emulation IS NULL OR "
                    "hdvm_rg.display_name is null)")
        cursor.execute(add_hdvm_lunmap_data, (session_id,))

    elif explorer in '3PAR':
        add_3par_lunmap_data = ("INSERT INTO lun_map_3par "
                "(`Fabric Zone`, `Host-WWN`, `Array Host-alias`,  `Host OS / Mode`, "
                "`LDEV / VVOL WWN`, "
                "`VVOL Name`, "
                "`LUN Capacity`, `LUN Consumed Capacity`, "
                "`RAID`, "
                "`VVOL Provisioning`, `VVOL Type`, `VVOL User CPG`, "
                "`SAN Switch Host-side`, `SAN Switch Host-side Port`, "
                "`SAN Switch Array-side`, `SAN Switch Array-side Port`, "
                "`Array-WWN`, `Array Port`, "
                "`Array Name`, `Array Serial Number / Array ID`, `Array Model`, `session_id`) "
            "SELECT "
                "bfcf_zoning.record_name, "
                "3par_vlun.host_wwniscsi, 3par_vlun.hostname, 3par_host.persona, 3par_vlun.vv_wwn, 3par_vlun.vvname, "
                "3par_vvol.vsize_kb, 3par_vvol.tot_rsvr_kb, "
                "concat(3par_cpg.raid, ' (', 3par_cpg.ssz, ')'), "
                "3par_vvol.prov, 3par_vvol.vv_type, 3par_vvol.usrcpg, "
                "bfcf_members.name, "
                "bfcf_ns.port_index AS 'Host-Port Index', "
                "arr_bfcf_members.name, "
                "arr_bfcf_ns.port_index AS 'Array-Port Index', "
                "3par_port.pwwn, 3par_port.nsp, "
                "3par_arrays.system_name, concat(3par_arrays.serial_number,' / ', 3par_arrays.system_id), "
                "3par_arrays.system_model, "
                "sessions.session_id "
            "FROM sessions "
                "JOIN bfcf ON sessions.session_id = bfcf.session_id "
                "JOIN bfcf_zoning ON bfcf_zoning.bfcf_id = bfcf.bfcf_id "
                "JOIN bfcf_zoning bz ON bfcf_zoning.record_count = bz.record_count AND "
                    "bfcf_zoning.bfcf_id = bz.bfcf_id AND "
                    "bfcf_zoning.record_member != bz.record_member AND "
                    "bfcf_zoning.bfcf_id = bfcf.bfcf_id AND "
                    "bz.bfcf_id = bfcf.bfcf_id "
                "JOIN 3par_port ON 3par_port.pwwn = bfcf_zoning.record_member "
                "JOIN 3par_vlun ON 3par_vlun.port = 3par_port.nsp AND "
                    "3par_vlun.array_id = 3par_port.array_id AND "
                    "3par_vlun.host_wwniscsi = bz.record_member "
                "JOIN 3par_host ON 3par_host.host_wwniscsi = 3par_vlun.host_wwniscsi AND "
                    "3par_host.array_id = 3par_vlun.array_id AND "
                    "3par_host.array_id = 3par_port.array_id AND "
                    "3par_host.host_wwniscsi = bz.record_member AND "
                    "3par_host.host_name LIKE 3par_vlun.hostname AND "
                    "3par_host.port = 3par_port.nsp AND "
                    "3par_host.port = 3par_vlun.port "
                "JOIN bfcf_ns ON bfcf_ns.port_name = 3par_vlun.host_wwniscsi AND "
                    "bfcf_ns.bfcf_id = bfcf_zoning.bfcf_id AND "
                    "bfcf_ns.bfcf_id = bz.bfcf_id "
#                    "AND bfcf_ns.device_type LIKE '%nitiator' "
                "JOIN bfcf_ns arr_bfcf_ns ON arr_bfcf_ns.port_name = 3par_port.pwwn AND "
                    "arr_bfcf_ns.bfcf_id = bfcf_ns.bfcf_id AND "
                    "arr_bfcf_ns.bfcf_id = bfcf_zoning.bfcf_id AND "
                    "arr_bfcf_ns.bfcf_id = bz.bfcf_id "
                "JOIN 3par_vvol ON 3par_vvol.vv_wwn = 3par_vlun.vv_wwn AND "
                    "3par_vvol.array_id = 3par_vlun.array_id AND "
                    "3par_vvol.array_id = 3par_port.array_id "
                "JOIN 3par_cpg ON 3par_cpg.array_id = 3par_vvol.array_id AND "
                    "3par_cpg.cpgname = 3par_vvol.usrcpg AND "
                    "3par_cpg.array_id = 3par_vvol.array_id AND "
                    "3par_cpg.array_id = 3par_vlun.array_id AND "
                    "3par_cpg.array_id = 3par_port.array_id "
                "JOIN 3par_arrays ON 3par_arrays.array_id = 3par_port.array_id AND "
                    "3par_arrays.session_id = sessions.session_id AND "
                    "3par_arrays.session_id = bfcf.session_id AND "
                    "3par_arrays.array_id = 3par_vlun.array_id AND "
                    "3par_arrays.array_id = 3par_host.array_id AND "
                    "3par_arrays.array_id = 3par_vvol.array_id AND "
                    "3par_arrays.array_id = 3par_cpg.array_id "
                "JOIN bfcf_members ON bfcf_members.bfcf_id = bfcf_zoning.bfcf_id AND "
                    "bfcf_members.bfcf_id = bz.bfcf_id AND "
                    "bfcf_members.bfcf_id = bfcf_ns.bfcf_id AND "
                    "bfcf_members.bfcf_id = arr_bfcf_ns.bfcf_id AND "
                    "bfcf_members.domain = bfcf_ns.did "
                "JOIN bfcf_members arr_bfcf_members ON arr_bfcf_members.bfcf_id = bfcf_zoning.bfcf_id AND "
                    "arr_bfcf_members.bfcf_id = bz.bfcf_id AND "
                    "arr_bfcf_members.bfcf_id = bfcf_ns.bfcf_id AND "
                    "arr_bfcf_members.bfcf_id = arr_bfcf_ns.bfcf_id AND "
                    "arr_bfcf_members.bfcf_id = bfcf_members.bfcf_id AND "
                    "arr_bfcf_members.domain = arr_bfcf_ns.did "
            "WHERE sessions.session_id = %s")
        cursor.execute(add_3par_lunmap_data, (session_id,))

    elif explorer in 'IBTS':
        add_ibts_lunmap_data = ("INSERT INTO lun_map_ibts "
                "(`Fabric Zone`, `Host-WWN`, `SAN Switch Host-side`, "
                "`SAN Switch Host-side Port`, `SAN Switch Array-side`, "
                "`SAN Switch Array-side Port`, `Array-WWN`, `Array Name`, "
                "`Array Model`, `session_id`) "
            "SELECT "
                "bfcf_zoning.record_name, "
                "bfcf_zoning.record_member AS 'Host-WWN', "
                "bfcf_members.name AS 'Host Switch', "
                "bfcf_ns.port_index AS 'Host-Port Index', "
                "lib_bfcf_members.name AS 'Library Switch', "
                "lib_bfcf_ns.port_index AS 'Array-Port Index', "
                "bz.record_member AS 'Tape WWN', "
                "ibts_libraries.name AS 'Library Name', "
                "ibts_libraries.model AS 'Library Model', "
                "sessions.session_id "
            "FROM sessions "
                "JOIN bfcf ON sessions.session_id = bfcf.session_id "
                "JOIN bfcf_zoning ON bfcf_zoning.bfcf_id = bfcf.bfcf_id "
                "JOIN bfcf_zoning bz ON bfcf_zoning.record_count = bz.record_count AND "
                    "bfcf_zoning.bfcf_id = bz.bfcf_id AND "
                    "bfcf_zoning.record_member != bz.record_member AND "
                    "bfcf_zoning.bfcf_id = bfcf.bfcf_id AND "
                    "bz.bfcf_id = bfcf.bfcf_id "
                "JOIN ibts_drives ON ibts_drives.wwn = bz.record_member "
                "JOIN bfcf_ns ON bfcf_ns.port_name = bfcf_zoning.record_member AND "
                    "bfcf_ns.device_type LIKE \"%Initiator\" AND "
                    "bfcf_ns.bfcf_id = bfcf_zoning.bfcf_id AND "
                    "bfcf_ns.bfcf_id = bz.bfcf_id "
#                    "AND bfcf_ns.device_type LIKE '%nitiator' "
                "JOIN ibts_libraries ON ibts_libraries.library_id = ibts_drives.library_id AND "
                    "ibts_libraries.session_id = sessions.session_id "
                "JOIN bfcf_ns lib_bfcf_ns ON lib_bfcf_ns.port_name = ibts_drives.wwn AND "
                    "lib_bfcf_ns.bfcf_id = bfcf_ns.bfcf_id AND "
                    "lib_bfcf_ns.bfcf_id = bfcf_zoning.bfcf_id AND "
                    "lib_bfcf_ns.bfcf_id = bz.bfcf_id "
                "JOIN bfcf_members ON bfcf_members.bfcf_id = bfcf_zoning.bfcf_id AND "
                   "bfcf_members.bfcf_id = bz.bfcf_id AND "
                   "bfcf_members.bfcf_id = bfcf_ns.bfcf_id AND "
                   "bfcf_members.bfcf_id = lib_bfcf_ns.bfcf_id AND "
                   "bfcf_members.domain = bfcf_ns.did "
                "JOIN bfcf_members lib_bfcf_members ON lib_bfcf_members.bfcf_id = bfcf_zoning.bfcf_id AND "
                    "lib_bfcf_members.bfcf_id = bz.bfcf_id AND "
                    "lib_bfcf_members.bfcf_id = bfcf_ns.bfcf_id AND "
                    "lib_bfcf_members.bfcf_id = lib_bfcf_ns.bfcf_id AND "
                    "lib_bfcf_members.bfcf_id = bfcf_members.bfcf_id AND "
                    "lib_bfcf_members.domain = lib_bfcf_ns.did "
            "WHERE sessions.session_id = %s")
        cursor.execute(add_ibts_lunmap_data, (session_id,))
    
    elif explorer in 'HEVA':
        add_heva_lunmap_data = ("INSERT INTO lun_map_heva "
                "(`Fabric Zone`, `Host-WWN`, `Array Host-alias`, `Host OS / Mode`, "
                "`VDISK WWLUNID`, "
                "`VDISK Name`, "
                "`LUN Capacity`, `LUN Consumed Capacity`, "
                "`RAID`, "
                "`Disk-Group`, "
                "`SAN Switch Host-side`, `SAN Switch Host-side Port`, "
                "`SAN Switch Array-side`, `SAN Switch Array-side Port`, "
                "`Array-WWN`, `Array Port`, "
                "`Array Name`, `Array SN WWN`, `Array Model`, `session_id`) "
             "SELECT "
                "bfcf_zoning.record_name, heva_host.portwwn, heva_host.hostname, "
                "heva_host.osmode, heva_vdisk.wwlunid, heva_vdisk.familyname, "
                "heva_vdisk.allocatedcapacity, heva_vdisk.requestedcapacity, "
                "heva_vdisk.redundancy, heva_dg.diskgroupname, "
                "bfcf_members.name, bfcf_ns.port_index AS 'Host-Port Index', "
                "arr_bfcf_members.name, arr_bfcf_ns.port_index AS 'Array-Port Index', "
                "heva_port.wwid, heva_port.controller_name, heva_arrays.name, "
                "heva_arrays.wwn, heva_arrays.systemtype, sessions.session_id "
            "FROM sessions "
            "JOIN bfcf ON sessions.session_id = bfcf.session_id "
            "JOIN bfcf_zoning ON bfcf_zoning.bfcf_id = bfcf.bfcf_id "
            "JOIN bfcf_zoning bz ON bfcf_zoning.record_count = bz.record_count AND "
                "bfcf_zoning.bfcf_id = bz.bfcf_id AND "
                "bfcf_zoning.record_member != bz.record_member AND "
                "bfcf_zoning.bfcf_id = bfcf.bfcf_id AND "
                "bz.bfcf_id = bfcf.bfcf_id "
            "JOIN heva_port ON heva_port.wwid = bfcf_zoning.record_member "
            "JOIN heva_arrays ON heva_arrays.array_id = heva_port.array_id AND "
                "heva_arrays.session_id = sessions.session_id "
            "JOIN heva_host ON heva_host.storagecellid = heva_arrays.uid AND "
                "heva_host.portwwn = bz.record_member AND "
                "heva_host.array_id = heva_arrays.array_id AND "
                "heva_host.array_id = heva_port.array_id "
            "JOIN heva_vdisk ON heva_vdisk.hostid = heva_host.uid AND "
                "heva_vdisk.uid = heva_host.virtualdiskid AND "
                "heva_vdisk.array_id = heva_port.array_id AND "
                "heva_vdisk.array_id = heva_arrays.array_id AND "
                "heva_vdisk.array_id = heva_host.array_id "
            "JOIN bfcf_ns ON bfcf_ns.port_name = heva_host.portwwn AND "
                "bfcf_ns.bfcf_id = bfcf_zoning.bfcf_id AND "
                "bfcf_ns.bfcf_id = bz.bfcf_id "
#                "AND bfcf_ns.device_type LIKE '%nitiator' "
            "JOIN bfcf_ns arr_bfcf_ns ON arr_bfcf_ns.port_name = heva_port.wwid AND "
                "arr_bfcf_ns.bfcf_id = bfcf_ns.bfcf_id AND "
                "arr_bfcf_ns.bfcf_id = bfcf_zoning.bfcf_id AND "
                "arr_bfcf_ns.bfcf_id = bz.bfcf_id "
            "JOIN heva_dg ON heva_dg.uid = heva_vdisk.diskgroupid AND "
                "heva_dg.array_id = heva_host.array_id AND "
                "heva_dg.array_id = heva_port.array_id AND "
                "heva_dg.array_id = heva_vdisk.array_id "
            "JOIN bfcf_members ON bfcf_members.bfcf_id = bfcf_zoning.bfcf_id AND "
                "bfcf_members.bfcf_id = bz.bfcf_id AND "
                "bfcf_members.bfcf_id = bfcf_ns.bfcf_id AND "
                "bfcf_members.bfcf_id = arr_bfcf_ns.bfcf_id AND "
                "bfcf_members.domain = bfcf_ns.did "
            "JOIN bfcf_members arr_bfcf_members ON arr_bfcf_members.bfcf_id = bfcf_zoning.bfcf_id AND "
                "arr_bfcf_members.bfcf_id = bz.bfcf_id AND "
                "arr_bfcf_members.bfcf_id = bfcf_ns.bfcf_id AND "
                "arr_bfcf_members.bfcf_id = arr_bfcf_ns.bfcf_id AND "
                "arr_bfcf_members.bfcf_id = bfcf_members.bfcf_id AND "
                "arr_bfcf_members.domain = arr_bfcf_ns.did "
            "WHERE sessions.session_id = %s")
        cursor.execute(add_heva_lunmap_data, (session_id,))
 
    elif explorer in 'UNKN':
        add_unkn_lunmap_data = ("INSERT INTO lun_map_unknown "
                "(`Fabric Zone`, `Initiatort-WWN`, `Initiator Device Type`, "
                "`Initiator Port Symb`, `Initiator Node Symb`, "
                "`SAN Switch Initiator-side`, `SAN Switch Initiator-side Port`, "
                "`SAN Switch Target-side Port`, `SAN Switch Target-side`, "
                "`Target Device Type`, `Target Port Symb`, `Target Node Symb`, "
                "`Target-WWN`, `session_id`) "
            "SELECT "
                "i_bfcf_zoning.record_name AS `Fabric Zone`, "
                "i_bfcf_zoning.record_member AS `Initiator-WWN`, "
                "i_bfcf_ns.device_type AS `Initiator Device Type`, "
                "i_bfcf_ns.port_symb AS `Initiator Port Symb`, "
                "i_bfcf_ns.node_symb AS `Initiator Node Symb`, "
                "i_bfcf_members.name AS `SAN Switch Initiator-side`, "
                "i_bfcf_ns.port_index AS `SAN Switch Initiator-side Port`, "
                "t_bfcf_ns.port_index AS `SAN Switch Target-side Port`, "
                "t_bfcf_members.name AS `SAN Switch Target-side`, "
                "t_bfcf_ns.device_type AS `Target Device Type`, "
                "t_bfcf_ns.port_symb AS `Target Port Symb`, "
                "t_bfcf_ns.node_symb AS `Target Node Symb`, "
                "t_bfcf_zoning.record_member AS `Target-WWN`, "
                "sessions.session_id "
            "FROM sessions "
                "JOIN bfcf ON sessions.session_id = bfcf.session_id "
                "JOIN bfcf_zoning i_bfcf_zoning ON i_bfcf_zoning.bfcf_id = bfcf.bfcf_id "
                "JOIN bfcf_zoning t_bfcf_zoning ON i_bfcf_zoning.record_count = t_bfcf_zoning.record_count AND "
                    "i_bfcf_zoning.bfcf_id = t_bfcf_zoning.bfcf_id AND "
                    "i_bfcf_zoning.record_member != t_bfcf_zoning.record_member AND "
                    "i_bfcf_zoning.bfcf_id = bfcf.bfcf_id AND "
                    "t_bfcf_zoning.bfcf_id = bfcf.bfcf_id "
                "JOIN bfcf_ns i_bfcf_ns ON i_bfcf_ns.port_name = i_bfcf_zoning.record_member AND "
                    "i_bfcf_ns.device_type LIKE '%nitiator%' AND " 
                    "i_bfcf_ns.bfcf_id = i_bfcf_zoning.bfcf_id "
                "JOIN bfcf_ns t_bfcf_ns ON t_bfcf_ns.port_name = t_bfcf_zoning.record_member AND "
                    "t_bfcf_ns.device_type NOT LIKE '%initiator' AND "
                    "t_bfcf_ns.bfcf_id = i_bfcf_zoning.bfcf_id "
                "JOIN bfcf_members i_bfcf_members ON i_bfcf_members.bfcf_id = i_bfcf_zoning.bfcf_id AND "
                    "i_bfcf_members.bfcf_id = t_bfcf_zoning.bfcf_id AND "
                    "i_bfcf_members.bfcf_id = i_bfcf_ns.bfcf_id AND "
                    "i_bfcf_members.bfcf_id = t_bfcf_ns.bfcf_id AND "
                    "i_bfcf_members.domain = i_bfcf_ns.did "
                "JOIN bfcf_members t_bfcf_members ON t_bfcf_members.bfcf_id = i_bfcf_zoning.bfcf_id AND "
                    "t_bfcf_members.bfcf_id = t_bfcf_zoning.bfcf_id AND "
                    "t_bfcf_members.bfcf_id = i_bfcf_ns.bfcf_id AND "
                    "t_bfcf_members.bfcf_id = t_bfcf_ns.bfcf_id AND "
                    "t_bfcf_members.bfcf_id = i_bfcf_members.bfcf_id AND "
                    "t_bfcf_members.domain = t_bfcf_ns.did "
                "WHERE "
                    "i_bfcf_zoning.record_member NOT IN (SELECT DISTINCT pwwn FROM d81s.hdvm_port) AND "
                    "i_bfcf_zoning.record_member NOT IN (SELECT pwwn FROM d81s.3par_port WHERE mode='target') AND "
                    "i_bfcf_zoning.record_member NOT IN (SELECT wwid FROM d81s.heva_port) AND "
                    "i_bfcf_zoning.record_member NOT IN (SELECT wwn FROM d81s.ibts_drives) AND "
                    "t_bfcf_zoning.record_member NOT IN (SELECT DISTINCT pwwn FROM d81s.hdvm_port) AND "
                    "t_bfcf_zoning.record_member NOT IN (SELECT pwwn FROM d81s.3par_port) AND "
                    "t_bfcf_zoning.record_member NOT IN (SELECT wwid FROM d81s.heva_port) AND "
                    "t_bfcf_zoning.record_member NOT IN (SELECT wwn FROM d81s.ibts_drives) AND "
                    "sessions.session_id = %s")
        cursor.execute(add_unkn_lunmap_data, (session_id,))

    else:
        print(time.ctime(time.time()) + ":",
              "Debug: LMAP: Skipping the unknown explorer:", explorer)

    cnx.commit()
    cursor.close()
    cnx.close()

    print(time.ctime(time.time()) + ":", "Debug: LMAP:", explorer, "End")

# ------------------------------------------------------------------------------
# Create the FULL LUN-MAP
# ------------------------------------------------------------------------------
def full_lunmap():
    print(time.ctime(time.time()) + ":", "Debug: LMAP:", "Full LUN-Map")

    cnx = connect_db(config['DATABASE']['host'], config['DATABASE']['database'],
                     config['DATABASE']['user'], config['DATABASE']['password'])
    cursor = cnx.cursor()

    add_hdvm_full_lunmap_data = ("INSERT INTO lun_map "
            "(`Fabric Zone`, `Host-WWN`, `Array Host-alias`, `Host OS / Mode`, "
            "`LDEV / VVOL WWN`, "
            "`LUN Capacity`, `LUN Consumed Capacity`, "
            "`RAID`, "
            "`Pool ID`, `Raid-Group`, `Raid-Group type`, "
            "`SAN Switch Host-side`, `SAN Switch Host-side Port`, "
            "`SAN Switch Array-side`, `SAN Switch Array-side Port`, "
            "`Array-WWN`, `Array Port`, `Array Host-group`, "
            "`Array Name`, `Array Serial Number / Array ID`, `Array Model`, `session_id`) "
        "SELECT "
            "`Fabric Zone`, `Host-WWN`, `Array Host-alias`,  `Host OS / Mode`, "
            "`LDEV / VVOL WWN`, "
            "`LUN Capacity`, `LUN Consumed Capacity`, "
            "`RAID`, "
            "`Pool ID`, `Raid-Group`, `Raid-Group type`, "
            "`SAN Switch Host-side`, `SAN Switch Host-side Port`, "
            "`SAN Switch Array-side`, `SAN Switch Array-side Port`, "
            "`Array-WWN`, `Array Port`, `Array Host-group`, "
            "`Array Name`, `Array Serial Number / Array ID`, `Array Model`, `session_id` "
        "FROM lun_map_hdvm WHERE session_id = %s")
    cursor.execute(add_hdvm_full_lunmap_data, (session_id,))

    add_3par_full_lunmap_data = ("INSERT INTO lun_map "
            "(`Fabric Zone`, `Host-WWN`, `Array Host-alias`, `Host OS / Mode`, "
            "`LDEV / VVOL WWN`, "
            "`VVOL Name`, "
            "`LUN Capacity`, `LUN Consumed Capacity`, "
            "`RAID`, "
            "`VVOL Provisioning`, `VVOL Type`, `VVOL User CPG`, "
            "`SAN Switch Host-side`, `SAN Switch Host-side Port`, "
            "`SAN Switch Array-side`, `SAN Switch Array-side Port`, "
            "`Array-WWN`, `Array Port`, "
            "`Array Name`, `Array Serial Number / Array ID`, `Array Model`, `session_id`) "
        "SELECT "
            "`Fabric Zone`, `Host-WWN`, `Array Host-alias`,  `Host OS / Mode`, "
            "`LDEV / VVOL WWN`, "
            "`VVOL Name`, "
            "`LUN Capacity`, `LUN Consumed Capacity`, "
            "`RAID`, "
            "`VVOL Provisioning`, `VVOL Type`, `VVOL User CPG`, "
            "`SAN Switch Host-side`, `SAN Switch Host-side Port`, "
            "`SAN Switch Array-side`, `SAN Switch Array-side Port`, "
            "`Array-WWN`, `Array Port`, "
            "`Array Name`, `Array Serial Number / Array ID`, `Array Model`, `session_id` "
        "FROM lun_map_3par WHERE session_id = %s")
    cursor.execute(add_3par_full_lunmap_data, (session_id,))

    add_ibts_full_lunmap_data = ("INSERT INTO lun_map "
            "(`Fabric Zone`, `Host-WWN`, "
            "`SAN Switch Host-side`, `SAN Switch Host-side Port`, "
            "`SAN Switch Array-side`, `SAN Switch Array-side Port`, "
            "`Array-WWN`, "
            "`Array Name`, `Array Model`, `session_id`) "
        "SELECT "
            "`Fabric Zone`, `Host-WWN`, "
            "`SAN Switch Host-side`, `SAN Switch Host-side Port`, "
            "`SAN Switch Array-side`, `SAN Switch Array-side Port`, "
            "`Array-WWN`, "
            "`Array Name`, `Array Model`, `session_id` "
        "FROM lun_map_ibts WHERE session_id = %s")
    cursor.execute(add_ibts_full_lunmap_data, (session_id,))

    add_heva_full_lunmap_data = ("INSERT INTO lun_map "
            "(`Fabric Zone`, `Host-WWN`, `Array Host-alias`, `Host OS / Mode`, "
            "`LDEV / VVOL WWN`, "
            "`VVOL Name`, "
            "`LUN Capacity`, `LUN Consumed Capacity`, "
            "`RAID`, "
            "`VVOL User CPG`, "
            "`SAN Switch Host-side`, `SAN Switch Host-side Port`, "
            "`SAN Switch Array-side`, `SAN Switch Array-side Port`, "
            "`Array-WWN`, `Array Port`, "
            "`Array Name`, `Array Serial Number / Array ID`, `Array Model`, `session_id`) "
        "SELECT "
            "`Fabric Zone`, `Host-WWN`, `Array Host-alias`,  `Host OS / Mode`, "
            "`VDISK WWLUNID`, "
            "`VDISK Name`, "
            "`LUN Capacity`, `LUN Consumed Capacity`, "
            "`RAID`, "
            "`Disk-Group`, "
            "`SAN Switch Host-side`, `SAN Switch Host-side Port`, "
            "`SAN Switch Array-side`, `SAN Switch Array-side Port`, "
            "`Array-WWN`, `Array Port`, "
            "`Array Name`, `Array SN WWN`, `Array Model`, `session_id` "
        "FROM lun_map_heva WHERE session_id = %s")
    cursor.execute(add_heva_full_lunmap_data, (session_id,))

    cnx.commit()

    cursor.close()
    cnx.close()


# ------------------------------------------------------------------------------
# Deck 8 One Step - main()
# ------------------------------------------------------------------------------

# Read INI-file
config = read_ini('d81s.ini') 

# Set limit for database connections
if config['DATABASE']['connections_limit']:
    db_connections_limit = int(config['DATABASE']['connections_limit'])

# Start the new discovery session 
session_id = start_session()

exp_threads = []
for scr_bfcs in sources_bfcs:
    thr = threading.Thread(target=explore_bfcs, args=(scr_bfcs,))
    exp_threads.append(thr)

for scr_hdvm in sources_hdvm:
    thr = threading.Thread(target=explore_hdvm, args=(scr_hdvm,))
    exp_threads.append(thr)

for scr_3par in sources_3par:
    thr = threading.Thread(target=explore_3par, args=(scr_3par,))
    exp_threads.append(thr)

for scr_ibts in sources_ibts:
    thr = threading.Thread(target=explore_ibts, args=(scr_ibts,))
    exp_threads.append(thr)

for scr_heva in sources_heva:
    thr = threading.Thread(target=explore_heva, args=(scr_heva,))
    exp_threads.append(thr)


for t in exp_threads:
    t.start()
    while len(threading.enumerate()) > db_connections_limit:
        time.sleep(1)
        print(time.ctime(time.time()) + ":",
              "Debug: CONN: Waiting for the free connection with the Database")

for t in exp_threads:
    t.join()

# Create LUN-Map for each explorer
tlm_hdvm = threading.Thread(target=exp_lunmap, args=('HDVM',))
tlm_3par = threading.Thread(target=exp_lunmap, args=('3PAR',))
tlm_ibts = threading.Thread(target=exp_lunmap, args=('IBTS',))
tlm_heva = threading.Thread(target=exp_lunmap, args=('HEVA',))
tlm_hdvm.start()
tlm_3par.start()
tlm_ibts.start()
tlm_heva.start()
tlm_hdvm.join()
tlm_3par.join()
tlm_ibts.join()
tlm_heva.join()

# Create the LUN-Map for the Unknown Initiators/Targets
exp_lunmap('UNKN')

# Creat the LUN-MAP for the whole SAN/Storage
full_lunmap()

end_session()

print(time.ctime(time.time()) + ":", "Rest Avatar, you need it")
exit(0)

