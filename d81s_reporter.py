#!/usr/bin/python3
# -*- coding: utf-8 -*-

# ------------------------------------------------------------------------------
# Deck 8 One Step - Reporter
# ------------------------------------------------------------------------------

import configparser
import mysql.connector
from mysql.connector import errorcode

import xlsxwriter

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
            exit(1)
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print(time.ctime(time.time()) + ":",
                  "Fatal: Database does not exists")
            exit(1)
        else:
            print(err)
            exit(1)

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

    # Fetch [REPORTER] variables

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
# Get the data from the DB executing the stored procedure
# ------------------------------------------------------------------------------
def get_data_proc(db_stored_proc_name, session_id):

    print(time.ctime(time.time()) + ":",
          "Report generation: Start:",
          db_stored_proc_name)

    # Connect with the DB
    cnx = connect_db(config['DATABASE']['host'], config['DATABASE']['database'],
                     config['DATABASE']['user'], config['DATABASE']['password'])
    cursor = cnx.cursor()

    # Run the stored procedure 
    if 'get_fresh_session' in db_stored_proc_name:
        cursor.callproc(db_stored_proc_name, args=())
    else:
        cursor.callproc(db_stored_proc_name, args=(session_id,))

    # Save the result
    for result in cursor.stored_results():
       fresh_data = result.fetchall()

    cursor.close()
    cnx.close()

    print(time.ctime(time.time()) + ":",
          "Report generation: End:",
          db_stored_proc_name)

    return fresh_data

# ------------------------------------------------------------------------------
# Get the data from the DB executing SQL query
# ------------------------------------------------------------------------------
def get_data_query(t_parent, t_set, headers, session_id, t_type):
    print(time.ctime(time.time()) + ":", "Report generation: Start:", t_set)

    # Connect with the DB
    cnx = connect_db(config['DATABASE']['host'], config['DATABASE']['database'],
                     config['DATABASE']['user'], config['DATABASE']['password'])
    cursor = cnx.cursor()

    # Form the query
    if 'array' in t_type:
        select_query = ("SELECT " + headers + " FROM " + t_set + " "
                        "JOIN " + t_parent + " ON " + 
                        t_set + ".array_id = " + t_parent + ".array_id "
                        "WHERE " + t_parent + ".session_id=" + 
                        str(session_id) + ";")

    elif 'library' in t_type:
        select_query = ("SELECT " + headers + " FROM " + t_set + " "
                        "JOIN " + t_parent + " ON " + 
                        t_set + ".library_id = " + t_parent + ".library_id "
                        "WHERE " + t_parent + ".session_id=" + 
                        str(session_id) + ";")

    elif 'fabric' in t_type:
        select_query = ("SELECT " + headers + " FROM " + t_set + " "
                        "JOIN " + t_parent + " ON " + 
                        t_set + ".bfcf_id = " + t_parent + ".bfcf_id "
                        "WHERE " + t_parent + ".session_id=" + 
                        str(session_id) + ";")

    else:
        print(time.ctime(time.time()) + ":",
              "Fatal: Unknown type of the source in the get_data_query()")
        exit(1)

    data_query = ()
    cursor.execute(select_query, data_query)

    result = cursor.fetchall()

    cursor.close()
    cnx.close()

    print(time.ctime(time.time()) + ":",
          "Report generation: End:",
          t_set)

    return result


# ------------------------------------------------------------------------------
# Write the LUN MAP on the new worksheet
# ------------------------------------------------------------------------------
def write_lun_map(workbook, output_type, lun_map_source):

    print(time.ctime(time.time()) + ":", "Report output: Start: LUN-MAP")

    if len(lun_map_source) == 0:
        print(time.ctime(time.time()) + ":",
              'Report output: Empty:',
              'LUN-MAP')
        return 1

    if 'xlsx' in output_type:
        # Create the new MS Excel Worksheet
        worksheet = workbook.add_worksheet('LUN-MAP')

        header_lun_map = (['Fabric Zone', 'Host-WWN', 'Array Host-alias',
                           'Host OS / Mode', 'LDEV / VVOL WWN', 'VVOL Name',
                           'RAID', 'LUN Capacity, KB', 'LUN Used Capacity, KB',
                           'Pool ID', 'Raid-Group', 'Raid-Group type',
                           'VVOL Provisioning', 'VVOL Type', 'VVOL User CPG',
                           'SAN Switch Host-side', 'SAN Switch Host-side Port',
                           'SAN Switch Array-side', 'SAN Switch Array-side Port',
                           'Array-WWN', 'Array Port', 'Array Host-group',
                           'Array Name', 'Array Serial Number / Array ID',
                           'Array Model'])

        header_format = workbook.add_format({'bold': True})
        header_format.set_text_wrap()

        # Write header
        col = 0
        for fld_hdr in (header_lun_map):
            worksheet.write(0, col, fld_hdr, header_format)
            col += 1

        # Write the LUN-MAP data
        col = 0
        row = 1
        for ln in lun_map_source:
            for fld in ln:
                if col > 1:
                    worksheet.write(row, col - 2, fld)
                col += 1
            row += 1
            col = 0

        # Set autofilter
        worksheet.autofilter(0, 0, row, 24)

        # Set the default column width
        worksheet.set_column(0, 24, 23)

        # Set exeptions for the column width
        worksheet.set_column(5, 5, 34)
        worksheet.set_column(6, 8, 18)
        worksheet.set_column(9, 9, 9)
        worksheet.set_column(10, 10, 13)
        worksheet.set_column(11, 13, 12)
        worksheet.set_column(16, 16, 15)
        worksheet.set_column(18, 18, 16)
        worksheet.set_column(20, 20, 12)
        worksheet.set_column(21, 21, 30)
        worksheet.set_column(22, 22, 34)
        worksheet.set_column(24, 24, 15)

    else:
        print(time.ctime(time.time()) + ":",
              "Fatal: Report output: LUN-MAP:",
              "Unknown output format was specified")


    print(time.ctime(time.time()) + ":", "Report output: End: LUN-MAP")


# ------------------------------------------------------------------------------
# Write the LUN MAP UNKNOWN devices on the new worksheet
# ------------------------------------------------------------------------------
def write_lun_map_unknown(workbook, output_type, lun_map_unknown_source):

    print(time.ctime(time.time()) + ":",
          "Report output: Start: LUN-MAP-UNKNOWN")

    if len(lun_map_unknown_source) == 0:
        print(time.ctime(time.time()) + ":",
              'Report output: Empty:',
              'LUN-MAP-UNKNOWN')
        return 1

    if 'xlsx' in output_type:
        # Create the new MS Excel Worksheet
        worksheet = workbook.add_worksheet('LUN-MAP-UNKNOWN')

        header_lun_map_unknown = (['Fabric Zone', 'Initiator-WWN',
                                   'Initiator Device Type',
                                   'Initiator Port Symb', 'Initiator Node Symb',
                                   'SAN Switch Initiator-side',
                                   'SAN Switch Initiator-side Port',
                                   'SAN Switch Target-side Port',
                                   'SAN Switch Target-side',
                                   'Target Port Symb', 'Target Node Symb',
                                   'Target Device Type', 'Target-WWN'])

        header_format = workbook.add_format({'bold': True})
        header_format.set_text_wrap()

        # Write header
        col = 0
        for fld_hdr in (header_lun_map_unknown):
            worksheet.write(0, col, fld_hdr, header_format)
            col += 1

        # Write the data to the sheet
        col = 0
        row = 1
        for ln in lun_map_unknown_source:
            for fld in ln:
                if col > 1:
                    worksheet.write(row, col - 2, fld)
                col += 1
            row += 1
            col = 0

        # Set autofilter
        worksheet.autofilter(0, 0, row, 12)

        # Set the default column width
        worksheet.set_column(0, 24, 23)

        # Set exeptions for the column width
        worksheet.set_column(3, 4, 40)
        worksheet.set_column(5, 8, 16)
        worksheet.set_column(9, 9, 40)
        worksheet.set_column(10, 10, 45)
    else:
        print(time.ctime(time.time()) + ":",
                "Fatal: Report output: LUN-MAP-UNKNOWN:",
                "Unknown output format was specified")

    print(time.ctime(time.time()) + ":", "Report output: End: LUN-MAP-UNKNOWN")


# ------------------------------------------------------------------------------
# Write the VOLUMES CAPACITY VS USED on the new worksheet
# ------------------------------------------------------------------------------
def write_capacity_vs_used(workbook, output_type, capacity_vs_used_source):

    print(time.ctime(time.time()) + ":",
          "Report output: Start: VOLUMES CAPACITY VS USED")

    if len(capacity_vs_used_source) == 0:
        print(time.ctime(time.time()) + ":",
              'Report output: Empty:',
              'VOLUMES CAPACITY VS USED')
        return 1

    if 'xlsx' in output_type:
        # Create the new MS Excel Worksheet
        worksheet = workbook.add_worksheet('VOLUMES CAPACITY vs USED')

        header_capacity_vs_used = (['Fabric Zone', 'LDEV / VVOL WWN', 'RAID',
                                    'LUN Capacity, KB', 'LUN Used Capacity, KB',
                                    'LUN Free Capacity, GB', 'Used %',
                                    'Array Name',
                                    'Array Serial Number / Array ID'])

        header_format = workbook.add_format({'bold': True})
        header_format.set_text_wrap()

        # Write header
        col = 0
        for fld_hdr in (header_capacity_vs_used):
            worksheet.write(0, col, fld_hdr, header_format)
            col += 1

        # Write the data to the sheet 
        col = 0
        row = 1
        for ln in capacity_vs_used_source:
            for fld in ln:
                worksheet.write(row, col, fld)
                col += 1
            row += 1
            col = 0

        # Set autofilter
        worksheet.autofilter(0, 0, row, 8)

        # Set the default column width
        worksheet.set_column(0, 8, 16)

       # Set exeptions for the column width
        worksheet.set_column(0, 1, 23)
        worksheet.set_column(2, 6, 15)
        worksheet.set_column(7, 7, 32)
        worksheet.set_column(8, 8, 23)

    else:
        print(time.ctime(time.time()) + ":",
                "Fatal: Report output: VOLUMES CAPACITY VS USED:",
                "Unknown output format was specified")

    print(time.ctime(time.time()) + ":",
          "Report output: End: VOLUMES CAPACITY VS USED")


# ------------------------------------------------------------------------------
# Write the HDVM-arrays on the new worksheet
# ------------------------------------------------------------------------------
def write_hdvm_arrays(workbook, output_type, hdvm_arrays_source):

    print(time.ctime(time.time()) + ":",
          "Report output: Start: HDVM-Arrays")

    if len(hdvm_arrays_source) == 0:
        print(time.ctime(time.time()) + ":",
              'Report output: Empty:',
               'HDVM-Arrays')
        return 1

    if 'xlsx' in output_type:
        # Create the new MS Excel Worksheet
        worksheet = workbook.add_worksheet('HDVM-Arrays')

        header_hdvm_arrays = (['Name', 'Serial', 'Array type',
                               'Display array type', 'Capacity, KB',
                               'Allocated capacity, KB', 'Free capacity, KB',
                               'Total free space, KB', 'Controllers', 'Cache',
                               'Hardware revision', 'Controller version'])

        header_format = workbook.add_format({'bold': True})
        header_format.set_text_wrap()

        # Write header
        col = 0
        for fld_hdr in (header_hdvm_arrays):
            worksheet.write(0, col, fld_hdr, header_format)
            col += 1

        # Write the data to the sheet
        col = 0
        row = 1
        for ln in hdvm_arrays_source:
            for fld in ln:
                if col > 2:
                    worksheet.write(row, col - 3, fld)
                col += 1
            row += 1
            col = 0

        # Set autofilter
        worksheet.autofilter(0, 0, row, 11)

        # Set exeptions for the column width
        worksheet.set_column(0, 0, 35)

        # Set the default column width
        worksheet.set_column(1, 11, 15)

    else:
        print(time.ctime(time.time()) + ":",
                "Fatal: Report output: HDVM-Arrays:",
                "Unknown output format was specified")

    print(time.ctime(time.time()) + ":",
          "Report output: End: HDVM-Arrays")


# ------------------------------------------------------------------------------
# Write the 3PAR-arrays on the new worksheet
# ------------------------------------------------------------------------------
def write_3par_arrays(workbook, output_type, threepar_arrays_source):

    print(time.ctime(time.time()) + ":",
          "Report output: Start: 3PAR-Arrays")

    if len(threepar_arrays_source) == 0:
        print(time.ctime(time.time()) + ":",
              'Report output: Empty:',
              '3PAR-Arrays')
        return 1

    if 'xlsx' in output_type:
        # Create the new MS Excel Worksheet
        worksheet = workbook.add_worksheet('3PAR-Arrays')

        header_3par_arrays = (['System name', 'System model', 'Serial number',
                               'System ID', 'Number of nodes', 'Master node', 
                               'Total capacity, KB', 'Allocated capacity, KB',
                               'Free capacity, KB', 'Failed capacity, KB',
                               'Location', 'Owner', 'Contact', 'Comment'])

        header_format = workbook.add_format({'bold': True})
        header_format.set_text_wrap()

        # Write header
        col = 0
        for fld_hdr in (header_3par_arrays):
            worksheet.write(0, col, fld_hdr, header_format)
            col += 1

        # Write the data to the sheet
        col = 0
        row = 1
        for ln in threepar_arrays_source:
            for fld in ln:
                if col > 2:
                    worksheet.write(row, col - 3, fld)
                col += 1
            row += 1
            col = 0

        # Set autofilter
        worksheet.autofilter(0, 0, row, 13)

        # Set the default column width
        worksheet.set_column(0, 15, 20)

        # Set exeptions for the column width
        worksheet.set_column(2, 9, 12)
        worksheet.set_column(10, 10, 40)
        worksheet.set_column(13, 13, 120)

    else:
        print(time.ctime(time.time()) + ":",
                "Fatal: Report output: 3PAR-Arrays:",
                "Unknown output format was specified")

    print(time.ctime(time.time()) + ":",
          "Report output: End: 3PAR-Arrays")


# ------------------------------------------------------------------------------
# Write the HEVA-arrays on the new worksheet
# ------------------------------------------------------------------------------
def write_heva_arrays(workbook, output_type, heva_arrays_source):

    print(time.ctime(time.time()) + ":",
          "Report output: Start: HEVA-Arrays")

    if len(heva_arrays_source) == 0:
        print(time.ctime(time.time()) + ":",
              'Report output: Empty:',
              'HEVA-Arrays')
        return 1
    
    if 'xlsx' in output_type:
        # Create the new MS Excel Worksheet
        worksheet = workbook.add_worksheet('HEVA-Arrays')

        header_heva_arrays = (['Name', 'WWN', 'Operational state',
                               'Operational state detail', 'License state',
                               'Comments', 'UID', 'HEX UID', 'System type',
                               'Total storage space, KB', 'Used storage space, KB',
                               'Available storage space, KB', 'Firmware version',
                               'Nscfw version', 'Controller memory',
                               'Controller cache'])

        header_format = workbook.add_format({'bold': True})
        header_format.set_text_wrap()

        # Write header
        col = 0
        for fld_hdr in (header_heva_arrays):
            worksheet.write(0, col, fld_hdr, header_format)
            col += 1

        # Write the data to the sheet
        col = 0
        row = 1
        for ln in heva_arrays_source:
            for fld in ln:
                if col > 2:
                    worksheet.write(row, col - 3, fld)
                col += 1
            row += 1
            col = 0

        # Set autofilter
        worksheet.autofilter(0, 0, row, 15)

        # Set the default column width
        worksheet.set_column(0, 15, 20)

        # Set exeptions for the column width
        worksheet.set_column(2, 4, 12)
        worksheet.set_column(6, 7, 43)
        worksheet.set_column(8, 8, 12)
        worksheet.set_column(12, 12, 12)
        worksheet.set_column(14, 15, 12)

    else:
        print(time.ctime(time.time()) + ":",
                "Fatal: Report output: HEVA-Arrays:",
                "Unknown output format was specified")

    print(time.ctime(time.time()) + ":",
          "Report output: End: HEVA-Arrays")


# ------------------------------------------------------------------------------
# Write the IBTS-tapes on the new worksheet
# ------------------------------------------------------------------------------
def write_ibts_libraries(workbook, output_type, ibts_libraries_source):

    print(time.ctime(time.time()) + ":",
          "Report output: Start: IBTS-libraries")

    if len(ibts_libraries_source) == 0:
        print(time.ctime(time.time()) + ":",
              "Report output: Empty:",
              'IBTS-Libraries')
        return 1

    if 'xlsx' in output_type:
        # Create the new MS Excel Worksheet
        worksheet = workbook.add_worksheet('IBTS-Libraries')

        header_ibts_libraries = (['Name', 'Model', 'Commentary'])

        header_format = workbook.add_format({'bold': True})
        header_format.set_text_wrap()

        # Write header
        col = 0
        for fld_hdr in (header_ibts_libraries):
            worksheet.write(0, col, fld_hdr, header_format)
            col += 1

        # Write the data to the sheet
        col = 0
        row = 1
        for ln in ibts_libraries_source:
            for fld in ln:
                if col > 2:
                    worksheet.write(row, col - 3, fld)
                col += 1
            row += 1
            col = 0

        # Set autofilter
        worksheet.autofilter(0, 0, row, 2)

        # Set the default column width
        worksheet.set_column(0, 2, 20)

    else:
        print(time.ctime(time.time()) + ":",
                "Fatal: Report output: IBTS-Libraries:",
                "Unknown output format was specified")

    print(time.ctime(time.time()) + ":",
          "Report output: End: IBTS-Libraries")


# ------------------------------------------------------------------------------
# Write generic table to the workbook
# ------------------------------------------------------------------------------
def write_generic(workbook, worksheet, output_type, data_source, headers):

    print(time.ctime(time.time()) + ":", "Report output: Start:", worksheet)

    if len(data_source) == 0:
        print(time.ctime(time.time()) + ":", "Report output: Empty:", worksheet)
        return 1

    if 'xlsx' in output_type:
        # Create the new MS Excel Worksheet
        wsheet = workbook.add_worksheet(worksheet)

        header = (headers.split(','))

        header_format = workbook.add_format({'bold': True})
        header_format.set_text_wrap()

        # Write header
        col = 0
        for fld_hdr in (header):
            wsheet.write(0, col, fld_hdr, header_format)
            col += 1

        # Write the data to the sheet
        col = 0
        row = 1
        for ln in data_source:
            for fld in ln:
                wsheet.write(row, col, fld)
                col += 1
            row += 1
            col = 0

        # Set autofilter
        wsheet.autofilter(0, 0, row, len(header) - 1)

        # Set the default column width
        wsheet.set_column(0, len(header) - 1, 16)

    print(time.ctime(time.time()) + ":", "Report output: End:", worksheet)

    return 0

# ------------------------------------------------------------------------------
# Deck 8 One Step - Reporter - main()
# ------------------------------------------------------------------------------
print(time.ctime(time.time()) + ":", "Starting Reporter")

# Read INI-file
print(time.ctime(time.time()) + ":", "Read INI-file")
config = read_ini('d81s.ini')

# Get the data from the DB server
# Get the fresh session_id
session_id = get_data_proc('get_fresh_session', 0)[0][0]

# Get actual data based on the session_id
lun_map = get_data_proc('get_lun_map', session_id)
lun_map_unknown = get_data_proc('get_lun_map_unknown', session_id)
capacity_vs_used = get_data_proc('get_thp_volumes_capacity_vs_consumed_percents', session_id)
hdvm_arrays = get_data_proc('get_hdvm_arrays', session_id)
threepar_arrays = get_data_proc('get_3par_arrays', session_id)
heva_arrays = get_data_proc('get_heva_arrays', session_id)
ibts_libraries = get_data_proc('get_ibts_libraries', session_id)

# BFCF
bfcf_zoning_headers = 'record_name, record_member, fabric_name'
bfcf_zoning = get_data_query('bfcf', 'bfcf_zoning', bfcf_zoning_headers, session_id, 'fabric')
bfcf_ns_headers = 'port_type, address, cos, port_name, node_name, did, aid, alpa, fabric_port_name, device_type, port_index, port_symb, node_symb, fabric_name'
bfcf_ns = get_data_query('bfcf', 'bfcf_ns', bfcf_ns_headers, session_id, 'fabric')
bfcf_members_headers = 'domain, switchid, wwn, ip, name, principal, fabric_name'
bfcf_members = get_data_query('bfcf', 'bfcf_members', bfcf_members_headers, session_id, 'fabric')

# HDVM
hdvm_ldev_headers = 'array_group_number, dev_num, dev_num_display, raid_type, dp_pool_id, dp_type, chassis, consumed_size, ldev_status, quorum_disk, encrypted, threshold, volume_kind, emulation, size, name'
hdvm_ldev = get_data_query('hdvm_arrays', 'hdvm_ldev', hdvm_ldev_headers, session_id, 'array')
hdvm_lun_headers = 'dev_num, dev_num_display, hdvm_lun.capacity, emulation, device_count, raid_type, consumed_capacity, command_device, dp_pool_id, dp_type, rg_number, port_id, domain_id, lun, wwn, nickname, name'
hdvm_lun = get_data_query('hdvm_arrays', 'hdvm_lun', hdvm_lun_headers, session_id, 'array')
hdvm_pool_headers = 'pool_function, dp_pool_id, controller_id, pool_type, status, threshold, threshold2, hdvm_pool.capacity, hdvm_pool.free_capacity, usage_rate, number_of_vvols, capacity_of_vvols, raid_level, combination, disk_type, name'
hdvm_pool = get_data_query('hdvm_arrays', 'hdvm_pool', hdvm_pool_headers, session_id, 'array')
hdvm_port_headers = 'port_id, port_type, port_role, topology, port_display_name, lun_security, controller_id, pwwn, channel_speed, port_option, domain_id, host_mode, host_mode2, hg_display_name, domain_type, nickname, name'
hdvm_port = get_data_query('hdvm_arrays', 'hdvm_port', hdvm_port_headers, session_id, 'array')
hdvm_rg_headers = 'number, display_name, disk_size, disk_type, total_capacity, hdvm_rg.allocated_capacity, hdvm_rg.free_capacity, hdvm_rg.total_free_space, dp_pool_id, emulation, chassis, controller_id, raid_type, rg_type, volume_type, encrypted, protection_level, form_factor, name'
hdvm_rg = get_data_query('hdvm_arrays', 'hdvm_rg', hdvm_rg_headers, session_id, 'array')

# 3PAR
threepar_cpg_headers = 'cpg_id, cpgname, warn, lim, grow, raid, ssz, rs, ss, ha, nd, devtype, rpm, system_name'
threepar_cpg = get_data_query('3par_arrays', '3par_cpg', threepar_cpg_headers, session_id, 'array')
threepar_host_headers = 'host_id, host_name, persona, host_wwniscsi, port, ip_addr, system_name'
threepar_host = get_data_query('3par_arrays', '3par_host', threepar_host_headers, session_id, 'array')
threepar_port_headers = 'nsp, mode, state, nwwn, pwwn, port_type, protocol, label, partner, system_name'
threepar_port = get_data_query('3par_arrays', '3par_port', threepar_port_headers, session_id, 'array')
threepar_vlun_headers = 'lun, vvname, vv_wwn, hostname, host_wwniscsi, port, system_name'
threepar_vlun = get_data_query('3par_arrays', '3par_vlun', threepar_vlun_headers, session_id, 'array')
threepar_vvol_headers = 'vv_id, vvname, rd, mstr, vv_wwn, prov, vv_type, usrcpg, snpcpg, tot_rsvr_kb, vsize_kb, system_name'
threepar_vvol = get_data_query('3par_arrays', '3par_vvol', threepar_vvol_headers, session_id, 'array')

# HEVA
heva_dg_headers = 'heva_dg.uid, heva_dg.operationalstate, heva_dg.operationalstatedetail, diskgroupname, totaldisks, levelingstate, levelingprogress, diskdrivetype, requestedsparepolicy, currentsparepolicy, totalstoragespace_raw, heva_dg.totalstoragespace, usedstoragespace_raw, heva_dg.usedstoragespace, occupancyalarmlevel, diskgrouptype, dgwarningalarmlevel, name'
heva_dg = get_data_query('heva_arrays', 'heva_dg', heva_dg_headers, session_id, 'array')
heva_host_headers = 'heva_host.uid, storagecellid, hostname, virtualdiskid, portwwn, heva_host.operationalstate, heva_host.operationalstatedetail, osmode, osmodebitmask, hosttype, osmodeindex, name'
heva_host = get_data_query('heva_arrays', 'heva_host', heva_host_headers, session_id, 'array')
heva_port_headers = 'portname, wwid, nodeid, hostportaddress, heva_port.operationalstate, speed, portcondition, topology, controller_name, controller_uid, name'
heva_port = get_data_query('heva_arrays', 'heva_port', heva_port_headers, session_id, 'array')
heva_vdisk_headers = 'heva_vdisk.uid, familyname, creationdatetime, timestampmodify, istpvdisk, wwlunid, dirtyblockcount, controllerid, migrationinprogress, heva_vdisk.operationalstate, heva_vdisk.operationalstatedetail, allocatedcapacity, requestedcapacity, virtualdisktype, redundancy, writecacheactual, writecache, mirrorcache, readcache, virtualdiskpresented, hostid, lunnumber, writeprotect, diskgroupid, preferredpath, restoreprogress, hostaccess, name'
heva_vdisk = get_data_query('heva_arrays', 'heva_vdisk', heva_vdisk_headers, session_id, 'array')

# IBTS
ibts_drives_headers = 'wwn, ibts_drives.model, serial, valid, error, abort, reset, recovery, name'
ibts_drives = get_data_query('ibts_libraries', 'ibts_drives', ibts_drives_headers, session_id, 'library')

# Output data to the file. Only XLSX is now supported
if 'xlsx' in config['REPORTER']['output_type']:
    print(time.ctime(time.time()) + ":",
          "Output type:", config['REPORTER']['output_type'] + "; " +
          "Output filename:", config['REPORTER']['output_filename'])

    workbook = xlsxwriter.Workbook(config['REPORTER']['output_filename'],
                                   {'constant_memory': True})

    workbook.set_properties({
        'title':    'Deck Eight One Step - LUN-MAP report',
        'subject':  'SAN/Storage LUN-MAP report',
        'author':   'D81S Reporter',
        'manager':  'Mikhail E. Zakharov <zmey20000@yahoo.com>',
        'company':  '',
        'category': '',
        'keywords': 'D81S, SAN, Storage, report',
        'comments': time.ctime(time.time())})

    write_lun_map(workbook, config['REPORTER']['output_type'], lun_map)
    write_lun_map_unknown(workbook, config['REPORTER']['output_type'], lun_map_unknown)
    write_capacity_vs_used(workbook, config['REPORTER']['output_type'], capacity_vs_used)
    write_hdvm_arrays(workbook, config['REPORTER']['output_type'], hdvm_arrays)
    write_3par_arrays(workbook, config['REPORTER']['output_type'], threepar_arrays)
    write_heva_arrays(workbook, config['REPORTER']['output_type'], heva_arrays)
    write_ibts_libraries(workbook, config['REPORTER']['output_type'], ibts_libraries)

    write_generic(workbook, "BFCF-Zoning", config['REPORTER']['output_type'], bfcf_zoning, bfcf_zoning_headers)
    write_generic(workbook, "BFCF-Name Service", config['REPORTER']['output_type'], bfcf_ns, bfcf_ns_headers)
    write_generic(workbook, "BFCF-Members", config['REPORTER']['output_type'], bfcf_members, bfcf_members_headers)

    write_generic(workbook, "HDVM-LDEV", config['REPORTER']['output_type'], hdvm_ldev, hdvm_ldev_headers)
    write_generic(workbook, "HDVM-LUN", config['REPORTER']['output_type'], hdvm_lun, hdvm_lun_headers)
    write_generic(workbook, "HDVM-Pool", config['REPORTER']['output_type'], hdvm_pool, hdvm_pool_headers)
    write_generic(workbook, "HDVM-Port", config['REPORTER']['output_type'], hdvm_port, hdvm_port_headers)
    write_generic(workbook, "HDVM-RG", config['REPORTER']['output_type'], hdvm_rg, hdvm_rg_headers)
    
    write_generic(workbook, "3PAR-CPG", config['REPORTER']['output_type'], threepar_cpg, threepar_cpg_headers)
    write_generic(workbook, "3PAR-Host", config['REPORTER']['output_type'], threepar_host, threepar_host_headers)
    write_generic(workbook, "3PAR-Port", config['REPORTER']['output_type'], threepar_port, threepar_port_headers)
    write_generic(workbook, "3PAR-VLUN", config['REPORTER']['output_type'], threepar_vlun, threepar_vlun_headers)
    write_generic(workbook, "3PAR-VVOL", config['REPORTER']['output_type'], threepar_vvol, threepar_vvol_headers)

    write_generic(workbook, "HEVA-DG", config['REPORTER']['output_type'], heva_dg, heva_dg_headers)
    write_generic(workbook, "HEVA-Host", config['REPORTER']['output_type'], heva_host, heva_host_headers)
    write_generic(workbook, "HEVA-Port", config['REPORTER']['output_type'], heva_port, heva_port_headers)
    write_generic(workbook, "HEVA-VDisk", config['REPORTER']['output_type'], heva_vdisk, heva_vdisk_headers)
    
    write_generic(workbook, "IBTS-Drives", config['REPORTER']['output_type'], ibts_drives, ibts_drives_headers)

    workbook.close()

else:
    print(time.ctime(time.time()) + ":",
           "Fatal: Only MS Excel XLSX format is supported")

print(time.ctime(time.time()) + ":", "Rest Avatar, you need it")
exit(0)

