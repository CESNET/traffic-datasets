import gzip
import json
import sqlite3
import time
import sys
import pprint
from sqlite3 import Error

#USER_CLASSES
sys.path.append("./ssh_brute_lib")
from ssh_accept_syslog_parser import SysLog_parser
from db_entry import DB_entry;
from db_entry import DB_row;
from flow_parser import Flow_parser;

def create_connection(db_file):
    """ """
    try:
        conn = sqlite3.connect(db_file)
        return conn;
    except Error as e:
        print(e)

    return none;


def create_table(conn, sql) :
    try:
        c=conn.cursor();
        c.execute(sql);
    except Error as e:
        print(e)


if len(sys.argv) != 4 :
    print("Provide arguments!")
    sys.exit(2);

row_db = DB_row();

row_db.add(DB_entry('id'                              ,"integer",    False, "PRIMARY KEY"));
row_db.add(DB_entry('bruteforce'                      ,"integer",    False, "NOT NULL"));
row_db.add(DB_entry('time_start'                      ,"real",       True));
row_db.add(DB_entry('time_end'                        ,"real",       True));
row_db.add(DB_entry('idp_in'                          ,"integer",    True));
row_db.add(DB_entry('idp_out'                         ,"integer",    True));
row_db.add(DB_entry('sa'                              ,"text",       True));
row_db.add(DB_entry('da'                              ,"text",       True));
row_db.add(DB_entry('dp'                              ,"integer",    True));
row_db.add(DB_entry('sp'                              ,"integer",    True));

row_db.add(DB_entry('entropy'                         ,"real",       True));
row_db.add(DB_entry('total_entropy'                   ,"real",       True));
row_db.add(DB_entry('duration'                        ,"integer",    False));


row_db.add(DB_entry('pr'                              ,"text",       True));

row_db.add(DB_entry('fdp_len'                         ,"integer",    False));
row_db.add(DB_entry('ldp_len'                         ,"integer",    False));
row_db.add(DB_entry('num_pkts_in'                     ,"integer",    True));
row_db.add(DB_entry('num_pkts_out'                    ,"integer",    True));
row_db.add(DB_entry('num_pkts'                        ,"integer",    False));
row_db.add(DB_entry('bytes_in'                        ,"integer",    True));
row_db.add(DB_entry('bytes_out'                       ,"integer",    True));
row_db.add(DB_entry('avg_ipt'                         ,"real",       False));
row_db.add(DB_entry('med_ipt'                         ,"integer",    False));
row_db.add(DB_entry('var_ipt'                         ,"real",       False));
row_db.add(DB_entry('ssh_client'                      ,"text",       False));
row_db.add(DB_entry('avgp_len'                        ,"integer",    False));
row_db.add(DB_entry('varp_len'                        ,"real",       False));

row_db.add(DB_entry('ssh_version'                     ,"text",       False));
row_db.add(DB_entry('ssh'                             ,"integer",    False));
row_db.add(DB_entry('dt_time_start'                   ,"text",       False));
row_db.add(DB_entry('dt_time_end'                     ,"text",       False));
row_db.add(DB_entry('medp_len'                        ,"integer",    False));
row_db.add(DB_entry('kex_algos_lenght'                ,"integer",    False));

row_db.add(DB_entry('encryption_algo_lenght'          ,"integer",    False));
row_db.add(DB_entry('first_encryption_algo'           ,"text",       False));
row_db.add(DB_entry('3des-cbc'                        ,"integer",    False));
row_db.add(DB_entry('3des-ctr'                        ,"integer",    False));
row_db.add(DB_entry('aes128-cbc'                      ,"integer",    False));
row_db.add(DB_entry('aes128-ctr'                      ,"integer",    False));
row_db.add(DB_entry('aes128-gcm@openssh.com'          ,"integer",    False));
row_db.add(DB_entry('aes192-cbc'                      ,"integer",    False));
row_db.add(DB_entry('aes192-ctr'                      ,"integer",    False));
row_db.add(DB_entry('aes256-cbc'                      ,"integer",    False));
row_db.add(DB_entry('aes256-ctr'                      ,"integer",    False));
row_db.add(DB_entry('aes256-gcm@openssh.com'          ,"integer",    False));
row_db.add(DB_entry('arcfour'                         ,"integer",    False));
row_db.add(DB_entry('arcfour128'                      ,"integer",    False));
row_db.add(DB_entry('arcfour256'                      ,"integer",    False));
row_db.add(DB_entry('blowfish-cbc'                    ,"integer",    False));
row_db.add(DB_entry('blowfish-ctr'                    ,"integer",    False));
row_db.add(DB_entry('cast128-cbc'                     ,"integer",    False));
row_db.add(DB_entry('chacha20-poly1305@openssh.com'   ,"integer",    False));
row_db.add(DB_entry('des-cbc-ssh1'                    ,"integer",    False));
row_db.add(DB_entry('rijndael-cbc@lysator.liu.se'     ,"integer",    False));
row_db.add(DB_entry('twofish128-cbc'                  ,"integer",    False));
row_db.add(DB_entry('twofish256-cbc'                  ,"integer",    False));
row_db.add(DB_entry('support_other_enc'               ,"integer",    False));

row_db.add(DB_entry('interflow_gap'                   ,"real",       False));
row_db.add(DB_entry('fp_bytes_count'                  ,"integer",    False));
row_db.add(DB_entry('dp_6_bytes_count'                ,"integer",    False));
row_db.add(DB_entry('dp_7_bytes_count'                ,"integer",    False));
row_db.add(DB_entry('dp_8_bytes_count'                ,"integer",    False));
row_db.add(DB_entry('dp_9_bytes_count'                ,"integer",    False));
row_db.add(DB_entry('dp_10_bytes_count'               ,"integer",    False));
row_db.add(DB_entry('dp_11_bytes_count'               ,"integer",    False));
row_db.add(DB_entry('dp_12_bytes_count'               ,"integer",    False));
row_db.add(DB_entry('dp_13_bytes_count'               ,"integer",    False));
row_db.add(DB_entry('dp_14_bytes_count'               ,"integer",    False));
row_db.add(DB_entry('dp_15_bytes_count'               ,"integer",    False));
row_db.add(DB_entry('expire_type'                     ,"text",       False));
row_db.add(DB_entry('fin_count'                       ,"integer",    False));
row_db.add(DB_entry('reset_count'                     ,"integer",    False));

create_table_string = row_db.to_create_table_string("flows");
db = create_connection(sys.argv[3]);
create_table(db, create_table_string);
logins = SysLog_parser(sys.argv[1], 2019);
first = True;
parser = Flow_parser(row_db, 6, 15);
with gzip.open(sys.argv[2]) as f:
    for line in f:
        if(first == True):
            first = False;
            continue;
        parser.parse_flow(json.loads(line));
        save_dic = parser.to_dictionary();
        save_dic["bruteforce"] = 1;
        if logins.Accepted(save_dic["sa"],save_dic["dt_time_start"], save_dic["dt_time_end"]) :
            save_dic["bruteforce"] = 0;


        columns = '\', \''.join(save_dic.keys());
        placeholders = ', '.join('?' * len(save_dic));
        if(save_dic["ssh"] == 1):
            sql = 'INSERT INTO flows (\'{}\') VALUES ({})'.format(columns, placeholders);
        #print(sql);
            db.execute(sql, save_dic.values());

db.commit();
db.close();
