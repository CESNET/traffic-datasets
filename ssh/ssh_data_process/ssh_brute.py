import gzip
import json
import numpy as np
import sqlite3
from datetime import datetime
from datetime import timedelta
import time
import sys
import math
import copy
import re
import pprint
#USER_CLASSES
sys.path.append("./ssh_brute_lib")
from ssh_accept_syslog_parser import SysLog_parser
from db_entry import DB_entry;
from db_entry import DB_row;
from flow_parser import Flow_parser;
from sqlite3 import Error

def fromf2b_datetime(date_time):
    format = '%Y-%m-%dT%H:%M:%SZ' # The format
    datetime_var = datetime.strptime(date_time, format)
    return datetime_var

def fromjoy_datetime(date_time):
    format = '%s' # The format
    datetime_var = datetime.fromtimestamp(date_time)
    return datetime_var

def fromdatetime_epoch(date_time):
    return str(time.mktime(date_time.timetuple()));

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


attacks = SysLog_parser(sys.argv[1], 2019);


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

last_flow_from_ip = {};
mean_flow_time_ip = {};
flow_data = {};
last_flow = {};
kex_algos_count = {};
encryption_algos_count = {};
karel = [];
first = True;
cnt = 0;
file = open("neco.json", "w+");
parser = Flow_parser(row_db);

with gzip.open(sys.argv[2]) as f:
    for line in f:
        if(first == True):
            first = False;
            continue;

	entry = json.loads(line);
        parser.parse_flow(entry);
        print(row_db);
        flow_data["fin_count"] = 0;
        flow_data["reset_count"] = 0;
        if("ppi" in entry):
            ppi = entry["ppi"];
            for packet in ppi :
                if( packet["flags"].find("F") >= 0):
                    flow_data["fin_count"]+=1;
                if(packet["flags"].find("R") >= 0):
                    flow_data["reset_count"]+=1;

        dt_time_start = fromjoy_datetime(math.floor(entry["time_start"]));
        flow_data["dt_time_start"] = dt_time_start;
        flow_data["time_start"] = "{:.6f}".format(entry["time_start"])
        dt_time_end = fromjoy_datetime(math.ceil(entry["time_end"]));
        flow_data["dt_time_end"] = dt_time_end;

        flow_data["duration"] = "{:.6f}".format(entry["time_end"]-entry["time_start"]);

        if ((str(entry["sa"]), str(entry["da"]))) in mean_flow_time_ip:
            mean_flow_time_ip[(str(entry["sa"]), str(entry["da"]))].append(entry["time_end"]-entry["time_start"]);
        else:
            mean_flow_time_ip[(str(entry["sa"]), str(entry["da"]))] = [];
            mean_flow_time_ip[(str(entry["sa"]), str(entry["da"]))].append(entry["time_end"]-entry["time_start"]);



        if ((str(entry["sa"]), str(entry["da"]))) in last_flow_from_ip:
            flow_data["interflow_gap"] = "{:.6f}".format(entry["time_start"] - last_flow_from_ip[(str(entry["sa"]),str(entry["da"]))]);
            last_flow_from_ip[(str(entry["sa"]), str(entry["da"]))] = entry["time_end"];
        else:
            flow_data["interflow_gap"] = 0;
            last_flow_from_ip[(str(entry["sa"]), str(entry["da"]))] = entry["time_end"];

        #print(flow_data["interflow_gap"]);
        flow_data["pr"] = entry["pr"];
        flow_data["sa"] = entry["sa"];
        flow_data["expire_type"] = entry["expire_type"] if "expire_type" in entry else '?';
        flow_data["da"] = entry["da"];
        flow_data["sp"] = entry["sp"] if "sp" in entry else 0;
        flow_data["dp"] = entry["dp"] if "sp" in entry else 0;
	if (flow_data["sp"] == 22 or  flow_data["dp"] == 22) :
            cnt+=1;
	flow_data["bytes_in"] = entry["bytes_in"] if "bytes_in" in entry else 0;
        flow_data["bytes_out"] = entry["bytes_out"] if "bytes_out" in entry else 0;
        flow_data["num_pkts_in"] = entry["num_pkts_in"] if "num_pkts_in" in entry else 0;
        flow_data["num_pkts_out"] = entry["num_pkts_out"] if "num_pkts_out" in entry else 0;
        flow_data["entropy"] = entry["entropy"] if "entropy" in entry else None;
        flow_data["total_entropy"] = entry["total_entropy"] if "total_entropy" in entry else None;
        flow_data["idp_in"] = entry["idp_in"] if "idp_in" in entry else "";
        flow_data["idp_out"] = entry["idp_out"] if "idp_out" in entry else "";
        flow_data["ssh"] = 1 if "ssh" in entry else "0";
        packets_data_len = [];
        packets_ipt = [];
        #if(flow_data["time_start"] == "1564674582.683170" ):
        #    print(json.dumps(entry, sort_keys=True, indent=4, separators=(',', ': ')));
        #print(flow_data["time_start"]);
        packet_cnt = 0;
        srv_packet_cnt = 6;

        for i in xrange(6, 15):
            flow_data["dp_" + str(i) + "_bytes_count"] = 0;

        flow_data["num_pkts"] = flow_data["num_pkts_in"] + flow_data["num_pkts_out"];
        for packet in entry["packets"] :
            packets_data_len.append(packet["b"] if "b" in packet else 0) ;
            packets_ipt.append(packet["ipt"]);
            if(packet_cnt >= 6 and packet_cnt <= 15 and packet["dir"] == '<'):
                flow_data["dp_" + str(srv_packet_cnt) + "_bytes_count"] = packet["b"] if "b" in packet else 0
                srv_packet_cnt+=1;
            packet_cnt+=1;

        if len(packets_data_len) > 0 :
            flow_data["fdp_len"] = entry["packets"][0]["b"] if "b" in entry["packets"][0] else 0 ;
            flow_data["ldp_len"] = entry["packets"][-1]["b"] if "b" in entry["packets"][-1] else 0;

            flow_data["avgp_len"] = np.mean(packets_data_len);
            flow_data["medp_len"] = np.median(packets_data_len);
            flow_data["varp_len"] = np.var(packets_data_len);
            flow_data["avg_ipt"] = np.mean(packets_ipt);
            flow_data["med_ipt"] = np.median(packets_ipt);
            flow_data["var_ipt"] = np.var(packets_ipt);
        else :
            flow_data["fdp_len"] = 0;
            flow_data["ldp_len"] = 0;
            flow_data["avgp_len"] = 0;
            flow_data["medp_len"] = 0;
            flow_data["varp_len"] = 0
            flow_data["avg_ipt"] = 0;
            flow_data["med_ipt"] = 0;
            flow_data["var_ipt"] = 0;

        flow_data["3des-cbc"] = 0;
        flow_data["3des-ctr"] = 0;
        flow_data["aes128-cbc"] = 0;
        flow_data["aes128-ctr"] = 0;
        flow_data["aes128-gcm@openssh.com"] = 0;
        flow_data["aes192-cbc"] = 0;
        flow_data["aes192-ctr"] = 0;
        flow_data["aes256-cbc"] = 0;
        flow_data["aes256-ctr"] = 0;
        flow_data["aes256-gcm@openssh.com"] = 0;
        flow_data["arcfour"] = 0;
        flow_data["arcfour128"] = 0;
        flow_data["arcfour256"] = 0;
        flow_data["blowfish-cbc"] = 0;
        flow_data["blowfish-ctr"] = 0;
        flow_data["cast128-cbc"] = 0;
        flow_data["chacha20-poly1305@openssh.com"] = 0;
        flow_data["des-cbc-ssh1"] = 0;
        flow_data["rijndael-cbc@lysator.liu.se"] = 0;
        flow_data["twofish128-cbc"] = 0;
        flow_data["twofish256-cbc"] = 0;
        flow_data["support_other_enc"] = 0;


        if "ssh" in entry:
            ssh_prot = entry["ssh"]["cli"]["protocol"].split("-",2);
            ssh_c_encryption_algo = entry["ssh"]["cli"]["c_encryption_algos"].split(",");
            ssh_c_kex_algo = entry["ssh"]["cli"]["kex_algos"].split(",");
            for value in ssh_c_encryption_algo:
                if value in flow_data and value != "" :
                    flow_data[value] = 1;
                elif value != "":
                    flow_data["support_other_enc"] = 1;

            flow_data["ssh_version"] = ssh_prot[1];
            flow_data["ssh_client"] = ssh_prot[2];
            flow_data["first_encryption_algo"] = ssh_c_encryption_algo[0];
            flow_data["encryption_algo_lenght"] = len(ssh_c_encryption_algo);
            flow_data["kex_algos_lenght"] = len(ssh_c_kex_algo);
        else:
            flow_data["ssh_version"] = None;
            flow_data["ssh_client"] = None;
            flow_data["first_encryption_algo"] = None;
            flow_data["encryption_algo_lenght"] = None;
            flow_data["kex_algos_lenght"] = None;

        flow_data["bruteforce"] = 1;

        if attacks.Accepted(flow_data["sa"], dt_time_start, dt_time_start) :
            flow_data["bruteforce"] = 0;

        columns = '\', \''.join(flow_data.keys());
        placeholders = ', '.join('?' * len(flow_data));
        if(flow_data["ssh"] == 1):
            sql = 'INSERT INTO flows (\'{}\') VALUES ({})'.format(columns, placeholders);
        #print(sql);
            db.execute(sql, flow_data.values());


db.commit();
db.close();


#for key, val in mean_flow_time_ip.iteritems():
#    b = 1 if key in attacks else 0;
#    print(str(key) + " -> " + str(np.mean(val)) + " " + str(b) );
#
#
#karel.sort(key= lambda i: (i["sa"], i["dt_time_start"]));

#print(cnt)
##for it in karel :
#    print(str(it["num_pkts"]) +  " " + " " + it["time_start"] + " " + str(it["sa"]),str(it["da"]) + " " + str(it["dt_time_start"]) + " " + str(it["dt_time_end"]) + " " + str(it["ssh"]));
