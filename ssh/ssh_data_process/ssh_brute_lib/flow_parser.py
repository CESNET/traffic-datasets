import json
import gzip
import copy
import numpy as np
import pprint
from datetime import datetime
from datetime import timedelta
import math
import time
import collections

class Flow_parser:
    def __init__(self, db_row, ppi_packet_size_begin, ppi_packet_size_end):
        self.__row = copy.deepcopy(db_row);
        self.__ip_time_start_memory = {};
        self.__ppi_packet_size_begin = ppi_packet_size_begin;
        self.__ppi_packet_size_end = ppi_packet_size_end;

    def __reset_row(self):
        for entry in self.__row.row.values():
            entry.reset_value();


    def __copy_direct_from_flow(self, flow):
        for entry in self.__row.row.values():
            if(entry.direct_from_flow ) :
                if( entry.name in flow):
                    entry.value = flow[entry.name];



    def __parse_ppi(self, flow):
        self.__row.row["fin_count"].value = 0;
        self.__row.row["reset_count"].value = 0;
        if("ppi" in flow):
            ppi = flow["ppi"];
            for packet in ppi :
                if( packet["flags"].find("F") >= 0):
                    self.__row.row["fin_count"].value+=1;
                if(packet["flags"].find("R") >= 0):
                    self.__row.row["reset_count"].value+=1;

    def __parse_timing_entries(self, flow):
        dt_time_start = datetime.fromtimestamp(math.floor(flow["time_start"]));
        dt_time_end = datetime.fromtimestamp(math.ceil(flow["time_end"]));
        self.__row.row["dt_time_start"].value = dt_time_start;
        self.__row.row["time_start"].value = "{:.6f}".format(flow["time_start"])
        self.__row.row["dt_time_end"].value = dt_time_end;
        self.__row.row["duration"].value = "{:.6f}".format(flow["time_end"]-flow["time_start"]);
        if(self.__row.row["duration"].value < 0):
            self.__row.row["duration"].value = 0;

        if (str(flow["sa"])) in self.__ip_time_start_memory:
            self.__row.row["interflow_gap"].value = "{:.6f}".format(flow["time_start"] - self.__ip_time_start_memory[str(flow["sa"])]);
            self.__ip_time_start_memory[str(flow["sa"])] = flow["time_end"];
            if(self.__row.row["interflow_gap"].value < 0):
                self.__row.row["interflow_gap"].value = 0;
        else:
            self.__row.row["interflow_gap"].value = 0;
            self.__ip_time_start_memory[str(flow["sa"])] = flow["time_end"];


    def __parse_packet_statistics(self, flow):
        packets_data_len = [];
        packets_ipt = [];
        packet_cnt = 0;
        pkts_in = flow["num_pkts_in"] if "num_pkts_in" in flow else 0;
        pkts_out = flow["num_pkts_out"] if "num_pkts_out" in flow else 0;
        self.__row.row["num_pkts"].value = pkts_in + pkts_out;

        for i in xrange(self.__ppi_packet_size_begin, self.__ppi_packet_size_end):
            self.__row.row["dp_" + str(i+1) + "_bytes"].value = 0;

        for packet in flow["packets"] :
            packets_data_len.append(packet["b"] if "b" in packet else 0) ;
            packets_ipt.append(packet["ipt"]);
            if(packet_cnt >= self.__ppi_packet_size_begin and packet_cnt <= self.__ppi_packet_size_end ):
                self.__row.row["dp_" + str(packet_cnt+1) + "_bytes"].value = packet["b"] if "b" in packet else 0
            packet_cnt+=1;


            if packet_cnt > 0 :
                self.__row.row["fdp_len"].value = flow["packets"][0]["b"] if "b" in flow["packets"][0] else 0 ;
                self.__row.row["ldp_len"].value = flow["packets"][-1]["b"] if "b" in flow["packets"][-1] else 0;

                self.__row.row["avgp_len"].value = np.mean(packets_data_len);
                self.__row.row["medp_len"].value = np.median(packets_data_len);
                self.__row.row["varp_len"].value = np.var(packets_data_len);
                self.__row.row["avg_ipt"].value = np.mean(packets_ipt);
                self.__row.row["med_ipt"].value = np.median(packets_ipt);
                self.__row.row["var_ipt"].value = np.var(packets_ipt);


    def __parse_ssh_info(self, flow):
        if "ssh" in flow:
            self.__row.row["ssh"].value = 1;
            ssh_prot = flow["ssh"]["cli"]["protocol"].split("-",2);
            ssh_c_encryption_algo = flow["ssh"]["cli"]["c_encryption_algos"].split(",");
            ssh_c_kex_algo = flow["ssh"]["cli"]["kex_algos"].split(",");
            for value in ssh_c_encryption_algo:
                if value in self.__row.row and value != "" :
                    self.__row.row[value].value = 1;
                elif value != "":
                    self.__row.row["support_other_enc"].value = 1;

            self.__row.row["ssh_version"].value = ssh_prot[1];
            self.__row.row["ssh_client"].value = ssh_prot[2];
            self.__row.row["first_encryption_algo"].value = ssh_c_encryption_algo[0];
            self.__row.row["encryption_algo_lenght"].value = len(ssh_c_encryption_algo);
            self.__row.row["kex_algos_lenght"].value = len(ssh_c_kex_algo);

    def parse_flow(self, flow):
        self.__reset_row()
        self.__copy_direct_from_flow(flow);
        self.__parse_ppi(flow);
        self.__parse_timing_entries(flow);
        self.__parse_packet_statistics(flow);
        self.__parse_ssh_info(flow);


    def to_dictionary(self):
        temp = collections.OrderedDict();
        for item in self.__row.row.values():
            if(item.constraint == None or item.constraint.lower().find("primary") < 0):
                temp[item.name] = item.value;
        return temp;
