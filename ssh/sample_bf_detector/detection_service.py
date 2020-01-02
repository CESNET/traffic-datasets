import csv
import sys
import socket
import json
import requests
import unirest
import numpy as np
import re
from datetime import datetime
from datetime import timedelta

sys.path.append("./abuseipdb/abuseipdb")
import abuseipdb

def lookup(addr):
    try:
        return socket.gethostbyaddr(addr)
    except socket.herror:
        return None, None, None

def get_abused_confidence(addr):
    response = unirest.get("https://www.abuseipdb.com/check/" + addr);
    if "was not found" in response.raw_body:
        return "NOT FOUND";
    if "was found" in response.raw_body:
        x = re.search("Confidence of Abuse is .+>:", response.raw_body);
        if(x):
            return re.search("[0-9]+",x.group()).group();

    return "ERROR;"



novelty_detector_rows = [];
nemea_detector_rows = [];
ips = {};
reported_ips = {};
nemea_detector_reported_ips = {};

#reading novelty detector output csv
with open(sys.argv[1]) as csvfile:
    reader = csv.DictReader(csvfile, delimiter=';', quotechar='"');
    for row in reader:
        novelty_detector_rows.append(row);

#reading flow based detector output csv
with open(sys.argv[2]) as csvfile:
    reader = csv.DictReader(csvfile, delimiter=',', quotechar='"');
    for row in reader:
        nemea_detector_rows.append(row);


#labeling nemea detector reported ips
for ip in nemea_detector_rows:
    nemea_detector_reported_ips[ip['ipaddr SRC_IP']] = 1;


#labeling flows
sorted(novelty_detector_rows, key = lambda i: i['time_end'])
brf_no = 0;
brf_yes = 0;
brf_ip_yes = {};
for row in novelty_detector_rows:
    if(row['sa'] not in ips):
        ips[row['sa']] = [];
    ips[row['sa']].append(row['prediction(bruteforce)']);
    if(row['prediction(bruteforce)'] == "true"):
        brf_ip_yes[row['sa']] = '1';
    if(row['prediction(bruteforce)'] == "true"):
	brf_yes+=1;
    else:
	brf_no+=1;


#evaluation of address against bruteforce_treshold
bruteforce_treshold = 3;
for ip in ips:
    cnt = 0;
    for event in ips[ip]:
        if event == "true":
            cnt+=1;
        else:
            cnt = 0;
        if(cnt > bruteforce_treshold):
            reported_ips[ip] = True;


print("reported by nemea and not reported by ML detector:")
cnt = 0;
for ip in nemea_detector_reported_ips:
    if(ip not in reported_ips):
        for row in novelty_detector_rows:
            if(ip == row['sa'] and row['bytes_in'] != 0):
                cnt+=1;
                break;
print("Total " + str(cnt));

cnt =0;
print("reported by ML detector and not reported by nemea:")
for ip in reported_ips:
    if(ip not in nemea_detector_reported_ips):
        print(ip +  ";" + str(lookup(ip)) + ";AbuseConfidence: " + str(get_abused_confidence(ip)));
        cnt+=1;
print("Total " + str(cnt));

cnt =0;
print("reported by both")
for ip in reported_ips:
    if(ip in nemea_detector_reported_ips):
	print(ip +  ";" + str(lookup(ip)) + ";AbuseConfidence: " + str(get_abused_confidence(ip)));        
	cnt+=1;

print("Total " + str(cnt));


print("not reported by both")
cnt = 0;
for ip in ips:
    if((ip not in nemea_detector_reported_ips) and (ip not in reported_ips)):
        print(ip +  ";" + str(lookup(ip)) + ";AbuseConfidence: " + str(get_abused_confidence(ip)));
        cnt+=1;
print("Total " + str(cnt));
