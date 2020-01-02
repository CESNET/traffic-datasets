import gzip
import json
from datetime import datetime
from datetime import timedelta
import time
import sys

def fromf2b_datetime(date_time):
    format = '%Y-%m-%dT%H:%M:%SZ' # The format
    datetime_var = datetime.strptime(date_time, format)
    return datetime_var



if len(sys.argv) != 4 :
    print("Provide arguments!")
    sys.exit(2);

min = datetime.fromtimestamp(1564667239.847492);
max = datetime.fromtimestamp(1565014998.209722);


file = open(sys.argv[1],"rt");
jsons = [];
outer_bounds_cnt = 0;
for line in file:
    entry = json.loads(line);
    create_etnry_time = fromf2b_datetime(entry["CreateTime"]);
    if(create_etnry_time >= min and create_etnry_time <= max):
        jsons.append(entry);
    else :
        outer_bounds_cnt+=1;
file.close();
file = open(sys.argv[2],"rt");
for line in file:
    entry = json.loads(line);
    create_etnry_time = fromf2b_datetime(entry["CreateTime"]);
    if(create_etnry_time >= min and create_etnry_time <= max):
        jsons.append(entry);
    else :
        outer_bounds_cnt+=1;


file.close();
print(outer_bounds_cnt);
print(len(jsons));


file = open(sys.argv[3], "w+");
for item in jsons:
    json.dump(item, file);
    file.write("\r\n");
