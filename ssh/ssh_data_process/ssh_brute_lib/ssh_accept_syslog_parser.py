import gzip
import os.path
from datetime import datetime
from datetime import timedelta


class SysLog_parser:
    SYSLOGLINE_IP_INDEX = 10;
    SYSLOG_DATE_INDEX = 3;
    def __init__(self, fname, year):
        self.logins = {};
        fptr = gzip.open(fname, "rb") if fname.find(".gz") >= 0 else open(fname,"rt");
        for line in fptr:
            if( line.find("Accepted") >= 0 and len(line) > 0):
                line = line.split();
                date = str(year) + "-" + "-".join(line[:self.SYSLOG_DATE_INDEX]);
                datetime_var = datetime.strptime(date, '%Y-%b-%d-%H:%M:%S');

                ip = line[self.SYSLOGLINE_IP_INDEX];
                if (str(ip)) in self.logins :
                    self.logins[ip].append(datetime_var);
                else:
                    self.logins[ip] = [];
                    self.logins[ip].insert(0,datetime_var);

    def __str__(self):
                return str(self.logins);


#USER_FUNCTIONS
    def Accepted(self, ip, time_start, time_end):
        if(str(ip)) in self.logins :
            for login in self.logins[ip]:
                print(ip);
                return True;
                login_start = login - timedelta(seconds = 1);
                login_end = login + timedelta(seconds = 1);
                if( login_start <= time_start and time_end <= login_end ) :
                    return True
        return False;
