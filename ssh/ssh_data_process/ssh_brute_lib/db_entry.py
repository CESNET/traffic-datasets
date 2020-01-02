from collections import OrderedDict

class DB_entry:
    def __init__(self, name, type, direct_from_flow, constraint = None, value = None):
        self.name = name;
        self.type = type;
        self.constraint = constraint;
        self.direct_from_flow = direct_from_flow;
        self.value = value;

    def __str__(self):
        tmp_dic = {};
        tmp_dic["name"] = self.name;
        tmp_dic["type"] = self.type;
        tmp_dic["direct_from_flow"] = self.direct_from_flow;
        tmp_dic["value"] = self.value;
        return str(tmp_dic);

    def to_crt_table_string(self):
        temp_string = "'" + str(self.name)+ "' " + str(self.type);
        if(self.constraint != None):
            temp_string += " " + str(self.constraint);
        return temp_string

    def __fill_default(self,type):
        type_low = type.lower();
        switcher = {
           "integer": 0,
           "real": 0.0,
           "text": ""
        }

        return switcher[type_low];

    def reset_value(self):
        self.value = self.__fill_default(self.type);


class DB_row:
    def __init__(self):
        self.row = OrderedDict();
    def __str__(self):
        tmp = [];
        for it in self.row.values():
            tmp.append(str(it));
        return str(tmp);

    def add(self, entry):
        if entry.name in self.row:
            raise Exception("Second attempt of adding element with name " + entry.name);

        self.row[entry.name] = entry;

    def to_create_table_string(self, table_name):
        tmp_string = "CREATE TABLE IF NOT EXISTS " + table_name+ " ( ";
        entries = ", ".join(value.to_crt_table_string() for (key, value) in self.row.items());
        return tmp_string + entries + " );";
