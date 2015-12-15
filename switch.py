#!/usr/bin/python
# -*- coding: utf-8 -*-
##########################################
#      switch connection class
##########################################
import socket
from time import sleep


class Switch:
    host = ""
    ip = ""
    user = ""
    passwd = ""
    stype = ""
    stack_member = "0"
    sock = None
    mac_table = {}
    lockout_table = []
    # Упорядочить работу
    log = None
    status = -1
    error_msg = ""
    debug = 0
    
    def __init__(self, stype="", sm="0", host="", ip="", user="", passwd="", log=None):
        if stype != "":
            self.stype = stype.lower()
        if ip != "":
            self.ip = ip
        if host != "":
            self.host = host
        if sm != "0":
            self.stack_member = str(sm)
        if user != "":
            self.user = user
        if passwd != "":
            self.passwd = passwd
        if log is not None:
            self.log = log
        log.debug("Switch init:"+str(self))
        self.update()
        # if self.debug:
        #    self.info()

    def __repr__(self):
        res = "stipe = "+self.stype+", host = "+self.host+", ip = "+self.ip+", sm = "+self.stack_member+"\n"
        res += "mac_table = "+str(self.mac_table)+"\n"+"lockout_table = "+str(self.lockout_table)
        return res

    def info(self):
        print "host =", self.host
        print "ip =", self.ip
        print "stype =", self.stype
        print "stack_member =", self.stack_member
        print "mac_table =", self.mac_table
        print "lockout_table =", self.lockout_table
        print "status =", self.status
        print "error_msg =", self.error_msg

    def update(self):
        self.status = -1
        self.connect_sw()
        if self.sock:
            # self.debug_info("login")
            self.send_login()
            sleep(1)
            self.debug_info("get_mac")
            self.mac_table = self.get_mac()
            sleep(1)
            self.debug_info("get_lockout")
            self.lockout_table = self.get_lockout()
            sleep(1)
            self.debug_info("logout")
            self.logout()
        if self.status < 1:
            self.status = 0

    @staticmethod
    def std_mac(mac):
        res = mac.upper()
        res = res.replace(":", "")
        res = res.replace("-", "")
        return res

    def connect_sw(self):
        self.log.debug("Create socket to connect to switch.")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(60)
        try:
            s.connect((self.ip, 23))
        except Exception, e:
            self.error_msg = "Can\'t connect to "+self.ip+", "+str(e).replace('\n', ' ')
            self.log.error(self.error_msg)
            self.status = 1
            s = None
        self.sock = s

    def recv_data(self):
        if self.status > 0:
            return ""
        try:
            res = self.sock.recv(1024)
            # self.debug_info(self.safe_str(res))
            self.log.debug(self.safe_str(res))
        except Exception, e:
            self.error_msg = "Error receiving data,"+str(e).replace('\n', ' ')
            self.status = 1
            res = ""
        return res

    def get_data(self, exit_condition):
        if self.status > 1:
            return
        data = ""
        response_data = " "
        while response_data != "":
            if response_data.find(exit_condition) != -1:
                # print self.safe_str(data)
                break
            elif response_data.find("MORE") != -1:
                self.sock.send(" "+chr(13))
            elif response_data.find("Enter <CR> for more") != -1:
                self.sock.send(chr(13))
            elif response_data.find("Next Page") != -1 and response_data.find("Next Entry") != -1:
                self.sock.send(" " + chr(13))
            response_data = self.recv_data()
            data = data+response_data
        # print self.safe_str(data)
        return data

    def send_login(self):
        self.log.debug("send_login: "+self.stype+" "+str(self.status))
        if self.status > 1:
            return
        if self.stype == "hp":
            self.send_login_hp()
        elif self.stype == "3com":
            self.debug_info("send_login_3com")
            self.send_login_3com()
        elif self.stype == "dlink":
            self.debug_info("send_login_dlink")
            self.send_login_dlink()
        else:
            self.status = 1
            self.error_msg = self.stype = " - incorrect switch type."
            return
        res = self.get_data(self.host)

    def send_login_hp(self):
        response_data = " "
        while response_data != "":
            if response_data.find("Username: ") != -1:
                self.sock.send(self.user+chr(13))
            if response_data.find("Password: ") != -1:
                self.sock.send(self.passwd+chr(13))
            if response_data.find("Enter switch number") != -1:
                self.sock.send(self.stack_member + chr(13))
                break
            if response_data.find("Session Terminated") != -1:
                self.error_msg = "Login failed."
                self.status = 1
            response_data = self.recv_data()
            if self.status > 0:
                return

    def send_login_3com(self):
        response_data = " "
        while response_data != "":
            if response_data.find("Login:") != -1:
                self.sock.send(self.user+chr(13))
            if response_data.find("Password:") != -1:
                self.debug_info("Send password.")
                self.sock.send(self.passwd+chr(13))
                break
            response_data = self.recv_data()
            if self.status > 0:
                return

    def send_login_dlink(self):
        response_data = " "
        while response_data != "":
            if response_data.find("username:") != -1:
                self.sock.send(self.user+chr(13))
            if response_data.find("password:") != -1:
                self.debug_info("Send password.")
                self.sock.send(self.passwd+chr(13))
                break
            response_data = self.recv_data()
            if self.status > 0:
                return

    def get_mac(self):
        if self.status > 1:
            return {}
        if self.stype == "hp":
            return self.get_mac_hp()
        elif self.stype == "3com":
            self.debug_info("get_mac_3com")
            return self.get_mac_3com()
        elif self.stype == "dlink":
            self.debug_info("get_mac_dlink")
            return self.get_mac_dlink()
        else:
            self.status = 1
            self.error_msg = self.stype = " - incorrect switch type."
            return {}

    def debug_info(self, message, level=1):
        if self.debug >= level:
            print message

    def get_mac_dlink(self):
        res = {}
        if self.sock:
            self.sock.send("show fdb"+chr(13))
            data = self.get_data("Total Entries")
            # print self.safe_str(data)
            res = self.parce_data_dlink(data)
        return res

    def parce_data_dlink(self, data):
        res = {}
        lines = data.split(chr(13)+chr(10))
        for line in lines:
            if line.find("Command:") != -1:
                continue
            elif line.find("MAC") != -1:
                continue
            elif line.find("Total Entries") != -1:
                continue
            elif line.find(self.host) != -1:
                continue
            elif line.find("----------") != -1:
                continue
            elif len(line) < 10:
                continue
            self.debug_info(str(len(line)) + self.safe_str(line))
            line = line.split()
            if len(line) == 5:
                mac = line[2]
                port_num = line[3]
                res[self.std_mac(mac)] = port_num
        return res

    def get_mac_hp(self):	    
        res = {}
        if self.sock:
            self.sock.send("show mac-address"+chr(13))
            data = self.get_data(self.host)
            # print self.safe_str(data)
            res = self.parce_data_hp(data)
        return res

    def get_mac_3com(self):
        res = {}
        if self.sock:
            self.sock.send("bridge"+chr(13))
            data = self.get_data("Select menu option (bridge):")
            if data != "":
                self.sock.send("addressDatabase"+chr(13))
                data = self.get_data("Select menu option (bridge/addressDatabase):")
                if data != "":
                    self.sock.send("summary"+chr(13))
                    data = self.get_data("Select bridge ports")
                    if data != "":
                        self.sock.send("all"+chr(13))
                        data = self.get_data("Select menu option (bridge/addressDatabase):")
                        if self.debug:
                            print self.safe_str(data)
                        res = self.parce_data_3com(data)
        return res

    def parce_data_3com(self, data):
        res = {}
        lines = data.split(chr(13)+chr(10))
        for line in lines:
            if line.find("Location") != -1:
                continue
            elif line.find("Select menu option (bridge/addressDatabase):") != -1:
                continue
            elif line.find("----------") != -1:
                continue
            elif len(line) < 10:
                continue
            line = line.strip()
            if len(line.split()) == 7:
                unit, unit_num, port, port_num, mac, vlan_id, p = line.split()
                res[self.std_mac(mac)] = int(port_num)
        return res

    def get_lockout(self):
        if self.status > 1:
            return []
        if self.stype != "hp":
            return []
        res = []
        if self.sock:
            self.sock.send("show lockout-mac"+chr(13))
            data = self.get_data(self.host)
            res = self.parce_data_lockout(data)
        return res

    def set_lockout_mac(self, mac, action="add"):
        if self.status > 1:
            return []
        if self.stype != "hp":
            return []
        err = 0
        if self.sock:
            self.sock.send("configure"+chr(13))
            data = self.get_data(self.host)
            cmodify = ""
            if action == "del":
                cmodify = "no "
            self.sock.send(cmodify + "lockout-mac " + self.std_mac(mac) + chr(13))
            data = self.get_data(self.host)
            if data.find("Value lockout-mac is invalid") != -1 or data.find("Invalid input:") != -1:
                err = 1
            self.sock.send("exit"+chr(13))
            data = self.get_data(self.host)
            # print self.safe_str(data)
        return err

    def del_lockout_mac(self, mac):
        return self.set_lockout_mac(mac, "del")

    def parce_data_lockout(self, data):
        if self.status > 1:
            return
        res = []
        lines = data.split(chr(10)+chr(13))
        for line in lines:
            line = line.replace(chr(13), "")
            # print len(line), self.safe_str(line)
            if line.find("show locko") != -1:
                continue
            elif line.find("empty list") != -1:
                continue
            elif line.find("Number of locked out MAC addresses") != -1:
                continue
            elif len(line) < 12 or len(line) > 20:
                continue
            elif line.find(self.host) != -1:
                continue
            elif line.find("MORE") != -1:
                line = line[-14:]
            line = self.std_mac(line.strip())
            res.append(line)
            # print self.std_mac(line)
        return res

    @staticmethod
    def safe_str(data):
        res = ""
        n = 0
        for c in data:
            n += 1
            if ord(c) < 32 or ord(c) > 127:
                res += '%%%02X' % ord(c)
            else:
                res += c
        return res

    def parce_data_hp(self, data):
        if self.status > 1:
            return {}
        res = {}
        # print self.safe_str(data)
        lines = data.split(chr(10)+chr(13))
        for line in lines:
            line = line.replace(chr(13), "")
            # print len(line),self.safe_str(line)
            if line.find("how mac") != -1:
                continue
            elif line.find("Status and Counters") != -1:
                continue
            elif line.find("MAC Address") != -1:
                continue
            elif line.find("----------") != -1:
                continue
            elif len(line) < 10:
                continue
            elif line.find(self.host) != -1:
                continue
            elif line.find("MORE") != -1:
                line = line[-31:]
                # line=line.replace(chr(13),"")
            line = line.strip()
            if len(line.split()) == 2:
                mac, port = line.split()
                res[self.std_mac(mac)] = int(port)
                # res.append([self.std_mac(mac),int(port)])
            return res

    def logout(self):
        if self.status > 1:
            return
        if self.sock:
            if self.stype == "hp":
                self.logout_hp()
            elif self.stype == "3com":
                self.logout_3com()
                self.sock.close()
            sleep(5)

    def logout_hp(self):
        self.sock.send("logout"+chr(13))
        data = self.get_data("Do you want to log out")
        if data.find("Do you want to log out") != -1:
            self.sock.send("y"+chr(13))
            data = self.get_data("24")
            if data.find("Do you want to save current configuration") != -1:
                self.sock.send("n"+chr(13))
                data = self.get_data("24")

    def logout_3com(self):
        self.sock.send("logout"+chr(13))
        data = self.get_data("Do you want to log out")
        if data.find("Do you want to log out") != -1:
            self.sock.send("y"+chr(13))
            data = self.get_data("24")
            if data.find("Do you want to save current configuration") != -1:
                self.sock.send("n"+chr(13))
                data = self.get_data("24")
