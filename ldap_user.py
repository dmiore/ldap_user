#!/usr/bin/python
# -*- coding: utf-8 -*-

from ConfigParser import SafeConfigParser
from sys import exit
import logging
import ldap
import MySQLdb


# define env variables
logging_file = 'log'
logging_level = logging.DEBUG
conf_files = ['public.conf', 'mac_info.conf']

# read application config
config = SafeConfigParser()
config.read(conf_files)
conf_warn = ""
exclude_login = []

# Database objects
db = None
cr = None

try:
    exclude_conf_login = config.get('logins', 'exclude')
    exclude_login = exclude_conf_login.split(",")
    logging_file = config.get('logging', 'file')
    logging_conf_level = config.get('logging', 'level')
except Exception, e:
    conf_warn = "Can't read config: " + str(e)
    logging_conf_level = None

# init log file
if logging_conf_level:
    level = logging_conf_level.lower()
    if level == "debug":
        logging_level = logging.DEBUG
    elif level == "info":
        logging_level = logging.INFO
    elif level == "warning":
        logging_level = logging.WARNING
    elif level == "error":
        logging_level = logging.ERROR
    elif level == "critical":
        logging_level = logging.CRITICAL

logging.basicConfig(
        filename=logging_file,
        level=logging_level,
        format='%(asctime)s %(levelname)s %(message)s',
        datefmt='%m/%d/%Y %H:%M:%S'
)

if conf_warn != "":
    logging.warning(conf_warn)

try:
    ad_ldap_url = config.get('ad-ldap', 'url')
    ad_ldap_bind_dn = config.get('ad-ldap', 'bind_dn')
    ad_ldap_secret = config.get('ad-ldap', 'secret')
    ad_ldap_base_dn = config.get('ad-ldap', 'base_dn')
    mysql_host = config.get('mysql', 'host')
    mysql_user = config.get('mysql', 'user')
    mysql_passwd = config.get('mysql', 'passwd')
    mysql_db = config.get('mysql', 'db')
except Exception, e:
    logging.critical("Can't read config: " + str(e))
    exit(1)


class User:
    login = ""
    fio = ""
    mail = ""
    groups = ""

    def __init__(self, login=login, fio=fio, mail=mail, groups=groups):
        if login != "":
            self.login = login
        if fio != "":
            self.fio = fio
        if mail != "":
            self.mail = mail
        if groups != "":
            self.groups = groups

    def __repr__(self):
        return self.login+" "+self.fio+" "+self.mail+" "+self.groups

    def insert_to_db(self):
        sql = "insert into erp_login (login,fio,mail,groups) \
               values ('"+self.login+"','"+self.fio+"','"+self.mail+"','"+self.groups+"');"
        logging.debug("Insert sql: " + sql)
        cr.execute(sql)

    def update_db(self):
        sql = "select login, fio, mail, groups from erp_login where login = '"+self.login+"';"
        cr.execute(sql)
        res = cr.fetchall()
        if len(res) == 1:
            # compare and update
            login, fio, mail, groups = res[0]
            changes_dict = {}
            if unicode(self.fio, "utf-8") != fio:
                changes_dict['fio'] = self.fio
            if self.mail != mail:
                changes_dict['mail'] = self.mail
            if self.groups != groups:
                changes_dict['groups'] = self.groups
            if len(changes_dict) > 0:
                self.update_changes(changes_dict)
                logging.debug("Changes_dict: " + str(changes_dict))
        elif len(res) == 0:
            # print "Insert",self
            self.insert_to_db()
        else:
            logging.debug("Non uniq login " + self.login)

    def update_changes(self, changes_dict):
        values = ""
        sql = ""
        for field in changes_dict:
            values += field+" = '"+changes_dict[field]+"',"
            sql = "update erp_login set "+values[:-1]+" where login = '"+self.login+"';"
        if sql != "":
            logging.debug("Update sql: "+sql)
            cr.execute(sql)


def get_ldap_users():
    res = []
    logging.debug("Try to get ldap users.")
    try:
        ad = ldap.initialize(ad_ldap_url)
        ad.simple_bind_s(ad_ldap_bind_dn, ad_ldap_secret)
        filterexp = 'objectClass=user'
        scope = ldap.SCOPE_SUBTREE
        attrlist = ['mail', 'sAMAccountName']
        res = ad.search_s(ad_ldap_base_dn, scope, filterexp, attrlist)
        ad.unbind_s()
    except Exception, err:
        logging.error("Can't read ldap data: " + str(err))
    return res


def parce_ldap(data):
    res = {}
    if len(data) == 0:
        return res
    for line in data:
        data_user_groups = line[0][3:-len(ad_ldap_base_dn)-1].split(',', 1)
        fio = data_user_groups[0]
        groups = ""
        mail = ""
        login = ""
        if len(data_user_groups) == 2:
            groups = data_user_groups[1].replace("OU=", "")
        if 'mail' in line[1]:
            mail = line[1]['mail'][0]
        if 'sAMAccountName' in line[1]:
            login = line[1]['sAMAccountName'][0]
        if login in exclude_login:
            continue
        # print login, user, mail, groups
        res[login] = User(login, fio, mail, groups)
    logging.debug("Get "+str(len(res))+" users.")
    return res


def update_db_users(user_dict):
    for login in user_dict:
        user_dict[login].update_db()
        db.commit()
        # print user_dict[login]


def connect_mysql():
    global db, cr
    res = True
    logging.debug("Connect to mysql.")
    try:
        # Connect to mysql
        db = MySQLdb.connect(
                            host=mysql_host,
                            user=mysql_user,
                            passwd=mysql_passwd,
                            db=mysql_db,
                            charset='utf8',
                            init_command='SET NAMES UTF8'
        )
        cr = db.cursor()
    except Exception, e:
        logging.error("Can't connet to mysql: "+str(e))
        res = False
    return res


def delete_from_db(user_dict):
    # remove deleted users
    sql = "select login from erp_login;"
    cr.execute(sql)
    res = cr.fetchall()
    for l in res:
        if l[0] not in user_dict:
            sql = "delete from erp_login where login = '" + l[0] + "';"
            logging.debug("Deleting user: "+sql)
            cr.execute(sql)
            db.commit()


def close_db():
    if db is not None:
        db.close()


if __name__ == "__main__":
    logging.info("Start updating ldap users.")
    ldap_data = get_ldap_users()
    user_dict = parce_ldap(ldap_data)
    if connect_mysql():
        update_db_users(user_dict)
        delete_from_db(user_dict)
        close_db()
