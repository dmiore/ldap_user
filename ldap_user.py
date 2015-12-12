#!/usr/bin/python
# -*- coding: utf-8 -*-

from ConfigParser import SafeConfigParser
from sys import exit
import logging
import ldap

# define env variables
logging_file = 'log'
logging_level = logging.DEBUG
conf_files = ['public.conf', 'mac_info.conf']

# read application config
config = SafeConfigParser()
config.read(conf_files)
conf_warn = ""
exclude_login = []

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


def get_ldap_users():
    res = []
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
        user = data_user_groups[0]
        group = ""
        mail = ""
        login = ""
        if len(data_user_groups) == 2:
            group = data_user_groups[1].replace("OU=","")
        if 'mail' in line[1]:
            mail = line[1]['mail'][0]
        if 'sAMAccountName' in line[1]:
            login = line[1]['sAMAccountName'][0]
        if login in exclude_login:
            continue
        print login, user, mail, group


if __name__ == "__main__":
    ldap_data = get_ldap_users()
    user_dict = parce_ldap(ldap_data)

