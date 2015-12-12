#!/usr/bin/python
# -*- coding: utf-8 -*-

from ConfigParser import SafeConfigParser
from sys import exit
import logging

# define env variables
logging_file = 'log'
logging_level = logging.DEBUG
conf_files = ['public.conf', 'mac_info.conf']

# read application config
config = SafeConfigParser()
config.read(conf_files)
conf_warn = ""

try:
    logging_file = config.get('logging', 'file1')
    logging_conf_level = config.get('logging', 'level')
except Exception, e:
    conf_warn = "Can't read logging config:" + str(e)
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

print ad_ldap_url, ad_ldap_bind_dn, ad_ldap_secret, ad_ldap_base_dn, mysql_host, mysql_user, mysql_passwd, mysql_db


if __name__ == "__main__":
    print "ii"
