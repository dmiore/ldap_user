#!/usr/bin/python
# -*- coding: utf-8 -*-

from ConfigParser import SafeConfigParser
from sys import exit
import logging

from switch import Switch


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
    # exit(1)


def get_switch_config():
    for section in config.sections():
        if section.find("switch_") != -1:
            switch_conf = {}
            for item in ["switch_type", "ip", "name", "stack_member", "user", "pass"]:
                switch_conf[item] = config.get(section, item)
            return switch_conf


if __name__ == "__main__":
    print "Test"
    dict_sw = get_switch_config()
    sw = Switch(
            stype=dict_sw['switch_type'],
            sm=dict_sw['stack_member'],
            ip=dict_sw['ip'],
            host=dict_sw['name'],
            user=dict_sw['user'],
            passwd=dict_sw['pass'],
            log=logging
    )
    sw.info()
