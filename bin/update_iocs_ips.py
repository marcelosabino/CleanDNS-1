#!/usr/bin/env python2
# -*- coding: utf-8 -*-

#    This file is part of CleanDNS.
#
#    CleanDNS is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    CleanDNS is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with CleanDNS.  If not, see <http://www.gnu.org/licenses/>.

"""
    Update ips otx - 0.0.1 (01/27/18)
    Replaces the following files:
        - update_otx_ips.sh
        - update_malwaredomainlist_ips.sh
        - update_ransomwaretracker_ips.sh
        - update_shallblacklist_ips.sh
"""

# Libraries
import argparse
import ConfigParser
import os
import socket
import sys

# Constants
config = ConfigParser.RawConfigParser()
config.read('/cf/cleandns/etc/setup.cfg')

# Some vars
CLEANDNS_DIR = config.get('cleandns', 'dir')
TMP_DIR = config.get('tmp', 'dir')

# Update malwaredomainlist IP file
def update_malwaredomainlist():
    MALWARE_URL = config.get('malwaredomainlist', 'url')
    MALWARE_FILE = TMP_DIR + config.get('malwaredomainlist', 'file')
    DOMAIN_FILE = CLEANDNS_DIR + '/spool/ips-malwaredomainlist.txt'
    print 'Creating file %s' % DOMAIN_FILE
    os.chdir(TMP_DIR)
    os.system('fetch -a -w 3 -q ' + MALWARE_URL + ' -o ' + MALWARE_FILE + '>/dev/null')
    write_to_file(DOMAIN_FILE, MALWARE_FILE)

# Update the OTX IPs file
def update_otx():
    MALWARE_FILE = '/cf/otx_pulses/pulses.txt'
    DOMAIN_FILE = CLEANDNS_DIR + '/spool/ips-otx.txt'
    print 'Creating file %s' % DOMAIN_FILE
    write_to_file(DOMAIN_FILE, MALWARE_FILE)

# Update the Ransomwaretracker IPs file
def update_ransomwaretracker():
    MALWARE_URL = config.get('ransomwaretracker', 'url')
    MALWARE_FILE = TMP_DIR + config.get('ransomwaretracker', 'file')
    DOMAIN_FILE = CLEANDNS_DIR + '/spool/ips-ransomwaretracker.txt'
    print 'Creating file %s' % DOMAIN_FILE
    os.chdir(TMP_DIR)
    os.system('fetch --no-verify-peer -a -w 3 -q ' + MALWARE_URL + ' -o ' + MALWARE_FILE + '>/dev/null')
    write_to_file(DOMAIN_FILE, MALWARE_FILE)

# Update the shallablacklist IPs file
def update_shallblacklist():
    CATEGORY = 'spyware'
    MALWARE_URL = config.get('shallblacklist', 'url')
    MALWARE_FILE_TMP = 'shallalist.tar.gz'
    MALWARE_FILE = TMP_DIR + '/BL/' + CATEGORY + '/domains'
    DOMAIN_FILE = CLEANDNS_DIR + '/spool/ips-shallablacklist.txt'
    print 'Creating file %s' % DOMAIN_FILE
    os.chdir(TMP_DIR)
    os.system('fetch -a -w 3 -q ' + MALWARE_URL)
    os.system('tar -xzf ' + MALWARE_FILE_TMP + '>/dev/null')
    write_to_file(DOMAIN_FILE, MALWARE_FILE)

    # Remove the temporary files
    os.system('rm -rf ' + TMP_DIR + '/BL >/dev/null')

# Write to IP.txt corresponding file
def write_to_file(DOMAIN_FILE, MALWARE_FILE):
    f_regs = set()
    while open(MALWARE_FILE) as f:
        for line in f:
            try:
                socket.inet_aton(line)
                f_regs.add(line)
            except:
                continue

    f = open(DOMAIN_FILE, 'w')
    f.writelines(sorted(f_regs))
    f.close()

# Main function
def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('-m', '--malwaredomain', dest='md', help='Update the MalwareDomainList IP file', action='store_true')
    argparser.add_argument('-o', '--otx', dest='otx', help='Update the OTX IP file', action='store_true')
    argparser.add_argument('-r', '--rantracker', dest='rt', help='Update the RansomwareTracker IP file', action='store_true')
    argparser.add_argument('-s', '--shallblacklist', dest='sb', help='Update the ShallBlackList IP file', action='store_true')
    args = argparser.parse_args()

    if (args.md):
        update_malwaredomainlist()
    elif (args.otx):
        update_otx()
    elif (args.rt):
        update_ransomwaretracker()
    elif (args.sb):
        update_shallblacklist()
    else:
        os.system(sys.argv[0] + ' -h')

# IF main then main :-D
if __name__ == '__main__':
    main()
