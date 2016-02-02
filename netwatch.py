#!/usr/bin/env python
#  -*- coding: utf-8 -*-
# *****************************************************************************
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# Module authors:
#   Alexander Lenz <alexander.lenz@frm2.tum.de>
#
# *****************************************************************************

import sys
import time
import nmap
import logging
import argparse
import pprint
import multiprocessing
import socket

EXCLUDED = [0, 255]
TIMEOUT = 100  # in ms
RETRIES = 1
DNS_SRVS = []
SCANPORTS = ['22', '23', '42', '137', '80', '502', '7000', '48898']

## util ##


def determineBestOsMatches(nmapOsMatches):
    bestAccuracy = 0
    bestMatches = []

    for match in nmapOsMatches:
        accuracy = int(match['accuracy'])
        if accuracy > bestAccuracy:
            bestAccuracy = accuracy
            bestMatches = []

        if accuracy == bestAccuracy:
            bestMatches.append(match['name'])
        else:
            break

    return bestMatches
##########


class Watcher(object):
    def __init__(self, excludes=None, dnssrvs=None, timeout=100, retries=1,
                 ports=None, deepScanDuringInit=False):
        if excludes is None:
            excludes = [0, 255]
        if ports is None:
            ports = [22, 23, 80]

        self._excludes = excludes
        self._dnssrvs = dnssrvs
        self._timeout = timeout
        self._retries = retries
        self._ports = ports
        self._initDone = False
        self._deepScanDuringInit=deepScanDuringInit
        self. _hostQueue = multiprocessing.Queue()
        self._hosts = {}  # ip : mac
        self._nms = []
        self._scanningHost = socket.gethostbyname(socket.gethostname())

    def watch(self, netid, prefix):
        logging.info('Initial scan of %s/%s ...' % (netid, prefix))

        options = ['-sn',
                   '-n',
                   '-T5',
                   '--max-parallelism=100']

        options.append('--host-timeout %sms' % self._timeout)

        args = ' '.join(options)
        hosts = '%s/%s' % (netid, prefix)

        print(args)

        nm = nmap.PortScannerAsync()
        self._nms.append(nm)

        while True:
            nm.scan(hosts=hosts,
                callback=self._enqueueFoundHost,
                arguments=args)

            while nm.still_scanning() or not self._hostQueue.empty():
                while not self._hostQueue.empty():
                    entry = self._hostQueue.get(timeout=0.1)
                    host, mac = entry.split('#')
                    self._handleHost(host, mac)

                time.sleep(1)

            self._waitForScans()
            self._nms = []

            if not self._initDone:
                self._initDone = True
                logging.info('Initial scan done; start watching')

    def _waitForScans(self):
        for entry in self._nms:
            entry.wait()

    def _enqueueFoundHost(self, host, result):
        if host == self._scanningHost:
            return
        try:

            if int(host.rpartition('.')[-1]) in self._excludes:
                logging.debug('%s excluded' % host)
                return

            if not result['scan']:
                logging.debug('%s offline' % host)
                return

            mac = result['scan'][host]['addresses']['mac']
            self._hostQueue.put('%s#%s' % (host, mac))
        except KeyError:
            logging.warning('Cannot determine mac address for %s' % host)
        except Exception as e:
            logging.exception(e)

    def _handleHost(self, host, mac):
        if host in self._hosts:
            if self._hosts[host] == mac:
                return
        self._hosts[host] = mac

        if self._initDone or self._deepScanDuringInit:
            self._deepScanHost(host)

    def _deepScanHost(self, host):
        logging.debug('Deep scan %s ...' % host)

        options = ['-sS',
                   '-O',
                   '-p %s' % ','.join(self._ports)]

        options.append('--max-rtt-timeout %sms' % self._timeout)

        if DNS_SRVS:
            options.append('--dns-servers %s ' % ','.join(self._dnssrvs))

        args = ' '.join(options)

        nm = nmap.PortScannerAsync()
        self._nms.append(nm)
        nm.scan(hosts=str(host),
            callback=self._handleDeepScanHost,
            arguments=args)

    def _handleDeepScanHost(self, host, result):
        scanResult = result['scan'][host]

        # if logging.root.level == logging.DEBUG:
        #     pprint.pprint(scanResult)

        hostname = scanResult['hostname'] if scanResult['hostname'] else 'Unknown'
        status = '{state} ({reason})'.format(**scanResult['status'])

        uptime = '-'
        if 'uptime' in scanResult:
            uptime = '%s h' % round(float(scanResult['uptime']['seconds']) / 60.0 / 60.0, 2)

        osInfo = '-'
        if 'osmatch' in scanResult:
            osInfo = ' / '.join(determineBestOsMatches(scanResult['osmatch']))

        ports = '-'
        if 'tcp' in scanResult:
            ports = []
            tcpResult = scanResult['tcp']
            for port in SCANPORTS:
                if int(port) in tcpResult:
                    if tcpResult[int(port)]['state'] == 'open':
                        ports.append(port)
            ports = ', '.join(ports) if ports else '-'

        data = {
            'mac' : scanResult['addresses']['mac'],
            'ipv4' : scanResult['addresses']['ipv4'],
            'ip' : host,
            'hostname' : hostname,
            'status' : status,
            'uptime' : uptime,
            'os' : osInfo,
            'ports' : ports
        }

        msg = '''
        Host: {hostname} ({ip})
            MAC:         {mac}
            IPv4:        {ipv4}
            Status:      {status}
            Uptime:      {uptime}
            OS:          {os}
            Open ports:  {ports}
        '''.format(**data)

        print(msg)


def parseArgv(argv):
    parser = argparse.ArgumentParser(description='Net scanner',
                                     conflict_handler='resolve')

    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        help='Verbose logging',
                        default=False)
    parser.add_argument('-e', '--exclude',
                        nargs='+',
                        help='Excluded ip addresses',
                        default=[0,255])
    parser.add_argument('-d', '--dnssrvs',
                        nargs='+',
                        help='Dns servers to use',
                        default=[])
    parser.add_argument('-t', '--timeout',
                        type=str,
                        help='Timeout in ms for network requests',
                        default=100)
    parser.add_argument('-r', '--retries',
                        type=int,
                        help='Retries for network requests',
                        default=1)
    parser.add_argument('-p', '--ports',
                        nargs='+',
                        help='Ports to scan',
                        default=['22', '23', '42', '137', '80', '502', '7000', '48898'])
    parser.add_argument('netid',
                        type=str,
                        help='Network to watch (format netid/prefix)',
                        default=False)
    return parser.parse_args(argv)


def main(argv):
    args = parseArgv(argv[1:])

    logLevel = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=logLevel,
                        format='[%(asctime)-15s][%(levelname)s]: %(message)s')

    w = Watcher(excludes=args.exclude,
                dnssrvs=args.dnssrvs,
                timeout=args.timeout,
                retries=args.retries,
                ports=args.ports)

    netid, prefix = args.netid.split('/')
    w.watch(netid, prefix)



if __name__ == '__main__':
    sys.exit(main(sys.argv))
