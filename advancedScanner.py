#!/usr/bin/python

from socket import *
import optparse
from threading import *
from termcolor import colored

def retBanner(port, host):
    try:
        socket.setdefaulttimeout(2)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        banner = s.recv(1024)
        return banner

    except:
        return ''


def connScan(host, port):
    try:
        S = socket(AF_INET, SOCK_STREAM)
        S.connect((host, port))
        banner = retBanner(port, host)
        print(colored(f'[+] {port}/tcp OPEN', 'green | {banner}'))
    except:
        print(colored(f'[-] {port}/tcp CLOSED', 'red'))
    finally:
        S.close()


def port_scan(host, ports):
    try:
        targetIP = gethostbyname(host)

    except:
        print(colored(f'[-] Unknown Host {host}', 'red'))
    
    try:
        target_name = gethostbyaddr(targetIP)
        print(colored(f'[+] Scan results for: {target_name[0]}', 'green'))

    except:
        print(colored(f'[+] Scan results for: {targetIP}', 'green'))
    
    setdefaulttimeout(1)
    for port in ports:
        t = Thread(target=connScan, args=(host, int(port)))
        t.start()
    

def main():
    parser = optparse.OptionParser('Usage of program: ' + '-H <target host> -p <target port>')
    parser.add_option('-H', dest='target_host', type='string', help='specify target host')
    parser.add_option('-p', dest='target_port', type='string', help='specify target ports separated by comma')
    (options, args) = parser.parse_args()
    target_host = options.target_host
    target_ports = str(options.target_port).split(',')
    if (target_host == None or target_ports == None):
        print(parser.usage)
        exit(0)

    port_scan(target_host, target_ports)


if __name__ == '__main__':
    main()