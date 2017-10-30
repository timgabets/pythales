#!/usr/bin/env python

import getopt
import sys

from pythales.hsm import HSM

def show_help(name):
    """
    Show help and basic usage
    """
    print('Usage: python3 {} [OPTIONS]... '.format(name))
    print('Thales HSM command simulator')
    print('  -p, --port=[PORT]\t\tTCP port to listen, 1500 by default')
    print('  -k, --key=[KEY]\t\tTCP port to listen, 1500 by default')
    print('  -h, --header=[HEADER]\t\tmessage header, empty by default')
    print('  -d, --debug\t\t\tEnable debug mode (show CVV/PVV mismatch etc)')
    print('  -s, --skip-parity\t\t\tSkip key parity checks')
    print('  -a, --approve-all\t\t\tApprove all requests')


if __name__ == '__main__':
    port = None
    header = ''
    key = None
    debug = False
    skip_parity = None
    approve_all = None

    optlist, args = getopt.getopt(sys.argv[1:], 'h:p:k:dsa', ['header=', 'port=', 'key=', 'debug', 'skip-parity', 'approve-all'])
    for opt, arg in optlist:
        if opt in ('-h', '--header'):
            header = arg
        elif opt in ('-p', '--port'):
            try:
                port = int(arg)
            except ValueError:
                print('Invalid TCP port: {}'.format(arg))
                sys.exit()
        elif opt in ('-k', '--key'):
            key = arg
        elif opt in ('-d', '--debug'):
            debug = True
        elif opt in ('-s', '--skip-parity'):
            skip_parity = True
        elif opt in ('-a', '--approve-all'):
            approve_all = True
        else:
            show_help(sys.argv[0])
            sys.exit()

    hsm = HSM(port=port, header=header, key=key, debug=debug, skip_parity=skip_parity, approve_all=approve_all)
    hsm.run()