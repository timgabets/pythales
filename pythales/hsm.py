#!/usr/bin/env python

import getopt
import sys
import socket
import struct 

from tracetools.tracetools import trace

class HSM():
    def __init__(self, _port=None):
        if _port:
            self.port = _port
        else:
            self._port = 1500

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind(('', self.port))   
            self.sock.listen(5)
            print('Listening on port {}'.format(self.port))
        except OSError as msg:
            print('Error starting server: {}'.format(msg))
            sys.exit()


    def run(self):
        while True:
            conn, addr = self.sock.accept()
            print ('Connected client: ' + addr[0] + ':' + str(addr[1]))

            while True:
                try:
                    data = conn.recv(4096)
                    trace('<< {} bytes received: '.format(len(data)), data)
                        
                    Len = struct.unpack_from("!H", data[:2])[0]
                    
                    if(Len != len(data) - 2):
                        print("Invalid length {0} - {1}".format(Len, len(data) - 2))
                        conn.close()
                        continue
                                    
                    conn.send(data)
                    trace('>> {} bytes sent:'.format(len(data)), data)
    
                except KeyboardInterrupt:
                    print('Exit')
                    s.close()
                    sys.exit()
    
    
def show_help(name):
    """
    Show help and basic usage
    """
    print('Usage: python3 {} [OPTIONS]... '.format(name))
    print('Thales HSM command simulator')
    print('  -p, --port=[PORT]\t\tTCP port to listen, 1500 by default')

if __name__ == '__main__':
    port = 1500
    max_conn = 5

    optlist, args = getopt.getopt(sys.argv[1:], 'hp:', ['help', 'port='])
    for opt, arg in optlist:
        if opt in ('-h', '--help'):
            show_help(sys.argv[0])
            sys.exit()
        elif opt in ('-p', '--port'):
            try:
                port = int(arg)
            except ValueError:
                print('Invalid TCP port: {}'.format(arg))
                sys.exit()

    hsm = HSM(port)
    hsm.run()


    
