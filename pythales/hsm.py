#!/usr/bin/env python

import getopt
import sys
import socket
import struct 

from tracetools.tracetools import trace

class Message:
    def __init__(self, data, header=None):
        Len = struct.unpack_from("!H", data[:2])[0]
        if(Len != len(data) - 2):
            raise ValueError('Expected message of length {0} but actual received message length is {1}'.format(Len, len(data) - 2))

        self.length = Len

    def get_length(self):
        return self.length


class HSM:
    def __init__(self, port=None, header=None):
        
        if port:
            self.port = port
        else:
            self.port = 1500

        if header:
            self.header = bytes(header, 'utf-8')
        else:
            self.header = b''

    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind(('', self.port))   
            self.sock.listen(5)
            print('Listening on port {}'.format(self.port))
        except OSError as msg:
            print('Error starting server: {}'.format(msg))
            sys.exit()

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
                        continue

                    request = Message(data, header=self.header)


                    response = struct.pack("!H", len(response)) + self.get_response(request[:2])
                    conn.send(response)
                    trace('>> {} bytes sent:'.format(len(response)), response)
    
                except KeyboardInterrupt:
                    print('Exit')
                    s.close()
                    sys.exit()
    

    def match_header(self):
        pass

    def get_response(self, request):
        response = b'00'


        return self.header + response


def show_help(name):
    """
    Show help and basic usage
    """
    print('Usage: python3 {} [OPTIONS]... '.format(name))
    print('Thales HSM command simulator')
    print('  -p, --port=[PORT]\t\tTCP port to listen, 1500 by default')
    print('  -h, --header=[HEADER]\t\tmessage header, empty by default')

if __name__ == '__main__':
    port = None
    header = ''

    optlist, args = getopt.getopt(sys.argv[1:], 'h:p:', ['header=', 'port='])
    for opt, arg in optlist:
        if opt in ('-h', '--header'):
            header = arg
        elif opt in ('-p', '--port'):
            try:
                port = int(arg)
            except ValueError:
                print('Invalid TCP port: {}'.format(arg))
                sys.exit()
        else:
            show_help(sys.argv[0])
            sys.exit()

    hsm = HSM(port, header)
    hsm.run()


    
