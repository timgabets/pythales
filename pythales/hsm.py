#!/usr/bin/env python

import getopt
import sys
import socket
import struct 

from tracetools.tracetools import trace

class Message:
    def __init__(self, data=None, header=None):
        if data:
            """
            Incoming message
            """
            self.length = struct.unpack_from("!H", data[:2])[0]
            if(self.length != len(data) - 2):
                raise ValueError('Expected message of length {0} but actual received message length is {1}'.format(self.length, len(data) - 2))
    
            if header:
                for h, d in zip(header, data[2:]):
                    if h != d:
                        raise ValueError('Invalid header')
                self.header = header 

            if header:
                self.data = data[2 + len(header) : ]
            else:
                self.data = data[2:]
        
        else:
            """
            Outgoing message
            """
            self.header = header

    
    def get_length(self):
        """
        """
        return self.length


    def get_data(self):
        """
        """
        return self.data


    def build(self, data):
        """
        Build the outgoing message
        """
        if self.header:
            return struct.pack("!H", len(self.header) + len(data)) + self.header + data
        else:
            return struct.pack("!H", len(data)) + data


class HSM:
    def __init__(self, port=None, header=None):
        self.firmware_version = '0007-E000'

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
            try:
                conn, addr = self.sock.accept()
                print ('Connected client: ' + addr[0] + ':' + str(addr[1]))

                while True:
                    data = conn.recv(4096)
                    trace('<< {} bytes received: '.format(len(data)), data)

                    try:
                        request = Message(data, header=self.header)
                    except ValueError as e:
                        print(e)
                        continue

                    response = Message(data=None, header=self.header).build(self.get_response(request.get_data()))
                    conn.send(response)

                    trace('>> {} bytes sent:'.format(len(response)), response)
    
            except KeyboardInterrupt:
                print('Exit')
                self.sock.close()
                sys.exit()
            
            except:
                print('Exception occured')
                continue

    

    def get_diagnostics_data(self):
        lmk_check_value = '1234567890ABCDEF'
        return lmk_check_value + self.firmware_version


    def get_response(self, request):
        rqst_command_code = request[:2]
        resp_command_code = None
        error_code = b'00'
        resp_data = ''

        if rqst_command_code == b'NC':
            resp_command_code = b'ND'
            resp_data = self.get_diagnostics_data()
        else:
            resp_command_code = b'ZZ'
            error_code = b'00'

        return resp_command_code + error_code + bytes(resp_data, 'utf-8')


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


    
