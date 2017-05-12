#!/usr/bin/env python

import getopt
import sys
import socket
import struct 

from tracetools.tracetools import trace
from collections import OrderedDict

class DC():
    def __init__(self, data):
        self.data = data
        self.fields = OrderedDict()

        # TPK
        if self.data[0:1] in [b'U', b'T', b'S']:
            self.fields['TPK'] = self.data[0:33]
            self.data = self.data[33:]

        # PVK
        if self.data[0:1] in [b'U']:
            self.fields['PVK Pair'] = self.data[0:33]
            self.data = self.data[33:]
        else:
            self.fields['PVK Pair'] = self.data[0:32]
            self.data = self.data[32:]

        # PIN block
        self.fields['PIN block'] = self.data[0:16]
        self.data = self.data[16:]

        # PIN block format code
        self.fields['PIN block format code'] = self.data[0:2]
        self.data = self.data[2:]

        # Account Number
        self.fields['Account Number'] = self.data[0:12]
        self.data = self.data[12:]

        # PVKI
        self.fields['PVKI'] = self.data[0:1]
        self.data = self.data[1:]

        # PVV
        self.fields['PVV'] = self.data[0:4]
        self.data = self.data[4:]

    



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

            self.command_code = self.data[:2]
            
            if self.command_code == b'DC':
                self.fields = DC(self.data[2:]).fields
            else:
                self.fields = None

        else:
            """
            Outgoing message
            """
            self.header = header

    
    def get_command_code(self):
        """
        """
        return self.command_code


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
            return struct.pack("!H", len(self.header) + len(data)) + self.header + bytes(data, 'utf-8')
        else:
            return struct.pack("!H", len(data)) + bytes(data, 'utf-8')


    def trace(self):
        """
        """
        if not self.fields:
            return ''

        width = 0
        for key, value in self.fields.items():
            if len(key) > width:
                width = len(key)

        dump = ''
        for key, value in self.fields.items():
            dump = dump + '\t[' + key.ljust(width, ' ') + ']: [' + str(value)[2:-1] + ']\n'
        return dump


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

    def _init_connection(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind(('', self.port))   
            self.sock.listen(5)
            print('Listening on port {}'.format(self.port))
        except OSError as msg:
            print('Error starting server: {}'.format(msg))
            sys.exit()
        

    def run(self):
        self._init_connection()

        while True:
            try:
                conn, addr = self.sock.accept()
                client_name = addr[0] + ':' + str(addr[1])
                print ('Connected client: {}'.format(client_name))

                while True:
                    data = conn.recv(4096)
                    if len(data):
                        trace('<< {} bytes received from {}: '.format(len(data), client_name), data)

                    try:
                        request = Message(data, header=self.header)
                        print(request.trace())
                    except ValueError as e:
                        print(e)
                        continue

                    response = self.get_response(request)
                    conn.send(response)

                    trace('>> {} bytes sent to {}:'.format(len(response), client_name), response)
    
            except KeyboardInterrupt:
                break
            
            except:
                print('Disconnected client: {}'.format(client_name))
                conn.close()
                continue

        conn.close()
        self.sock.close()


    def get_diagnostics_data(self):
        """
        Get response to NC command
        """
        response_code = 'ND'
        error_code = '00'
        lmk_check_value = '1234567890ABCDEF'
        response_data = response_code + error_code + lmk_check_value + self.firmware_version
        return Message(data=None, header=self.header).build(response_data)


    def get_response(self, request):
        """
        """
        rqst_command_code = request.get_command_code()
        if rqst_command_code == b'NC':
            return self.get_diagnostics_data()

        #elif rqst_command_code == b'DC':
        #    return self.translate_pinblock(request)
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


    
