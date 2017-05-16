#!/usr/bin/env python

import getopt
import sys
import socket
import struct 

from tracetools.tracetools import trace
from collections import OrderedDict
from Crypto.Cipher import DES3
from binascii import hexlify, unhexlify


def raw2str(raw_data):
    """
    Convert raw binary data to string representation, e.g. b'\xdf\x12g\xee\xdc\xba\x98v'-> 'DF1267EEDCBA9876'
    """
    return hexlify(raw_data).decode('utf-8').upper()


def raw2B(raw_data):
    """
    Convert raw binary data to hex representation, e.g. b'\xdf\x12g\xee\xdc\xba\x98v'-> b'DF1267EEDCBA9876'

    """
    return bytes(raw2str(raw_data), 'utf-8')


def B2raw(bin_data):
    """
    Convert hex representation to raw binary data, e.g. b'DF1267EEDCBA9876' -> b'\xdf\x12g\xee\xdc\xba\x98v'
    """
    return unhexlify(bin_data)


class DC():
    def __init__(self, data):
        self.data = data
        self.fields = OrderedDict()

        # TPK
        if self.data[0:1] in [b'U', b'T', b'S']:
            field_size = 33            
            self.fields['TPK'] = self.data[0:field_size]
            self.data = self.data[field_size:]

        # PVK
        if self.data[0:1] in [b'U']:
            field_size = 33            
            self.fields['PVK Pair'] = self.data[0:field_size]
            self.data = self.data[field_size:]
        else:
            field_size = 32
            self.fields['PVK Pair'] = self.data[0:field_size]
            self.data = self.data[field_size:]

        # PIN block
        field_size = 16
        self.fields['PIN block'] = self.data[0:field_size]
        self.data = self.data[field_size:]

        # PIN block format code
        field_size = 2
        self.fields['PIN block format code'] = self.data[0:field_size]
        self.data = self.data[field_size:]

        # Account Number
        field_size = 12
        self.fields['Account Number'] = self.data[0:field_size]
        self.data = self.data[field_size:]

        # PVKI
        field_size = 1
        self.fields['PVKI'] = self.data[0:field_size]
        self.data = self.data[field_size:]

        # PVV
        field_size = 4
        self.fields['PVV'] = self.data[0:field_size]
        self.data = self.data[field_size:]


class CA():
    def __init__(self, data):
        self.data = data
        self.fields = OrderedDict()

        # TPK
        if self.data[0:1] in [b'U', b'T', b'S']:
            field_size = 33
            self.fields['TPK'] = self.data[0:field_size]
            self.data = self.data[field_size:]

        # Destination Key
        if self.data[0:1] in [b'U', b'T', b'S']:
            field_size = 33
            self.fields['Destination Key'] = self.data[0:field_size]
            self.data = self.data[field_size:]

        # Maximum PIN Length
        field_size = 2
        self.fields['Maximum PIN Length'] = self.data[0:field_size]
        self.data = self.data[field_size:]

        # Source PIN block
        field_size = 16
        self.fields['Source PIN block'] = self.data[0:field_size]
        self.data = self.data[field_size:]

        # Source PIN block format
        field_size = 2
        self.fields['Source PIN block format'] = self.data[0:field_size]
        self.data = self.data[field_size:]

        # Destination PIN block format
        field_size = 2
        self.fields['Destination PIN block format'] = self.data[0:field_size]
        self.data = self.data[field_size:]

        # Account Number
        field_size = 12
        self.fields['Account Number'] = self.data[0:field_size]
        self.data = self.data[field_size:]


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
            elif self.command_code == b'CA':
                self.fields = CA(self.data[2:]).fields
            else:
                self.fields = None

        else:
            """
            Outgoing message
            """
            self.header = header
            self.fields = OrderedDict()

    
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


    def build(self):
        """
        Build the outgoing message (legacy)
        """
        data = b''
        for key, value in self.fields.items():
            data += value

        if self.header:
            return struct.pack("!H", len(self.header) + len(data)) + self.header + data
        else:
            return struct.pack("!H", len(data)) + data


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
            dump = dump + '\t[' + key.ljust(width, ' ') + ']: [' + value.decode('utf-8') + ']\n'
        return dump


class HSM:
    def __init__(self, port=None, header=None, key=None):
        self.firmware_version = '0007-E000'

        if port:
            self.port = port
        else:
            self.port = 1500

        if header:
            self.header = bytes(header, 'utf-8')
        else:
            self.header = b''

        if key:
            self.LMK = bytes.fromhex(key)
        else:
            self.LMK = bytes.fromhex('deadbeef deadbeef deadbeef deadbeef')
        self.cipher = DES3.new(self.LMK, DES3.MODE_ECB)

    
    def info(self):
        """
        """
        dump = ''
        dump += 'LMK: {}\n'.format(raw2str(self.LMK))
        dump += 'Firmware version: {}\n'.format(self.firmware_version)
        if self.header:
            dump += 'Message header: {}\n'.format(self.header.decode('utf-8'))
        return dump


    def _init_connection(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind(('', self.port))   
            self.sock.listen(5)
            print(self.info())
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
                    response_data = response.build()
                    conn.send(response_data)

                    trace('>> {} bytes sent to {}:'.format(len(response_data), client_name), response_data)
                    print(response.trace())
    
            except KeyboardInterrupt:
                break
            
            except:
                print('Disconnected client: {}'.format(client_name))
                conn.close()
                continue

        self.sock.close()
        print('Exit')


    def _get_clear_key(self, encrypted_key):
        """
        Decrypt the key, encrypted under LMK
        """
        if encrypted_key[0:1] in [b'U']:
            return self.cipher.decrypt(B2raw(encrypted_key[1:]))
        else:
            return self.cipher.decrypt(B2raw(encrypted_key))


    def _decrypt_pinblock(self, encrypted_pinblock, encrypted_terminal_key):
        """
        Decrypt pin block
        """
        clear_terminal_key = self._get_clear_key(encrypted_terminal_key)
        cipher = DES3.new(clear_terminal_key, DES3.MODE_ECB)
        decrypted_pinblock = cipher.decrypt(B2raw(encrypted_pinblock))
        return raw2B(decrypted_pinblock)


    def _get_clear_pin(self, pinblock, account_number):
        """
        Calculate the clear PIN from provided PIN block and account_number, which is the 12 right-most digits of card account number, excluding check digit
        """
        raw_pinblock = bytes.fromhex(pinblock.decode('utf-8'))
        raw_acct_num = bytes.fromhex((b'0000' + account_number).decode('utf-8'))
            
        pin_str = ''.join(['{0:#0{1}x}'.format((i ^ j), 4)[2:] for i, j in zip(raw_pinblock, raw_acct_num)])
        pin_length = int(pin_str[:2], 16)
        
        if pin_length >= 4 and pin_length < 9:
            pin = pin_str[2:2+pin_length]            
            try:
                int(pin)
            except ValueError:
                raise ValueError('PIN contains non-numeric characters')
            return bytes(pin, 'utf-8')
        else:
            raise ValueError('Incorrect PIN length: {}'.format(pin_length))

    
    def check_key_parity(self, key):
        pass


    def _get_pvv_digits_from_string(self, cyphertext):
        """
        Extract PVV digits from the cyphertext (HEX-encoded string)
        """
        PVV = ''
    
        """
        1. The cyphertext is scanned from left to right. Decimal digits are
        selected during the scan until four decimal digits are found. Each
        selected digit is placed from left to right according to the order
        of selection. If four decimal digits are found, those digits are the
        PVV.
        """
        for c in cyphertext:
            if len(PVV) >= 4:
                break
    
            try:
                int(c)
                PVV += c
            except ValueError:
                continue
    
        """
        2. If, at the end of the first scan, less than four decimal digits
        have been selected, a second scan is performed from left to right.
        During the second scan, all decimal digits are skipped and only nondecimal
        digits can be processed. Nondecimal digits are converted to decimal
        digits by subtracting 10. The process proceeds until four digits of
        PVV are found.
        """
        if len(PVV) < 4:
            for c in cyphertext:
                if len(PVV) >= 4:
                    break
    
                if (int(c, 16) - 10) >= 0:
                    PVV += str(int(c, 16) - 10)
    
        return PVV


    def _get_visa_pvv(self, account_number, key_index, pin, PVK):
        """
        The algorithm generates a 4-digit PIN verification value (PVV) based on the transformed security parameter (TSP).
    
        For VISA PVV algorithms, the leftmost 11 digits of the TSP are the personal account number (PAN), 
        the leftmost 12th digit is a key table index to select the PVV generation key, and the rightmost 
        4 digits are the PIN. The key table index should have a value between 1 and 6, inclusive.
        """
        tsp = account_number[-12:-1] + key_index + pin
        if len(PVK) != 32:
            raise ValueError('Incorrect key length')

        left_key_cypher = DES3.new(PVK[:16], DES3.MODE_ECB)
        right_key_cypher = DES3.new(PVK[16:], DES3.MODE_ECB)

        encrypted_tsp = left_key_cypher.encrypt(right_key_cypher.decrypt((left_key_cypher.encrypt(B2raw(tsp)))))
        return bytes(self._get_pvv_digits_from_string(raw2str(encrypted_tsp)), 'utf-8')


    def verify_pin(self, request):
        """
        Get response to DC command
        """
        decrypted_pinblock = self._decrypt_pinblock(request.fields['PIN block'], request.fields['TPK'])
        response =  Message(data=None, header=self.header)
        response.fields['Response Code'] = b'DD'

        try:
            pin = self._get_clear_pin(decrypted_pinblock, request.fields['Account Number'])
            pvv = self._get_visa_pvv(request.fields['Account Number'], request.fields['PVKI'], pin[:4], request.fields['PVK Pair'])
            if pvv == request.fields['PVV']:
                response.fields['Error Code'] = b'00'
            else:
                response.fields['Error Code'] = b'01'
            
            return response

        except ValueError:
            response.fields['Error Code'] = b'01'
            return response


    def translate_pinblock(self, request):
        """
        Get response to CA command (Translate PIN from TPK to ZPK)
        TODO: return Message object
        """
        response_code = b'CB00'
        pinblock_format = request.fields['Destination PIN block format']

        if request.fields['Destination PIN block format'] != request.fields['Source PIN block format']:
            raise ValueError('Cannot translate PIN block from format {} to format {}'.format(request.fields['Source PIN block format'].decode('utf-8'), request.fields['Destination PIN block format'].decode('utf-8')))

        if request.fields['Source PIN block format'] != b'01':
            raise ValueError('Unsupported PIN block format: {}'.format(request.fields['Source PIN block format'].decode('utf-8')))

        decrypted_pinblock = self._decrypt_pinblock(request.fields['Source PIN block'], request.fields['TPK'])
        pin_length = decrypted_pinblock[0:2]

        if request.fields['Destination Key'][0:1] in [b'U']:
            destination_key = request.fields['Destination Key'][1:]
        else:
            destination_key = request.fields['Destination Key']

        cipher = DES3.new(B2raw(destination_key), DES3.MODE_ECB)
        translated_pin_block = cipher.encrypt(B2raw(decrypted_pinblock))

        response = Message(data=None, header=self.header)
        response.fields['Response Code'] = b'CB'
        response.fields['Error Code'] = b'00'
        response.fields['PIN Length'] = decrypted_pinblock[0:2]
        response.fields['Destination PIN Block'] = raw2B(translated_pin_block)
        response.fields['Destination PIN Block format'] = pinblock_format

        return response


    def get_diagnostics_data(self):
        """
        Get response to NC command
        """
        response = Message(data=None, header=self.header)
        response.fields['Response Code'] = b'ND' 
        response.fields['Error Code'] = b'00' 
        # TODO: non-dummy check value
        response.fields['LMK Check Value'] = b'1234567890ABCDEF'
        response.fields['Firmware Version'] = bytes(self.firmware_version, 'utf-8')
        return response


    def get_response(self, request):
        """
        """
        rqst_command_code = request.get_command_code()
        if rqst_command_code == b'NC':
            return self.get_diagnostics_data()
        elif rqst_command_code == b'DC':
            return self.verify_pin(request)
        elif rqst_command_code == b'CA':
            return self.translate_pinblock(request)
        else:
            response = Message(data=None, header=self.header)
            response.fields['Response Code'] = b'ZZ'
            response.fields['Error Code'] = b'00'
            return response


def show_help(name):
    """
    Show help and basic usage
    """
    print('Usage: python3 {} [OPTIONS]... '.format(name))
    print('Thales HSM command simulator')
    print('  -p, --port=[PORT]\t\tTCP port to listen, 1500 by default')
    print('  -k, --key=[KEY]\t\tTCP port to listen, 1500 by default')
    print('  -h, --header=[HEADER]\t\tmessage header, empty by default')


if __name__ == '__main__':
    port = None
    header = ''
    key = None

    optlist, args = getopt.getopt(sys.argv[1:], 'h:p:k:', ['header=', 'port=', 'key='])
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
        else:
            show_help(sys.argv[0])
            sys.exit()

    hsm = HSM(port=port, header=header, key=key)
    hsm.run()
