
import sys
import socket
import struct
import os

from tracetools.tracetools import trace
from collections import OrderedDict
from Crypto.Cipher import DES, DES3
from binascii import hexlify, unhexlify
from pynblock.tools import str2bytes, raw2str, raw2B, B2raw, xor, get_visa_pvv, get_visa_cvv, get_digits_from_string, key_CV, get_clear_pin, check_key_parity, modify_key_parity

class DummyMessage():
    def __init__(self, data):
        self.command_code = None
        self.fields = OrderedDict()

    def get(self, field):
        """
        """
        try:
            return self.fields[field]
        except KeyError:
            return None

    def set(self, field, value):
        """
        """
        self.fields[field] = value


    def get_command_code(self):
        """
        """
        return self.command_code

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


class BU(DummyMessage):
    def __init__(self, data):
        self.data = data
        self.command_code = b'BU'
        self.description = 'Generate a Key check value'
        self.fields = OrderedDict()

        # Key type code 
        field_size = 2
        self.fields['Key Type Code'] = self.data[0:field_size]
        self.data = self.data[field_size:]

        # Key length flag
        field_size = 1
        self.fields['Key Length Flag'] = self.data[0:field_size]
        self.data = self.data[field_size:]

        # Key
        if self.data[0:1] in [b'U']:
            field_size = 33
            self.fields['Key'] = self.data[0:field_size]
            self.data = self.data[field_size:]


class DC(DummyMessage):
    def __init__(self, data):
        self.data = data
        self.command_code = b'DC'
        self.description = 'Verify PIN'
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


class CA(DummyMessage):
    def __init__(self, data):
        self.data = data
        self.command_code = b'CA'
        self.description = 'Translate PIN from TPK to ZPK'
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


class CY(DummyMessage):
    def __init__(self, data):
        self.data = data
        self.command_code = b'CY'
        self.description = 'Verify CVV/CSC'
        self.fields = OrderedDict()

        # CVK
        if self.data[0:1] in [b'U', b'T', b'S']:
            field_size = 33
            self.fields['CVK'] = self.data[0:field_size]
            self.data = self.data[field_size:]

        # CVV
        field_size = 3
        self.fields['CVV'] = self.data[0:field_size]
        self.data = self.data[field_size:]

        # Primary Account Number
        delimiter_index = 0
        for byte in self.data:
            if byte == 59:  # b';'
                break
            delimiter_index += 1

        self.fields['Primary Account Number'] = self.data[0:delimiter_index]
        self.data = self.data[delimiter_index + 1:]

        # Expiration Date
        field_size = 4
        self.fields['Expiration Date'] = self.data[0:field_size]
        self.data = self.data[field_size:]

        # Service Code
        field_size = 3
        self.fields['Service Code'] = self.data[0:field_size]
        self.data = self.data[field_size:]


class EC(DummyMessage):
    def __init__(self, data):
        self.data = data
        self.command_code = b'EC'
        self.description = 'Verify an Interchange PIN using ABA PVV method'
        self.fields = OrderedDict()

        # ZPK
        if self.data[0:1] in [b'U']:
            field_size = 33
        self.fields['ZPK'] = self.data[0:field_size]
        self.data = self.data[field_size:]

        # PVK Pair
        if self.data[0:1] in [b'U']:
            field_size = 33
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

        if self.fields['PIN block format code'] != b'04':
            # Account Number
            field_size = 12
            self.fields['Account Number'] = self.data[0:field_size]
            self.data = self.data[field_size:]
        else:
            # Token
            field_size = 18
            self.fields['Token'] = self.data[0:field_size]
            self.data = self.data[field_size:]

        # PVKI
        field_size = 1
        self.fields['PVKI'] = self.data[0:field_size]
        self.data = self.data[field_size:]

        # PVV
        field_size = 4
        self.fields['PVV'] = self.data[0:field_size]
        self.data = self.data[field_size:] 


class HC(DummyMessage):
    """
    Generate a TMK, TPK or PVK
    """
    def __init__(self, data):
        self.data = data
        self.command_code = b'HC'
        self.description = 'Generate a TMK, TPK or PVK'
        self.fields = OrderedDict()

        # Current Key
        if self.data[0:1] in [b'U']:
            field_size = 33
        else:
            field_size = 16

        self.fields['Current Key'] = self.data[0:field_size]
        self.data = self.data[field_size:]

        # ; delimiter
        field_size = 1
        self.data = self.data[field_size:]

        # Key Scheme (TMK)
        field_size = 1
        self.fields['Key Scheme (TMK)'] = self.data[0:field_size]
        self.data = self.data[field_size:]

        # Key Scheme (LMK)
        field_size = 1
        self.fields['Key Scheme (LMK)'] = self.data[0:field_size]
        self.data = self.data[field_size:]


class NC(DummyMessage):
    """
    Diagnostics data
    """
    def __init__(self, data):
        self.data = data
        self.command_code = b'NC'
        self.description = 'Diagnostics data'
        self.fields = OrderedDict()


class OutgoingMessage(DummyMessage):
    def __init__(self, data=None, header=None):
        self.header = header
        self.fields = OrderedDict()


    def set_response_code(self, response_code):
        """
        """
        self.command_code = response_code
        self.fields['Response Code'] = str2bytes(response_code)


    def set_error_code(self, error_code):
        """
        """
        self.fields['Error Code'] = str2bytes(error_code)


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


def parse_message(data=None, header=None):
    """
    Parse the incoming message, check the header and return tuple (command code, command data)
    """
    if not data:
        return None
    
    length = struct.unpack_from("!H", data[:2])[0]
    if(length != len(data) - 2):
        raise ValueError('Expected message of length {0} but actual received message length is {1}'.format(length, len(data) - 2))
    
    if header:
        for h, d in zip(header, data[2:]):
            if h != d:
                raise ValueError('Invalid header')
        header = header 

    if header:
        data = data[2 + len(header) : ]
    else:
        data = data[2:]

    return (data[:2], data[2:])


class HSM:
    def __init__(self, port=None, header=None, key=None, debug=False, skip_parity=None):
        self.firmware_version = '0007-E000'

        if port:
            self.port = port
        else:
            self.port = 1500

        if header:
            self.header = str2bytes(header)
        else:
            self.header = b''

        if key:
            self.LMK = unhexlify(key)
        else:
            self.LMK = unhexlify('deafbeedeafbeedeafbeedeafbeedeaf')
        
        self.cipher = DES3.new(self.LMK, DES3.MODE_ECB)
        self.debug = debug
        self.skip_parity_check = skip_parity

    
    def info(self):
        """
        """
        dump = ''
        dump += 'LMK: {}\n'.format(raw2str(self.LMK))
        dump += 'Firmware version: {}\n'.format(self.firmware_version)
        if self.header:
            dump += 'Message header: {}\n'.format(self.header.decode('utf-8'))
        return dump


    def _debug_trace(self, data):
        """
        """
        if self.debug:
            print('\tDEBUG: {}\n'.format(data))


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
                        command_code, command_data = parse_message(data, header=self.header)
                        
                        if command_code == b'BU':
                            request = BU(command_data)
                        elif command_code == b'CA':
                            request = CA(command_data)
                        elif command_code == b'CY':
                            request = CY(command_data)
                        elif command_code == b'DC':
                            request = DC(command_data)
                        elif command_code == b'EC':
                            request = EC(command_data)
                        elif command_code == b'HC':
                            request = HC(command_data)
                        elif command_code == b'NC':
                            request = NC(command_data)
                        else:
                            request = None

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
                print('RUNTIME ERROR: {}\n'.format(sys.exc_info()[1]))
                print('Disconnected client: {}'.format(client_name))
                conn.close()
                continue

        self.sock.close()
        print('Exit')


    def _decrypt_pinblock(self, encrypted_pinblock, encrypted_terminal_key):
        """
        Decrypt pin block
        """
        if encrypted_terminal_key[0:1] in [b'U']:
            clear_terminal_key = self.cipher.decrypt(B2raw(encrypted_terminal_key[1:]))
        else:
            clear_terminal_key = self.cipher.decrypt(B2raw(encrypted_terminal_key))

        cipher = DES3.new(clear_terminal_key, DES3.MODE_ECB)
        decrypted_pinblock = cipher.decrypt(B2raw(encrypted_pinblock))
        return raw2B(decrypted_pinblock)


    def verify_cvv(self, request):
        """
        Get response to CY command
        """
        response =  OutgoingMessage(data=None, header=self.header)
        response.set_response_code('CZ')
        
        if not self.check_key_parity(request.get('CVK')):
            self._debug_trace('CVK parity error')
            response.set_error_code('10')
            return response

        CVK = request.get('CVK')
        if CVK[0:1] in [b'U']:
            CVK = CVK[1:]
        cvv = get_visa_cvv(request.get('Primary Account Number'), request.get('Expiration Date'), request.get('Service Code'), CVK)
        
        if str2bytes(cvv) == request.get('CVV'):
            response.set_error_code('00')
        else:
            self._debug_trace('CVV mismatch: {} != {}'.format(cvv, request.get('CVV').decode('utf-8')))
            response.set_error_code('01')
            
        return response


    def generate_key(self, request):
        """
        Get response to HC command
        TODO: generating keys for different schemes
        """
        response =  OutgoingMessage(data=None, header=self.header)
        response.set_response_code('HD')
        response.set_error_code('00')

        new_clear_key = modify_key_parity(bytes(os.urandom(16)))
        self._debug_trace('Generated key: {}'.format(raw2str(new_clear_key)))

        current_key = request.get('Current Key')
        if current_key[0:1] in [b'U']:
            current_key = current_key[1:]

        clear_current_key = self.cipher.decrypt(B2raw(current_key))
        curr_key_cipher = DES3.new(clear_current_key, DES3.MODE_ECB)

        new_key_under_current_key = curr_key_cipher.encrypt(new_clear_key)
        new_key_under_lmk = self.cipher.encrypt(new_clear_key)

        response.set('New key under the current key', b'U' + raw2B(new_key_under_current_key))
        response.set('New key under LMK', b'U' + raw2B(new_key_under_lmk))

        return response


    def check_key_parity(self, _key):
        """
        """
        if self.skip_parity_check:
            return True
        else:
            if _key[0:1] in [b'U']:
                key = _key[1:]
            else:
                key = _key
            return check_key_parity(self.cipher.decrypt(B2raw(key)))


    def verify_pin(self, request):
        """
        Get response to DC or EC command
        """
        response =  OutgoingMessage(data=None, header=self.header)
        command_code = request.get_command_code()

        if command_code == b'DC':            
            response.set_response_code('DD')
            key_type = 'TPK'
        elif command_code == b'EC':
            response.set_response_code('ED')
            key_type = 'ZPK'

        if not self.check_key_parity(request.get(key_type)):
            self._debug_trace(key_type + ' parity error')
            response.set_error_code('10')
            return response

        if not self.check_key_parity(request.get('PVK Pair')):
            self._debug_trace('PVK parity error')
            response.set_error_code('11')
            return response     

        if len(request.get('PVK Pair')) != 32:
            self._debug_trace('PVK not double length')
            response.set_error_code('27')
            return response

        decrypted_pinblock = self._decrypt_pinblock(request.get('PIN block'), request.get(key_type))
        self._debug_trace('Decrypted pinblock: {}'.format(decrypted_pinblock.decode('utf-8')))
        
        try:
            pin = get_clear_pin(decrypted_pinblock, request.get('Account Number'))
            pvv = get_visa_pvv(request.get('Account Number'), request.get('PVKI'), pin[:4], request.get('PVK Pair'))
            if pvv == request.get('PVV'):
                response.set_error_code('00')
            else:
                self._debug_trace('PVV mismatch: {} != {}'.format(pvv.decode('utf-8'), request.get('PVV').decode('utf-8')))
                response.set_error_code('01')

            return response

        except ValueError as err:
            self._debug_trace(err)
            response.set_error_code('01')
            return response


    def translate_pinblock(self, request):
        """
        Get response to CA command (Translate PIN from TPK to ZPK)
        """
        response = OutgoingMessage(header=self.header)
        response.set_response_code('CB')
        pinblock_format = request.get('Destination PIN block format')

        if request.get('Destination PIN block format') != request.get('Source PIN block format'):
            raise ValueError('Cannot translate PIN block from format {} to format {}'.format(request.get('Source PIN block format').decode('utf-8'), request.get('Destination PIN block format').decode('utf-8')))

        if request.get('Source PIN block format') != b'01':
            raise ValueError('Unsupported PIN block format: {}'.format(request.get('Source PIN block format').decode('utf-8')))

        # Source key parity check
        if not self.check_key_parity(request.get('TPK')):
            self._debug_trace('Source TPK parity error')
            response.set_error_code('10')
            return response

        # Destination key parity check
        if not self.check_key_parity(request.get('Destination Key')):
            self._debug_trace('Destination ZPK parity error')
            response.set_error_code('11')
            return response

        decrypted_pinblock = self._decrypt_pinblock(request.get('Source PIN block'), request.get('TPK'))
        self._debug_trace('Decrypted pinblock: {}'.format(decrypted_pinblock.decode('utf-8')))
        
        pin_length = decrypted_pinblock[0:2]

        destination_key = request.get('Destination Key')
        if destination_key[0:1] in [b'U']:
            destination_key = destination_key[1:]
        cipher = DES3.new(B2raw(destination_key), DES3.MODE_ECB)
        translated_pin_block = cipher.encrypt(B2raw(decrypted_pinblock))

        response.set_error_code('00')
        response.set('PIN Length', decrypted_pinblock[0:2])
        response.set('Destination PIN Block', raw2B(translated_pin_block))
        response.set('Destination PIN Block format', pinblock_format)

        return response


    def get_diagnostics_data(self):
        """
        Get response to NC command
        """
        response = OutgoingMessage(header=self.header)
        response.set_response_code('ND')
        response.set_error_code('00')
        response.set('LMK Check Value', key_CV(raw2B(self.LMK), 16))
        response.set('Firmware Version', str2bytes(self.firmware_version))
        return response


    def get_key_check_value(self, request):
        """
        Get response to BU command
        TODO: return different check values (length of 6 or length of 16)
        """
        response = OutgoingMessage(header=self.header)
        response.set_response_code('BV')
        response.set_error_code('00')
        
        key = request.get('Key')
        if key[0:1] in [b'U']:
            key = key[1:]
        response.set('Key Check Value', key_CV(key, 16))
        return response


    def get_response(self, request):
        """
        """
        rqst_command_code = request.get_command_code()
        if rqst_command_code == b'BU':
            return self.get_key_check_value(request)
        elif rqst_command_code == b'NC':
            return self.get_diagnostics_data()
        elif rqst_command_code in [b'DC', b'EC']:
            return self.verify_pin(request)
        elif rqst_command_code == b'CA':
            return self.translate_pinblock(request)
        elif rqst_command_code == b'CY':
            return self.verify_cvv(request)
        elif rqst_command_code == b'HC':
            return self.generate_key(request)
        else:
            response = OutgoingMessage(header=self.header)
            response.set_response_code('ZZ')
            response.set_error_code('00')
            return response
