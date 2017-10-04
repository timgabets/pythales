#!/usr/bin/env python

import unittest

from pythales.hsm import HSM, OutgoingMessage, DummyMessage, A0, BU, CA, CW, CY, DC, EC, HC, NC, parse_message


class TestDummyMessage(unittest.TestCase):
    """
    """
    def setUp(self):
        self.message = DummyMessage(b'')

    def test_dummy_message_trace_empty(self):
        self.assertEqual(self.message.trace(), '')
    
    def test_dummy_message_get_non_existent_field(self):
        self.assertEqual(self.message.get('IDDQD'), None)

    def test_dummy_message_set(self):
        self.message.set('IDDQD', b'00')
        self.assertEqual(self.message.get('IDDQD'), b'00')

    def test_dummy_trace(self):
        self.message.set('IDDQD', b'00')
        self.assertEqual(self.message.trace(), '\t[IDDQD]: [00]\n')

class TestParseMessage(unittest.TestCase):
    """
    """
    def test_parse_message_none(self):
        self.assertEqual(parse_message(None), None)

    def test_get_length_incorrect(self):
        with self.assertRaisesRegex(ValueError, 'Expected message of length 6 but actual received message length is 2'):
            parse_message(b'\x00\x0600')

    def test_invalid_message_header(self):
        data = b'\x00\x06SSSS00'
        header = b'XDXD'
        with self.assertRaisesRegex(ValueError, 'Invalid header'):
            parse_message(data, header)

    def test_parse_message_command_code_and_data(self):
        parsed = parse_message(b'\x00\x07HDRDCXX', b'HDR')
        self.assertEqual(parsed[0], b'DC')    
        self.assertEqual(parsed[1], b'XX')    


class TestOutgoingMessageClass(unittest.TestCase):
    """
    """
    def test_outgoing_message(self):
        m = OutgoingMessage(header=b'XXXX')
        m.fields['Command Code'] = b'NG'
        m.fields['Response Code'] = b'00'
        m.fields['Data'] = b'7444321'
        self.assertEqual(m.build(), b'\x00\x0FXXXXNG007444321')


    def test_outgoing_message_no_header(self):
        m = OutgoingMessage(header=None)
        m.fields['Command Code'] = b'NG'
        m.fields['Response Code'] = b'00'
        m.fields['Data'] = b'7444321'
        self.assertEqual(m.build(), b'\x00\x0BNG007444321')


class TestMessageGet(unittest.TestCase):
    def setUp(self):
        self.m = OutgoingMessage(header=None)
        self.m.fields['Command Code'] = b'NG'
        self.m.fields['Response Code'] = b'00'
        self.m.fields['Data'] = b'7444321'

    def test_get_empty(self):
        self.assertEqual(self.m.get(''), None)

    def test_get_none(self):
        self.assertEqual(self.m.get(None), None)

    def test_get_command_code(self):
        self.assertEqual(self.m.get('Command Code'), b'NG')

class TestA0(unittest.TestCase):
    """
    DC command received:
    00 2f 53 53 53 53 41 30 31 37 30 44 55 3b 31 55         ./SSSSA0170DU;1U
    34 45 45 32 34 39 42 37 43 30 44 38 34 32 39 36         4EE249B7C0D84296
    30 37 32 38 44 46 31 42 32 45 43 38 37 30 31 45         0728DF1B2EC8701E
    58                                                      X
    """
    def setUp(self):
        data = b'170DU;1U4EE249B7C0D842960728DF1B2EC8701EX'
        self.a0 = A0(data)

    def test_mode_parsed(self):
        self.assertEqual(self.a0.fields['Mode'], b'1')

    def test_key_type_parsed(self):
        self.assertEqual(self.a0.fields['Key Type'], b'70D')

    def test_key_scheme_parsed(self):
        self.assertEqual(self.a0.fields['Key Scheme'], b'U')
    
    def test_zmk_tpk_flag_parsed(self):
        self.assertEqual(self.a0.fields['ZMK/TMK Flag'], b'1')

    def test_zmk_tpk_flag_parsed(self):
        self.assertEqual(self.a0.fields['ZMK/TMK'], b'U4EE249B7C0D842960728DF1B2EC8701E')


class TestDC(unittest.TestCase):
    """
    DC command received:
    00 6a 53 53 53 53 44 43 55 44 45 41 44 42 45 45         .jSSSSDCUDEADBEE
    46 44 45 41 44 42 45 45 46 44 45 41 44 42 45 45         FDEADBEEFDEADBEE
    46 44 45 41 44 42 45 45 46 31 32 33 34 35 36 37         FDEADBEEF1234567
    38 39 30 41 42 43 44 45 46 31 32 33 34 35 36 37         890ABCDEF1234567
    38 39 30 41 42 43 44 45 46 32 42 36 38 37 41 45         890ABCDEF2B687AE
    46 43 33 34 42 31 41 38 39 30 31 30 30 31 31 32         FC34B1A890100112
    33 34 35 36 37 38 39 31 38 37 32 33                     345678918723
    """
    def setUp(self):
        data = b'UDEADBEEFDEADBEEFDEADBEEFDEADBEEF1234567890ABCDEF1234567890ABCDEF2B687AEFC34B1A890100112345678918723'
        self.dc = DC(data)
        
    def test_tpk_parsed(self):
        self.assertEqual(self.dc.fields['TPK'], b'UDEADBEEFDEADBEEFDEADBEEFDEADBEEF')

    def test_pvk_parsed(self):
        self.assertEqual(self.dc.fields['PVK Pair'], b'1234567890ABCDEF1234567890ABCDEF')

    def test_pinblock_parsed(self):
        self.assertEqual(self.dc.fields['PIN block'], b'2B687AEFC34B1A89')

    def test_pinblock_format_code_parsed(self):
        self.assertEqual(self.dc.fields['PIN block format code'], b'01')

    def test_account_number_parsed(self):
        self.assertEqual(self.dc.fields['Account Number'], b'001123456789')

    def test_pvki_parsed(self):
        self.assertEqual(self.dc.fields['PVKI'], b'1')

    def test_pvv_parsed(self):
        self.assertEqual(self.dc.fields['PVV'], b'8723')

    def test_DC_desciprion(self):
        self.assertEqual(self.dc.description, 'Verify PIN')


class TestCA(unittest.TestCase):
    """
    18:47:19.371109 << 108 bytes received from 192.168.56.101:33284: 
        00 6a 53 53 53 53 43 41 55 45 44 34 41 33 35 44         .jSSSSCAUED4A35D
        35 32 43 39 30 36 33 41 31 45 44 34 41 33 35 44         52C9063A1ED4A35D
        35 32 43 39 30 36 33 41 31 55 44 33 39 44 33 39         52C9063A1UD39D39
        45 42 37 43 39 33 32 43 46 33 36 37 43 39 37 43         EB7C932CF367C97C
        35 42 31 30 42 32 43 31 39 35 31 32 37 44 46 33         5B10B2C195127DF3
        36 36 42 38 36 41 45 32 44 39 41 37 30 31 30 33         66B86AE2D9A70103
        35 35 32 30 30 30 30 30 30 30 31 32                     552000000012
    """
    def setUp(self):
        data = b'UED4A35D52C9063A1ED4A35D52C9063A1UD39D39EB7C932CF367C97C5B10B2C195127DF366B86AE2D9A70103552000000012'
        self.ca = CA(data)

    def test_tpk_parsed(self):
        self.assertEqual(self.ca.fields['TPK'], b'UED4A35D52C9063A1ED4A35D52C9063A1')

    def test_dest_key_parsed(self):
        self.assertEqual(self.ca.fields['Destination Key'], b'UD39D39EB7C932CF367C97C5B10B2C195')

    def test_max_pin_length_parsed(self):
        self.assertEqual(self.ca.fields['Maximum PIN Length'], b'12')

    def test_source_pin_block_parsed(self):
        self.assertEqual(self.ca.fields['Source PIN block'], b'7DF366B86AE2D9A7')

    def test_source_pin_block_format_parsed(self):
        self.assertEqual(self.ca.fields['Source PIN block format'], b'01')

    def test_dest_pin_block_format_parsed(self):
        self.assertEqual(self.ca.fields['Destination PIN block format'], b'03')

    def test_account_number_parsed(self):
        self.assertEqual(self.ca.fields['Account Number'], b'552000000012')


class TestCW(unittest.TestCase):
    """
    00 3f 53 53 53 53 43 57 55 31 43 31 45 42 31 30         .?SSSSCWU1C1EB10
    39 30 36 38 31 43 43 39 45 36 30 30 33 45 30 35         90681CC9E6003E05
    32 31 37 43 37 30 37 37 45 34 35 37 35 32 37 32         217C7077E4575272
    32 32 32 35 36 37 31 32 32 3b 32 30 31 30 30 30         222567122;201000
    30                                                      0
    """
    def setUp(self):
        data = b'U1C1EB1090681CC9E6003E05217C7077E4575272222567122;2010000'
        self.cy = CW(data)

    def test_cvk_parsed(self):
        self.assertEqual(self.cy.fields['CVK'], b'U1C1EB1090681CC9E6003E05217C7077E')

    def test_account_number_parsed(self):
        self.assertEqual(self.cy.fields['Primary Account Number'], b'4575272222567122')

    def test_expiry_date_parsed(self):
        self.assertEqual(self.cy.fields['Expiration Date'], b'2010')

    def test_service_code_parsed(self):
        self.assertEqual(self.cy.fields['Service Code'], b'000')


class TestCY(unittest.TestCase):
    """
    00 42 53 53 53 53 43 59 55 34 34 39 44 46 31 36         .BSSSSCYU449DF16
    37 39 46 34 41 34 45 30 36 39 35 45 39 39 44 39         79F4A4E0695E99D9
    32 31 41 32 35 33 44 43 42 30 30 30 38 39 39 30         21A253DCB0008990
    30 31 31 32 33 34 35 36 37 38 39 30 3b 31 38 30         011234567890;180
    39 32 30 31                                             9201

    """
    def setUp(self):
        data = b'U449DF1679F4A4E0695E99D921A253DCB0008990011234567890;1809201'
        self.cy = CY(data)

    def test_cvk_parsed(self):
        self.assertEqual(self.cy.fields['CVK'], b'U449DF1679F4A4E0695E99D921A253DCB')

    def test_cvv_parsed(self):
        self.assertEqual(self.cy.fields['CVV'], b'000')

    def test_account_number_parsed(self):
        self.assertEqual(self.cy.fields['Primary Account Number'], b'8990011234567890')

    def test_expiry_date_parsed(self):
        self.assertEqual(self.cy.fields['Expiration Date'], b'1809')

    def test_service_code_parsed(self):
        self.assertEqual(self.cy.fields['Service Code'], b'201')

class TestECAccountNumber(unittest.TestCase):
    """
    00 6a 53 53 53 53 45 43 55 41 45 37 39 44 32 30         .jSSSSECUAE79D20
    33 46 39 36 34 30 41 39 33 43 46 42 41 31 35 35         3F9640A93CFBA155
    45 33 34 35 39 35 33 46 36 37 33 33 36 44 35 30         E345953F67336D50
    43 34 37 31 32 38 44 37 31 30 44 46 34 35 30 42         C47128D710DF450B
    43 42 32 43 36 34 36 31 42 43 33 32 46 31 30 34         CB2C6461BC32F104
    41 36 38 34 36 42 44 38 37 30 31 34 30 37 30 30         A6846BD870140700
    30 30 30 30 30 31 30 31 32 33 34 35                     000001012345

    """
    def setUp(self):
        data = b'UAE79D203F9640A93CFBA155E345953F67336D50C47128D710DF450BCB2C6461BC32F104A6846BD870140700000001012345'
        self.ec = EC(data)

    def test_zpk_parsed(self):
        self.assertEqual(self.ec.fields['ZPK'], b'UAE79D203F9640A93CFBA155E345953F6')
        
    def test_pvk_pair_parsed(self):
        self.assertEqual(self.ec.fields['PVK Pair'], b'7336D50C47128D710DF450BCB2C6461B')

    def test_pin_block_parsed(self):
        self.assertEqual(self.ec.fields['PIN block'], b'C32F104A6846BD87')

    def test_pin_block_format_code_parsed(self):
        self.assertEqual(self.ec.fields['PIN block format code'], b'01')

    def test_pan_parsed(self):
        self.assertEqual(self.ec.fields['Account Number'], b'407000000010')

    def test_pvki_parsed(self):
        self.assertEqual(self.ec.fields['PVKI'], b'1')

    def test_pvv_parsed(self):
        self.assertEqual(self.ec.fields['PVV'], b'2345')

class TestECToken(unittest.TestCase):
    """
    """
    def setUp(self):
        data = b'UAE79D203F9640A93CFBA155E345953F67336D50C47128D710DF450BCB2C6461BC32F104A6846BD8704xxxxxxxxxxxxzzzzzz12345'
        self.ec = EC(data)

    def test_zpk_parsed(self):
        self.assertEqual(self.ec.fields['ZPK'], b'UAE79D203F9640A93CFBA155E345953F6')
        
    def test_pvk_pair_parsed(self):
        self.assertEqual(self.ec.fields['PVK Pair'], b'7336D50C47128D710DF450BCB2C6461B')

    def test_pin_block_parsed(self):
        self.assertEqual(self.ec.fields['PIN block'], b'C32F104A6846BD87')

    def test_pin_block_format_code_parsed(self):
        self.assertEqual(self.ec.fields['PIN block format code'], b'04')

    def test_pan_parsed(self):
        self.assertEqual(self.ec.fields['Token'], b'xxxxxxxxxxxxzzzzzz')

    def test_pvki_parsed(self):
        self.assertEqual(self.ec.fields['PVKI'], b'1')

    def test_pvv_parsed(self):
        self.assertEqual(self.ec.fields['PVV'], b'2345')


class TestHC(unittest.TestCase):
    """
    16:48:04.000521 << 45 bytes received from 192.168.56.101:42292: 
    00 2b 53 53 53 53 48 43 55 31 32 33 34 35 36 37         .+SSSSHCU1234567
    38 39 30 41 42 43 44 45 46 31 32 33 34 35 36 37         890ABCDEF1234567
    38 39 30 41 42 43 44 45 46 3b 58 55 31                  890ABCDEF;XU1

    """
    def setUp(self):
        data = b'U1234567890ABCDEF1234567890ABCDEF;XU1'
        self.hc = HC(data)

    def test_current_key_parsed(self):
        self.assertEqual(self.hc.fields['Current Key'], b'U1234567890ABCDEF1234567890ABCDEF')


class TestBU(unittest.TestCase):
    """
    16:53:16.560494 << 44 bytes received from 192.168.56.101:42364: 
    00 2a 53 53 53 53 42 55 30 32 31 55 41 39 37 38         .*SSSSBU021UA978
    33 31 38 36 32 45 33 31 43 43 43 33 36 45 38 35         31862E31CCC36E85
    34 46 45 31 38 34 45 45 36 34 35 33                     4FE184EE6453
    """
    def setUp(self):
        data = b'021UA97831862E31CCC36E854FE184EE6453'
        self.bu = BU(data)

    def test_key_type_code_parsed(self):
        self.assertEqual(self.bu.fields['Key Type Code'], b'02')

    def test_key_length_flag_parsed(self):
        self.assertEqual(self.bu.fields['Key Length Flag'], b'1')

    def test_key_parsed(self):
        self.assertEqual(self.bu.fields['Key'], b'UA97831862E31CCC36E854FE184EE6453')



class TestHSMThread(unittest.TestCase):
    def setUp(self):
        self.hsm = HSM(header='SSSS', skip_parity=True)

    def test_decrypt_pinblock(self):
        self.assertEqual(self.hsm._decrypt_pinblock(b'2B687AEFC34B1A89', b'UDEADBEEFDEADBEEFDEADBEEFDEADBEEF'), b'2AD242FBD61291DB')

    """
    hsm.translate_pinblock()
    """
    def test_translate_pinblock_different_pinblock_formats(self):
        data = b'UED4A35D52C9063A1ED4A35D52C9063A1UD39D39EB7C932CF367C97C5B10B2C195127DF366B86AE2D9A70103552000000012'
        self.ca = CA(data)
        with self.assertRaisesRegex(ValueError, 'Cannot translate PIN block from format 01 to format 03'):
            self.hsm.translate_pinblock(self.ca)

    def test_translate_pinblock_unsupported_format(self):
        data = b'UED4A35D52C9063A1ED4A35D52C9063A1UD39D39EB7C932CF367C97C5B10B2C195127DF366B86AE2D9A70303552000000012'
        self.ca = CA(data)
        with self.assertRaisesRegex(ValueError, 'Unsupported PIN block format: 03'):
            self.hsm.translate_pinblock(self.ca)  

    """
    User-defined key
    """
    def test_user_defined_key_wrong_key_size(self):
        with self.assertRaises(ValueError):
            self.hsm = HSM(key='DEADBEAF')

    def test_user_defined_key_value(self):
        with self.assertRaises(ValueError):
            self.hsm = HSM(key='iddqdeef deadbeef deadbeef deadbeef')

    """
    verify_pin()
    """
    def test_verify_pin_EC(self):
        """
        00 6a 53 53 53 53 45 43 55 38 32 37 45 36 37 42         .jSSSSECU827E67B
        35 39 41 31 44 36 42 38 46 38 32 37 45 36 37 42         59A1D6B8F827E67B
        35 39 41 31 44 36 42 38 46 37 33 33 36 44 35 30         59A1D6B8F7336D50
        43 34 37 31 32 38 44 37 31 30 44 46 34 35 30 42         C47128D710DF450B
        43 42 32 43 36 34 36 31 42 43 33 32 46 31 30 34         CB2C6461BC32F104
        41 36 38 34 36 42 44 38 37 30 31 34 30 37 30 30         A6846BD870140700
        30 30 30 30 30 31 30 31 33 38 34 33                     000001013843
        
        [ZPK                  ]: [U827E67B59A1D6B8F827E67B59A1D6B8F]
        [PVK Pair             ]: [7336D50C47128D710DF450BCB2C6461B]
        [PIN block            ]: [C32F104A6846BD87]
        [PIN block format code]: [01]
        [Account Number       ]: [407000000010]
        [PVKI                 ]: [1]
        [PVV                  ]: [3843]
        """
        data = b'U827E67B59A1D6B8F827E67B59A1D6B8F7336D50C47128D710DF450BCB2C6461BC32F104A6846BD870140700000001013843'
        request = EC(data)
        response = self.hsm.verify_pin(request)
        self.assertEqual(response.get('Response Code'), b'ED')
        self.assertEqual(response.get('Error Code'), b'00')


    def test_verify_pin_DC(self):
        """
        """
        data = b'U827E67B59A1D6B8F827E67B59A1D6B8F7336D50C47128D710DF450BCB2C6461BC32F104A6846BD870140700000001013843'
        request = DC(data)
        response = self.hsm.verify_pin(request)
        self.assertEqual(response.get('Response Code'), b'DD')
        self.assertEqual(response.get('Error Code'), b'00')

    """
    verify_cvv()
    """
    def test_verify_cvv_proper_response_code(self):
        """
        00 42 53 53 53 53 43 59 55 31 43 31 45 42 31 30         .BSSSSCYU1C1EB10
        39 30 36 38 31 43 43 39 45 36 30 30 33 45 30 35         90681CC9E6003E05
        32 31 37 43 37 30 37 37 45 36 34 30 34 31 37 34         217C7077E6404174
        30 37 30 30 30 30 30 30 30 31 30 34 3b 31 37 31         070000000104;171
        32 32 30 31                                             2201
        """
        data = b'U1C1EB1090681CC9E6003E05217C7077E6404174070000000104;1712201'
        request = CY(data)
        response = self.hsm.verify_cvv(request)
        self.assertEqual(response.get('Response Code'), b'CZ')

        """
    generate_cvv()
    """
    def test_generate_cvv_proper_response_code(self):
        """
        00 3f 53 53 53 53 43 57 55 31 43 31 45 42 31 30         .?SSSSCWU1C1EB10
        39 30 36 38 31 43 43 39 45 36 30 30 33 45 30 35         90681CC9E6003E05
        32 31 37 43 37 30 37 37 45 34 35 37 35 32 37 32         217C7077E4575272
        32 32 32 35 36 37 31 32 32 3b 32 30 31 30 30 30         222567122;201000
        30                                                      0
        """
        data = b'U1C1EB1090681CC9E6003E05217C7077E4575272222567122;2010000'
        request = CW(data)
        response = self.hsm.generate_cvv(request)
        self.assertEqual(response.get('Response Code'), b'CX')
        self.assertEqual(response.get('Error Code'), b'00')
        self.assertEqual(response.get('CVV'), b'670')

    """
    generate_key()
    """
    def test_generate_key_proper_response_code(self):
        """
        """
        data = b'U1234567890ABCDEF1234567890ABCDEF;XU1'
        request = HC(data)
        response = self.hsm.generate_key(request)
        self.assertEqual(response.get('Response Code'), b'HD')
        self.assertEqual(response.get('Error Code'), b'00')

    """
    generate_key_a0()
    """
    def test_generate_key_a0_proper_response_code(self):
        """
        """
        data = b'0002U'
        request = A0(data)
        response = self.hsm.generate_key_a0(request)
        self.assertEqual(response.get('Response Code'), b'A1')
        self.assertEqual(response.get('Error Code'), b'00')

    def test_generate_key_a0_proper_response_code(self):
        """
        """
        data = b'170DU;1U4EE249B7C0D842960728DF1B2EC8701EX'
        request = A0(data)
        response = self.hsm.generate_key_a0(request)
        self.assertEqual(response.get('Response Code'), b'A1')
        self.assertEqual(response.get('Error Code'), b'00')
        self.assertEqual(response.get('Key under ZMK')[0], 85) # b'U'
        self.assertEqual(len(response.get('Key under ZMK')), 33)
        self.assertEqual(len(response.get('Key Check Value')), 6)


class TestHSMResponsesMapping(unittest.TestCase):
    def setUp(self):
        self.hsm = HSM(header='SSSS', skip_parity=True)

    def test_ZZ_response(self):
        response = self.hsm.get_response(DummyMessage(b''))
        self.assertEqual(response.get('Response Code'), b'ZZ')

    def test_BU_response(self):
        data = b'021UA97831862E31CCC36E854FE184EE6453'
        response = self.hsm.get_response(BU(data))
        self.assertEqual(response.get('Response Code'), b'BV')


    def test_DC_response(self):
        data = b'UDEADBEEFDEADBEEFDEADBEEFDEADBEEF1234567890ABCDEF1234567890ABCDEF2B687AEFC34B1A890100112345678918723'        
        response = self.hsm.get_response(DC(data))
        self.assertEqual(response.get('Response Code'), b'DD')


    def test_CA_response(self):
        data = b'UED4A35D52C9063A1ED4A35D52C9063A1UD39D39EB7C932CF367C97C5B10B2C195127DF366B86AE2D9A70101552000000012'
        response = self.hsm.get_response(CA(data))
        self.assertEqual(response.get('Response Code'), b'CB')

    def test_CY_response(self):
        data = b'U449DF1679F4A4E0695E99D921A253DCB0008990011234567890;1809201'
        response = self.hsm.get_response(CY(data))
        self.assertEqual(response.get('Response Code'), b'CZ')


    def test_HC_response(self):
        data = b'U1234567890ABCDEF1234567890ABCDEF;XU1'
        response = self.hsm.get_response(HC(data))
        self.assertEqual(response.get('Response Code'), b'HD')


    def test_NC_response(self):
        response = self.hsm.get_response(NC(b''))
        self.assertEqual(response.get('Response Code'), b'ND')
        self.assertEqual(response.get('Error Code'), b'00')

if __name__ == '__main__':
    unittest.main()