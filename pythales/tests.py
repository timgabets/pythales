#!/usr/bin/env python

import unittest

from pythales.hsm import HSM, Message, DC

class TestMessageClass(unittest.TestCase):
    """
    """
    def test_get_length(self):
        m = Message(b'\x00\x06SSSS00')
        self.assertEqual(m.get_length(), 6)


    def test_get_length_incorrect(self):
        with self.assertRaisesRegex(ValueError, 'Expected message of length 6 but actual received message length is 2'):
            m = Message(b'\x00\x0600')
            self.assertEqual(m.get_length(), 6)


    def test_invalid_message_header(self):
        data = b'\x00\x06SSSS00'
        header = b'XDXD'
        with self.assertRaisesRegex(ValueError, 'Invalid header'):
            m = Message(data, header)


    def test_valid_message_header(self):
        data = b'\x00\x07IDDQD77'
        header = b'IDDQD'
        self.assertTrue(Message(data, header))


    def test_get_data(self):
        data = b'\x00\x07HDRDATA'
        header = b'HDR'
        m = Message(data, header)
        self.assertEqual(m.get_data(), b'DATA')


    def test_get_command_code(self):
        data = b'\x00\x07HDRDCXX'
        header = b'HDR'
        m = Message(data, header)
        self.assertEqual(m.get_command_code(), b'DC')    


    def test_outgoing_message(self):
        m = Message(data=None, header=b'XXXX')
        self.assertEqual(m.build('NG007444321'), b'\x00\x0FXXXXNG007444321')


    def test_outgoing_message_no_header(self):
        m = Message(data=None, header=None)
        self.assertEqual(m.build('NG007444321'), b'\x00\x0BNG007444321')


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
        self.hsm = HSM(header='SSSS')
        
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


class TestHSM(unittest.TestCase):
    def setUp(self):
        self.hsm = HSM(header='SSSS')

    def test_decrypt_pinblock(self):
        self.assertEqual(self.hsm._decrypt_pinblock(b'2B687AEFC34B1A89', b'UDEADBEEFDEADBEEFDEADBEEFDEADBEEF'), b'D694D2659AD26C2E')

    def test_get_clear_pin_1234(self):
        self.assertEqual(self.hsm._get_clear_pin(b'0412BCEEDCBA9876', b'881123456789'), b'1234')

    def test_get_clear_pin_non_numeric(self):
        with self.assertRaisesRegex(ValueError, 'PIN contains non-numeric characters'):
            self.hsm._get_clear_pin(b'041267EEDCBA9876', b'881123456789')

    def test_get_clear_pin_pin_length_9(self):
        with self.assertRaisesRegex(ValueError, 'Incorrect PIN length: 9'):
            self.hsm._get_clear_pin(b'091267EEDCBA9876', b'881123456789')

    def test_get_clear_pin_improper_length(self):
        with self.assertRaisesRegex(ValueError, 'Incorrect PIN length: 223'):
            self.hsm._get_clear_pin(b'DF1267EEDCBA9876', b'881123456789')

    """
    hsm._get_pvv_digits_from_string()
    """
    def test_get_pvv_digits_from_string(self):
        self.assertEqual(self.hsm._get_pvv_digits_from_string('59EF34AD722C0556F7F6FBD4A76D38E6'), '5934')

    def test_get_pvv_digits_from_mixed_string(self):
        self.assertEqual(self.hsm._get_pvv_digits_from_string('EEFADCFFFBD7ADECAB9FBB'), '7944')

    def test_get_pvv_digits_from_string_letters_only(self):
        self.assertEqual(self.hsm._get_pvv_digits_from_string('EFADCFFFBDADECABFBB'), '4503')

    """
    hsm._get_visa_pvv()
    """
    def test_get_visa_pvv(self):
        self.assertEqual(self.hsm._get_visa_pvv(b'4761260000000134', b'1', b'1234', b'DEADDEADDEADDEADBEAFBEAFBEAFBEAF'), b'8289')

    def test_get_visa_pvv_incorrect_key(self):
        with self.assertRaisesRegex(ValueError, 'Incorrect key length'):
            self.hsm._get_visa_pvv(b'4761260000000134', b'1', b'1234', b'DEADDEADDEADDEADBEAFBEAFBEAF')

    """
    User-defined key
    """
    def test_user_defined_key_wrong_key_size(self):
        with self.assertRaises(ValueError):
            self.hsm = HSM(key='DEADBEAF')

    def test_user_defined_key_value(self):
        with self.assertRaises(ValueError):
            self.hsm = HSM(key='iddqdeef deadbeef deadbeef deadbeef')

if __name__ == '__main__':
    unittest.main()