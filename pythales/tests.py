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


    def test_outgoing_message(self):
        m = Message(data=None, header=b'XXXX')
        self.assertEqual(m.build(b'NG007444321'), b'\x00\x0FXXXXNG007444321')


    def test_outgoing_message_no_header(self):
        m = Message(data=None, header=None)
        self.assertEqual(m.build(b'NG007444321'), b'\x00\x0BNG007444321')


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
        
    def test_key_scheme_U(self):
        self.assertEqual(self.dc.get_key_scheme(), 85)


class TestHSM(unittest.TestCase):
    def setUp(self):
        self.hsm = HSM(header='SSSS')

    """
    NC 
    """
    def test_NC(self):
        self.assertEqual(self.hsm.get_response(b'NC'), b'ND001234567890ABCDEF0007-E000')

if __name__ == '__main__':
    unittest.main()