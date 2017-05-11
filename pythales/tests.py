#!/usr/bin/env python

import unittest

from pythales.hsm import HSM, Message

class TestMessageClass(unittest.TestCase):
    def test_get_length(self):
        m = Message(b'\x00\x06SSSS00')
        self.assertEqual(m.get_length(), 6)

    def test_get_length_incorrect(self):
        with self.assertRaisesRegex(ValueError, 'Expected message of length 6 but actual received message length is 2'):
            m = Message(b'\x00\x0600')
            self.assertEqual(m.get_length(), 6)

"""
class TestHSM(unittest.TestCase):
    def setUp(self):
        self.hsm = HSM(header='SSSS')

    def test_message_header(self):
        self.assertEqual(self.hsm.header, b'SSSS')

    NC 
    def test_NC(self):
        request = b'NC'
        self.assertEqual(self.hsm.get_response(request), b'ND00')
"""

if __name__ == '__main__':
    unittest.main()