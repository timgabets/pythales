#!/usr/bin/env python

import unittest

from pythales.hsm import HSM

class TestHSM(unittest.TestCase):
    def setUp(self):
        self.hsm = HSM()

    def test_message_header(self):
        self.hsm = HSM(header='IDDQD')
        self.assertEqual(self.hsm.header, 'IDDQD')

    """
    NC 
    def test_NC(self):
        self.assertEqual(self.trxn.set_expected_action('approve'), True)
        self.assertEqual(self.trxn.expected_response_action, 'APPROVE')
    """


if __name__ == '__main__':
    unittest.main()