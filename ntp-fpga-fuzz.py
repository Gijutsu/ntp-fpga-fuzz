#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# This is a quick and dirty start at fuzzying the FPGA implementation of NTP
# as seen at https://github.com/Netnod/FPGA_NTP_SERVER
# Some of the parsing done by ntplib is not compatible with the packet received
# by Scapy (or is just broken) and therefore in some tests we have to mix parsers.
# Most of the tests, or the idea behind which ones are important, are based on
# code made by Rolf Andersson and Ragnar Sundblad.

import time
import unittest
import ntplib
from scapy.all import *

class TestNTPLib(unittest.TestCase):

    NTP_SERVER = ""
    """test NTP server"""

    POLL_DELAY = 0.5
    """delay between NTP polls, in seconds"""

    def test_request(self):

        # This is bad practice and should be converted
        # from using unittest to e.g. plain asserts.
        while True:
            t1 = time.time()
            ntp_response = ntplib.NTPStats()

            scapy_response = None
            while scapy_response == None:
                scapy_response = sr1(IP(dst=self.NTP_SERVER)/UDP()/fuzz(NTP(version=4)), timeout=0.5)
            
            # build the destination timestamp as seen in ntplib
            ntp_response.dest_timestamp = ntplib.system_to_ntp_time(time.time())
            
            ntp_response.from_data(bytes(scapy_response))
            t2 = time.time()

            # check response
            self.assertTrue(isinstance(ntp_response, ntplib.NTPStats))

            # We use version 4 when sending and expect the same version back
            self.assertEqual(scapy_response[0][NTP].version, 4)

            self.assertTrue(isinstance(ntp_response.offset, float))
            self.assertEqual(scapy_response[0][NTP].stratum, 1)
            self.assertTrue(-0x7f <= ntp_response.precision < 0x7f)
            self.assertTrue(isinstance(ntp_response.root_delay, float))
            self.assertTrue(isinstance(ntp_response.root_dispersion, float))
            self.assertTrue(isinstance(ntp_response.delay, float))
            self.assertTrue(isinstance(ntp_response.leap, int))
            self.assertIn(ntp_response.leap, ntplib.NTP.LEAP_TABLE)
            self.assertTrue(0 <= ntp_response.poll < 0xfff)
            self.assertTrue(isinstance(ntp_response.mode, int))

            # The FPGA should only respond with mode 4
            self.assertEqual(scapy_response[0][NTP].mode, 4)

            self.assertTrue(0 <= ntp_response.ref_id < 0xffffffff)
            self.assertTrue(isinstance(ntp_response.tx_time, float))
            self.assertTrue(isinstance(ntp_response.ref_time, float))
            self.assertTrue(isinstance(ntp_response.orig_time, float))
            self.assertTrue(isinstance(ntp_response.recv_time, float))
            self.assertTrue(isinstance(ntp_response.dest_time, float))

            time.sleep(self.POLL_DELAY)

            new_scapy_response = sr1(IP(dst=self.NTP_SERVER)/UDP()/NTP(version=4))

            new_dest_timestamp = ntplib.system_to_ntp_time(time.time())

            new_ntp_response = ntplib.NTPStats()
            new_ntp_response.dest_timestamp = new_dest_timestamp
            new_ntp_response.from_data(bytes(new_scapy_response))

            # ntplib parsing of these fields are broken so we use Scapy here as well
            self.assertTrue(t1 < ntplib.ntp_to_system_time(scapy_response[0][NTP].orig) < ntp_response.dest_time < t2)
            self.assertTrue(ntplib.ntp_to_system_time(scapy_response[0][NTP].orig) < ntplib.ntp_to_system_time(new_scapy_response[0][NTP].orig))
            self.assertTrue(ntplib.ntp_to_system_time(scapy_response[0][NTP].recv) < ntplib.ntp_to_system_time(new_scapy_response[0][NTP].recv))
            self.assertTrue(ntplib.ntp_to_system_time(scapy_response[0][NTP].sent) < ntplib.ntp_to_system_time(new_scapy_response[0][NTP].sent))
            self.assertTrue(ntp_response.dest_time < new_ntp_response.dest_time)

if __name__ == '__main__':
    unittest.main()

