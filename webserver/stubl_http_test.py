#!/usr/bin/python
# Copyright 2008 Google Inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

"""Unittests for Basic HTTP server for generating tunnel instructions."""

__author__ = "ek@google.com (Erik Kline)"


import socket
from StringIO import StringIO
import struct
import unittest

import stubl_http as http


# Inject a fake config file for tests to use.
fake_config = """
PREFIX="2001:db8:1:2"
KEY="746869735f69735f7468655f6b6579"
SERVER_IPV4="0.1.2.3"
SUBNETS="172.16.0.0/12"
"""
http.config = http.ConfigFileParser(StringIO(fake_config))


kInvalidIPv4 = "1.2.3.4"
kInvalidIPv4Mapped = "::ffff:1.2.3.4"
kValidIPv4 = "172.16.12.34"
kValidIPv4Mapped = "::ffff:172.16.12.34"
kInvalidIPv6 = "3ffe::1:2:3:4"
kValidIPv6 = "2001:db8:1:2:84d9:1490:d0c0:d5fd"       # from kValidIPv4
kOutOfRangeIPv6 = "2001:db8:1:2:487c:4474:790c:e680"  # from kInvalidIPv4


class EncryptedIPConverterTest(unittest.TestCase):

  def setUp(self):
    self.converter = http.EncryptedIPConverter()
    self.packed_ip4 = socket.inet_aton(kInvalidIPv4)

    self.prefix = "3ffe:"  # 6bone :)
    self.expected_v6_addrs = [
        self.prefix + ":487c:4474:790c:e680",
        self.prefix + ":b3c5:4b4d:6821:3574",
        self.prefix + ":71dc:98a2:e850:56bf",
        self.prefix + ":7016:506c:66ab:5402",
        self.prefix + ":505d:525c:befb:01c3",
        self.prefix + ":5753:d8fd:4feb:92fe",
        ]

  def testGetEncrypted64(self):
    for i in xrange(len(self.expected_v6_addrs)):
      suffix = self.converter.GetEncrypted64(self.packed_ip4, i)
      v6_addr = self.prefix
      for j in range(0, 8, 2):
        v6_addr += ":%02x%02x" % (ord(suffix[j]), ord(suffix[j+1]))
      self.assertEquals(self.expected_v6_addrs[i], v6_addr)

  def testGetFirstLocal64(self):
    suffix = self.converter.GetFirstLocal64(self.packed_ip4)
    v6_addr = self.prefix
    for j in range(0, 8, 2):
      v6_addr += ":%02x%02x" % (ord(suffix[j]), ord(suffix[j+1]))
    self.assertEquals(self.expected_v6_addrs[0], v6_addr)

  def testGetDecrypted64(self):
    for i in xrange(len(self.expected_v6_addrs)):
      v6_packed = socket.inet_pton(socket.AF_INET6, self.expected_v6_addrs[i])
      v4_packed = self.converter.GetDecrypted64(v6_packed)
      self.assertEquals(kInvalidIPv4,
                        socket.inet_ntop(socket.AF_INET, v4_packed))


class ParsedAddressTest(unittest.TestCase):

  def testBadAddresses(self):
    self.assertRaises(http.Error, http.ParsedAddress, "this:is:not:valid")
    self.assertRaises(http.Error, http.ParsedAddress, "")
    self.assertRaises(http.Error, http.ParsedAddress, None)

  def testIPv4Address(self):
    parsed = http.ParsedAddress(kInvalidIPv4)
    self.assertEquals(socket.AF_INET, parsed.family)
    self.assertEquals(socket.inet_pton(socket.AF_INET, kInvalidIPv4),
                      parsed.packed)
    self.assertEquals(kInvalidIPv4, parsed.ToString())
    self.assertFalse(http.ValidTunnelAddress.IPv4InRange(parsed.packed))
    self.assertFalse(http.ValidTunnelAddress(kInvalidIPv4).IsValid())

  def testValidTunnelIPv4Address(self):
    parsed = http.ParsedAddress(kValidIPv4)
    self.assertEquals(socket.AF_INET, parsed.family)
    self.assertEquals(socket.inet_pton(socket.AF_INET, kValidIPv4),
                      parsed.packed)
    self.assertEquals(kValidIPv4, parsed.ToString())
    self.assertTrue(http.ValidTunnelAddress.IPv4InRange(parsed.packed))
    valid = http.ValidTunnelAddress(kValidIPv4)
    self.assertTrue(valid.IsValid())
    converted = valid.ConvertedAddress()
    self.assertEquals(socket.AF_INET6, converted.family)
    self.assertEquals(kValidIPv6, converted.ToString())

  def testMappedIPv4Address(self):
    parsed = http.ParsedAddress(kValidIPv4Mapped)
    self.assertEquals(socket.AF_INET, parsed.family)
    self.assertEquals(socket.inet_pton(socket.AF_INET, kValidIPv4),
                      parsed.packed)
    self.assertEquals(kValidIPv4, parsed.ToString())
    valid = http.ValidTunnelAddress(kValidIPv4)
    self.assertTrue(valid.IsValid())
    converted = valid.ConvertedAddress()
    self.assertEquals(socket.AF_INET6, converted.family)
    self.assertEquals(kValidIPv6, converted.ToString())

  def testIPv6Address(self):
    parsed = http.ParsedAddress(kInvalidIPv6)
    self.assertEquals(socket.AF_INET6, parsed.family)
    self.assertEquals(socket.inet_pton(socket.AF_INET6, kInvalidIPv6),
                      parsed.packed)
    self.assertEquals(kInvalidIPv6, parsed.ToString())
    self.assertFalse(http.ValidTunnelAddress.IPv6InRange(parsed.packed))
    self.assertFalse(http.ValidTunnelAddress(kInvalidIPv6).IsValid())

  def testIPv6AddressOutOfRange(self):
    parsed = http.ParsedAddress(kOutOfRangeIPv6)
    self.assertEquals(socket.AF_INET6, parsed.family)
    self.assertEquals(socket.inet_pton(socket.AF_INET6, kOutOfRangeIPv6),
                      parsed.packed)
    self.assertEquals(kOutOfRangeIPv6, parsed.ToString())
    self.assertFalse(http.ValidTunnelAddress.IPv6InRange(parsed.packed))
    self.assertFalse(http.ValidTunnelAddress(kOutOfRangeIPv6).IsValid())

  def testValidTunnelIPv6Address(self):
    parsed = http.ParsedAddress(kValidIPv6)
    self.assertEquals(socket.AF_INET6, parsed.family)
    self.assertEquals(socket.inet_pton(socket.AF_INET6, kValidIPv6),
                      parsed.packed)
    self.assertEquals(kValidIPv6, parsed.ToString())
    valid = http.ValidTunnelAddress(kValidIPv6)
    self.assertTrue(valid.IsValid())
    converted = valid.ConvertedAddress()
    self.assertEquals(socket.AF_INET, converted.family)
    self.assertEquals(kValidIPv4, converted.ToString())


class IPv6TunnelHTTPServerTest(unittest.TestCase):

  def GetTestHandler(self, client_address6, input_string):
    """Prep an http.MyHandler() instance for test use."""
    handler = http.MyHandler()
    handler.rfile = StringIO(input_string)
    handler.wfile = StringIO()
    handler.client_address = (client_address6, 0, 0, 0)

    # Quite the stderr log output.
    handler.efile = StringIO()

    class FakeHeaders(object):
      def __init__(self):
        self.dict = {}
      def getheader(self, h):
        return self.dict[h]
    handler.headers = FakeHeaders()

    def FakeLogMessage(format, *args):
      # Copied from BaseHTTPRequestHandler.
      handler.efile.write("%s - - [%s] %s\n" %
                          (handler.client_address[:1],
                           handler.log_date_time_string(),
                           format%args))
    handler.log_message = FakeLogMessage

    return handler

  def assertHTTPReturnCode(self, rcode, body):
    rcode_word = body.split("\n")[0].split()[1]  # second word of first line
    self.assertEquals(int(rcode), int(rcode_word))

  def testGET_404(self):
    handler = self.GetTestHandler(kValidIPv4Mapped,
                                  "GET /does?n=t#exist HTTP/1.0\r\n\r\n")
    handler.handle()
    self.assertHTTPReturnCode(404, handler.wfile.getvalue())

  def testGET_403s(self):
    test_cases = [
        (kInvalidIPv4Mapped, "GET / HTTP/1.0\r\n\r\n"),
        (kInvalidIPv4Mapped, "GET /ip6z HTTP/1.0\r\n\r\n"),
        (kInvalidIPv4Mapped, "GET /ip6z/ HTTP/1.0\r\n\r\n"),
        (kInvalidIPv4Mapped, "GET /foo HTTP/1.0\r\n\r\n"),
        (kInvalidIPv6, "GET / HTTP/1.0\r\n\r\n"),
        (kInvalidIPv6, "GET /ip4z HTTP/1.0\r\n\r\n"),
        (kInvalidIPv6, "GET /ip4z/ HTTP/1.0\r\n\r\n"),
        (kInvalidIPv6, "GET /foo HTTP/1.0\r\n\r\n"),
        ]
    for tc in test_cases:
      handler = self.GetTestHandler(tc[0], tc[1])
      handler.handle()
      self.assertHTTPReturnCode(403, handler.wfile.getvalue())

  def testGET_root_WithValidSourceIPv4(self):
    handler = self.GetTestHandler(kValidIPv4Mapped, "GET / HTTP/1.0\r\n\r\n")
    handler.handle()
    self.assertHTTPReturnCode(200, handler.wfile.getvalue())
    # make sure the correct suffix ends up in there
    self.assert_(handler.wfile.getvalue().index(kValidIPv6))

  def testGET_ip6z_WithValidIPv4ClientAddress(self):
    for uri in ["/ip6z", "/ip6z/"]:
      handler = self.GetTestHandler(kValidIPv4Mapped,
                                    "GET %s HTTP/1.0\r\n\r\n" % uri)
      handler.handle()
      self.assertHTTPReturnCode(200, handler.wfile.getvalue())
      self.assertTrue(handler.wfile.getvalue().endswith(kValidIPv6))

  def testGET_ip4z_WithValidIPv6ClientAddress(self):
    for uri in ["/ip4z", "/ip4z/"]:
      handler = self.GetTestHandler(kValidIPv6,
                                    "GET %s HTTP/1.0\r\n\r\n" % uri)
      handler.handle()
      self.assertHTTPReturnCode(200, handler.wfile.getvalue())
      self.assertTrue(handler.wfile.getvalue().endswith(kValidIPv4))

  def testGET_ip6z_WithValidIPv4URIAddress(self):
    # This should fail the top-level filter.
    for uri in ["/ip6z/" + kValidIPv4, "/ip6z/" + kValidIPv4Mapped]:
      handler = self.GetTestHandler(kInvalidIPv6,
                                    "GET %s HTTP/1.0\r\n\r\n" % uri)
      handler.handle()
      self.assertHTTPReturnCode(403, handler.wfile.getvalue())

  def testGET_ip4z_WithValidIPv6URIAddress(self):
    # This should fail the top-level filter.
    uri = "/ip4z/" + kValidIPv6
    handler = self.GetTestHandler(kInvalidIPv6,
                                  "GET %s HTTP/1.0\r\n\r\n" % uri)
    handler.handle()
    self.assertHTTPReturnCode(403, handler.wfile.getvalue())

  def testUserIP_Proxy(self):
    handler = self.GetTestHandler(kValidIPv6, "GET / HTTP/1.0\r\n\r\n")
    handler.headers.dict["x-forwarded-for"] = kValidIPv4 + ",foo,bar"
    self.assertEqual(handler.UserIP(), (kValidIPv4, True))

  def testUserIP_NoProxy(self):
    handler = self.GetTestHandler(kValidIPv6, "GET / HTTP/1.0\r\n\r\n")
    handler.headers.dict["x-forwarded-for"] = None
    self.assertEqual(handler.UserIP(), (kValidIPv6, False))


class ConfigFileParserTest(unittest.TestCase):

  SIMPLE_CONFIG = (
      'PREFIX="2001:db8:0:0"\n'
      'KEY=""\n'
      'SERVER_IPV4="0.1.2.3"\n'
      'SUBNETS=""\n')

  def IPv4ToInt(self, ip):
    return struct.unpack("!i", socket.inet_aton(ip))[0]

  def testValidConfig(self):
    config_txt = (
        '# Comment "\n'
        ' PREFIX="2001:db8:0:0"  \n'
        'KEY="01 02 0304"\n'
        'SERVER_IPV4="0.1.2.3"\n'
        'SUBNETS="172.16.0.0/12 1.2.3.4/5 0.0.0.0/0   127.0.0.1"\n')

    config = http.ConfigFileParser(StringIO(config_txt))
    self.assertEquals(config.prefix, "\x20\x01\x0d\xb8\x00\x00\x00\x00")
    self.assertEquals(config.key, "\x01\x02\x03\x04")
    self.assertEquals(config.subnets,
                      [(self.IPv4ToInt("172.16.0.0"), ~0 << 20),
                       (self.IPv4ToInt("1.2.3.4"), ~0 << 27),
                       (self.IPv4ToInt("0.0.0.0"), 0),
                       (self.IPv4ToInt("127.0.0.1"), ~0)])

  def testInvalidKey(self):
    config_txt = self.SIMPLE_CONFIG + 'KEY="0"\n'
    self.assertRaises(http.Error, http.ConfigFileParser, StringIO(config_txt))

  def testInvalidPrefix(self):
    config_txt = self.SIMPLE_CONFIG + 'PREFIX="lol"\n'
    self.assertRaises(http.Error, http.ConfigFileParser, StringIO(config_txt))

  def testInvalidServerIPv4(self):
    config_txt = self.SIMPLE_CONFIG + 'SERVER_IPV4="0.1"\n'
    self.assertRaises(http.Error, http.ConfigFileParser, StringIO(config_txt))

  def testInvalidSubnets(self):
    config_txt = self.SIMPLE_CONFIG + 'SUBNETS="1.2.3.4//"\n'
    self.assertRaises(http.Error, http.ConfigFileParser, StringIO(config_txt))

    config_txt = self.SIMPLE_CONFIG + 'SUBNETS="1.2.3.4/x"\n'
    self.assertRaises(http.Error, http.ConfigFileParser, StringIO(config_txt))

    # This could technically be valid, but it's not worth the effort to parse.
    config_txt = self.SIMPLE_CONFIG + 'SUBNETS="1.2/16"\n'
    self.assertRaises(http.Error, http.ConfigFileParser, StringIO(config_txt))

    config_txt = self.SIMPLE_CONFIG + 'SUBNETS="lol"\n'
    self.assertRaises(http.Error, http.ConfigFileParser, StringIO(config_txt))

if __name__ == "__main__":
  unittest.main()
