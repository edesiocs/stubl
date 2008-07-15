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

"""Basic HTTP server for generating tunnel instructions."""

__author__ = "pmarks@google.com (Paul Marks)"
__author__ = "ek@google.com (Erik Kline)"


from BaseHTTPServer import BaseHTTPRequestHandler
from BaseHTTPServer import HTTPServer
import binascii
import re
import socket
import SocketServer
import struct
import sys
from Crypto.Cipher import Blowfish


# Global config instance.
config = None


class Error(Exception):
  """Raise this when bad things happen."""
  pass


class ConfigFileParser(object):
  """A class to read a simple config file, and hold its options."""

  def __init__(self, file_obj):
    """Parse options from a config file."""
    self.vars = {}
    var_re = re.compile(r'(\w+)="(.*)"')
    for line in file_obj:
      m = var_re.match(line.strip())
      if m:
        self.vars[m.group(1)] = m.group(2)

    self.key = self.ParseKey()
    self.subnets = self.ParseSubnets()
    self.prefix = self.ParsePrefix()
    self.server_ipv4 = self.ParseServerIPv4()

  def GetConfigValue(self, var):
    """Retrieve a variable from the parsed config file."""
    try:
      return self.vars[var]
    except KeyError:
      raise Error("%s not defined in config file." % var)

  def ParseKey(self):
    """Get the encryption key, and convert to binary."""
    key_str = self.GetConfigValue("KEY")
    try:
      return binascii.a2b_hex(re.sub("[^0-9A-Fa-f]", "", key_str))
    except TypeError, e:
      raise Error("Can't parse key: %s" % e)

  def ParseSubnets(self):
    """Get list of allowed subnets, as a list of (int ip, int mask) pairs."""
    subnets = self.GetConfigValue("SUBNETS").split()
    ipmasks = []

    for cidr in subnets:
      try:
        ip, mask_len = cidr.split("/")
        mask_len = int(mask_len)
      except ValueError:
        ip = cidr
        mask_len = 32

      try:
        ip, = struct.unpack("!i", socket.inet_pton(socket.AF_INET, ip))
      except socket.error:
        raise Error("Invalid subnet IP: %s" % cidr)

      if mask_len == 0:
        mask = 0
      elif 1 <= mask_len <= 32:
        mask = ~0 << (32 - mask_len)
      else:
        raise Error("Invalid subnet length: %s" % cidr)

      ipmasks.append((ip, mask))

    return ipmasks

  def ParsePrefix(self):
    """Get the 64-bit IPv6 tunnel prefix, as an 8 byte packed string."""
    prefix = self.GetConfigValue("PREFIX")
    try:
      return socket.inet_pton(socket.AF_INET6, prefix + "::")[:8]
    except socket.error:
      raise Error("Invalid IPv6 prefix: %s" % prefix)

  def ParseServerIPv4(self):
    """Get the tunnel server's configured IPv4 address, as text."""
    ip = self.GetConfigValue("SERVER_IPV4")
    try:
      # Note: pton is more strict than aton.
      socket.inet_pton(socket.AF_INET, ip)
    except socket.error:
      raise Error("Invalid server IPv4 address: %s" % ip)
    return ip


class EncryptedIPConverter(object):
  """Encapsulates the {en,de}cryption of IPv{4,6} tunnel addresses."""
  _ENC = None

  def __init__(self):
    if self._ENC is None:
      EncryptedIPConverter._ENC = Blowfish.new(config.key,
                                               Blowfish.MODE_ECB)

  def GetEncrypted64(self, addr4, counter):
    return self._ENC.encrypt(addr4 + struct.pack("!I", counter))

  def GetFirstLocal64(self, addr4):
    # Try to get an address with the universal/local bit set to 0
    for i in xrange(64):
      suffix = self.GetEncrypted64(addr4, i)
      if (ord(suffix[0]) & 0x02) == 0:
        return suffix

    # Probability of getting 64 1's in a row is very tiny.
    raise Error("No local addresses found.  This should be impossible.")

  def GetDecrypted64(self, addr6):
    addr6 = addr6[-8:]
    return self._ENC.decrypt(addr6)[:4]


class ParsedAddress(object):
  """Little data (code smell!) class to encapsulate address parsing."""
  V4_MAPPED_PREFIX = socket.inet_pton(socket.AF_INET6, "::ffff:0:0")[:12]
  FAMILY_NAMES = {socket.AF_INET: "IPv4",
                  socket.AF_INET6: "IPv6"}

  def __init__(self, address_string):
    try:
      addrinfo = socket.getaddrinfo(address_string, None, socket.AF_UNSPEC,
                                    socket.SOCK_STREAM, socket.IPPROTO_TCP,
                                    socket.AI_NUMERICHOST)
      self.family = addrinfo[0][0]
      self.packed = socket.inet_pton(self.family, addrinfo[0][4][0])
      if (self.family == socket.AF_INET6 and
          self.packed.startswith(self.V4_MAPPED_PREFIX)):
        self.packed = self.packed[-4:]
        self.family = socket.AF_INET

    except (socket.gaierror, IndexError), e:
      raise Error("Error parsing address string %s: %s"
                  % (address_string, str(e)))

  def ToString(self):
    return socket.inet_ntop(self.family, self.packed)

  def FamilyName(self):
    return self.FAMILY_NAMES[self.family]


class ValidTunnelAddress(ParsedAddress):
  """A subclass of ParsedAddress that also does validation/conversion."""

  @staticmethod
  def IPv4InRange(packed4):
    """Returns true for any IPv4 address which can be a tunnel endpoint."""
    query_ip, = struct.unpack("!i", packed4)
    for ip, mask in config.subnets:
      if (ip & mask) == (query_ip & mask):
        return True
    return False

  @staticmethod
  def IPv6InRange(packed6):
    if packed6.startswith(config.prefix):
      return ValidTunnelAddress.IPv4InRange(
          EncryptedIPConverter().GetDecrypted64(packed6))
    return False

  def __init__(self, address_string):
    ParsedAddress.__init__(self, address_string)
    self._converter = EncryptedIPConverter()

  def IsValid(self):
    if self.family == socket.AF_INET:
      return ValidTunnelAddress.IPv4InRange(self.packed)
    elif self.family == socket.AF_INET6:
      return ValidTunnelAddress.IPv6InRange(self.packed)
    return False

  def ConvertedAddress(self):
    """Return a ValidTunnelAddress representing the "converted" address."""
    if self.family == socket.AF_INET:
      packed6 = (config.prefix +
                 self._converter.GetFirstLocal64(self.packed))
      return ValidTunnelAddress(socket.inet_ntop(socket.AF_INET6, packed6))
    elif self.family == socket.AF_INET6:
      packed4 = self._converter.GetDecrypted64(self.packed)
      return ValidTunnelAddress(socket.inet_ntop(socket.AF_INET, packed4))
    raise Error("unknown address family")


class MyHandler(BaseHTTPRequestHandler):
  """HTTP Request handler."""
  template = file("template.html").read()

  def __init__(self, *args):
    # This make live serving usage AND testability possible.  Probably
    # there is/should be a better way (without having to instantiate a
    # whole running server).
    if args:
      BaseHTTPRequestHandler.__init__(self, *args)

  def do_GET(self):
    """Handle GET requests."""

    # Top-level IP filtering.
    if not ValidTunnelAddress(self.client_address[0]).IsValid():
      self.send_error(403, "Your IP is not authorized to view this page")
      return

    def TryWrapError(callable_method):
      try:
        callable_method()
      except Error, e:
        self.send_error(400, str(e))

    # Simple URL map
    if self.path == "/ip4z" or self.path.startswith("/ip4z/"):
      TryWrapError(self.GetIp4z)
    elif self.path == "/ip6z" or self.path.startswith("/ip6z/"):
      TryWrapError(self.GetIp6z)
    elif self.path == "/":
      TryWrapError(self.GetRoot)
    else:
      # Send 404 error for anything else
      self.send_error(404)
    return

  def GetRoot(self):
    """Handle "GET /" requests."""

    valid = ValidTunnelAddress(self.client_address[0])
    if not valid.IsValid():
      raise Error("invalid tunnel endpoint")

    self.send_response(200, "OK")
    self.send_header("Content-type", "text/html")
    self.end_headers()

    if valid.family == socket.AF_INET:
      v4_addr = valid.ToString()
      v6_addr = valid.ConvertedAddress().ToString()
    else:
      v4_addr = valid.ConvertedAddress().ToString()
      v6_addr = valid.ToString()

    template_args = {
        'client_family': valid.FamilyName(),
        'client_addr': valid.ToString(),
        'server_ip4': config.server_ipv4,
        'client_ip4': v4_addr,
        'client_ip6': v6_addr,
    }

    self.wfile.write(self.template % template_args)

  def GetIp4z(self):
    """Handle "GET /ip4z" requests.

    This is a URI that can be used to programmatically convert IPv6
    addresses to IPv4 addresses, if they are in the correct range.

    These requests may be of the form:
              "GET /ip4z"
              "GET /ip4z/3ffe::1:2:3:4"

    If the requested path is "/ip4z" it is treated as if it were
    "/ip4z/<client_address>".
    """
    address = self.path[len("/ip4z/"):]
    if not address:
      address = self.client_address[0]

    valid = ValidTunnelAddress(address)
    if not valid.IsValid():
      raise Error("bad address")

    if valid.family == socket.AF_INET:
      response = valid.ToString()
    else:
      response = valid.ConvertedAddress().ToString()

    self.send_response(200, "OK")
    self.send_header("Content-type", "text/plain")
    self.end_headers()
    self.wfile.write(response)

  def GetIp6z(self):
    """Handle "GET /ip6z" requests.

    This is a URI that can be used to programmatically convert IPv4
    addresses to IPv6 addresses, if they are in the correct range.

    These requests may be of the form:
              "GET /ip6z"
              "GET /ip6z/1.2.3.4"

    If the requested path is "/ip6z" it is treated as if it were
    "/ip6z/<client_address>".
    """
    address = self.path[len("/ip6z/"):]
    if not address:
      address = self.client_address[0]

    valid = ValidTunnelAddress(address)
    if not valid.IsValid():
      raise Error("bad address")

    if valid.family == socket.AF_INET6:
      response = valid.ToString()
    else:
      response = valid.ConvertedAddress().ToString()

    self.send_response(200, "OK")
    self.send_header("Content-type", "text/plain")
    self.end_headers()
    self.wfile.write(response)
    return


def main():
  global config
  config = ConfigFileParser(file("/etc/stubl.conf"))
  SocketServer.TCPServer.address_family = socket.AF_INET6
  server_addr = ("", 6446)
  httpd = HTTPServer(server_addr, MyHandler)

  print "Stubl HTTP listening on port %d" % server_addr[1]
  httpd.serve_forever()


if __name__ == "__main__":
  main()
