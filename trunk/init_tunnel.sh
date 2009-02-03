#!/bin/bash
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

# Read config (KEY, PREFIX, SUBNETS)
echo "Reading config"
source /etc/stubl.conf || exit

echo "Reloading module"
rmmod stubl
modprobe stubl || exit

echo "Setting module parameters"
echo $KEY > /sys/module/stubl/parameters/tunnel_key || exit
echo $PREFIX > /sys/module/stubl/parameters/tunnel_prefix || exit
echo $SUBNETS > /sys/module/stubl/parameters/allowed_subnets || exit

echo "Activating link"
ip -6 addr add $PREFIX::1/64 dev stubl0
ip link set stubl0 up mtu 1400

echo "Done"
