# ARP Table Dumping in .NET

This is basic support for using `sysctl` to dump the ARP table. Only
the IP address and MAC address of entries in the table are parsed out
of the native structures, but this could easily be extended.

This sample is derived from Apple's open source implementation of the
[Mac OS X/BSD `arp` command line utility](http://opensource.apple.com/source/network_cmds/network_cmds-457/arp.tproj/arp.c).

Tested only on Mac OS X 10.10, but theoretically should work on iOS,
provided Apple allows access to the appropriate `sysctl` call. Likely
cannot be submitted to the App Store howerver.

## Build

`% xbuild Arp.sln`

## Run

`% mono bin/Debug/Arp.exe`

Outputs devices connected to the network:

	192.168.0.1 => 000D6B38D521
	192.168.0.9 => 11F9426C13D7
	192.168.0.255 => FFFFFFFFFFFF
