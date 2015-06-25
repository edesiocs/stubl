Stubl is a transition mechanism for providing a basic level of IPv6 connectivity to individual nodes on a private network. All that's required is a single Linux server with an IPv6 /64 subnet routed to it.

The Stubl server consists of a Linux kernel module (stubl.ko) for handling the tunnel packets, and an HTTP server (stubl\_http.py) for calculating clients' addresses and providing tunnel setup instructions.

The main advantage of Stubl is that it allows a user on the network, running any major OS, to get a working IPv6 connection with nothing but a few lines of shell commands. This makes it very easy for developers to start getting familiar with the protocol, with minimal administrative overhead.