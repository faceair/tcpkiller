# TCPKiller

<img src="cat.jpg" width="240" height="240">

a TCP killer.

## Installation

> go get github.com/faceair/tcpkiller

## Usage

support tcpdump expression

> tcpkiller -i en0 port 443

> tcpkiller -i en0 host 192.168.1.1

> tcpkiller -i en0 dst host 192.168.1.1 and port 80
