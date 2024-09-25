<h1 align="center"> TCP Hijacking </h1>

Python script that performs a Man-in-the-Middle attack on TCP connections, allowing real-time packet modification.<br>

## Usage

1. The first step of the attack is to poison the MAC Table of the server and its default gateway. Modify the addresses accordingly and run `arp_spoofing.py`. (Keep this script running)<br><br>
 Note: It may take some time for the MAC Table to refresh. To speed up the proccess in a lab environment, you can use the following commands:<br>
Linux:  `sudo ip -s -s neigh flush all`<br>
Windows: `arp -d *`<br>

2. Run `tcp_hijack.py` and provide the [IP Address] and [Port number] of the server as arguments.<br>
Syntax: `python tcp_hijack.py [IP_ADDRESS] [PORT NUMBER]`

3. Once `tcp_hijack.py` is running, everything you type in the terminal will be used as the new payload and will be appended at the end of each packet exchanged between the server and its clients.

