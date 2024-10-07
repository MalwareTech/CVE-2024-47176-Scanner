#!/usr/bin/env python3
import socket
import ipaddress
import argparse
import threading
import time
import signal
import sys
import os
from http.server import BaseHTTPRequestHandler, HTTPServer


# a simple function to enable easy changing of the timestamp format
def timestamp():
    return time.strftime("%Y-%m-%d %H:%M:%S")


# custom class for handling HTTP requests from cups-browsed instances
class CupsCallbackRequest(BaseHTTPRequestHandler):
    # replace default access log behavior (logging to stderr) with logging to access.log
    # log format is: {date} - {client ip} - {first line of HTTP request} {HTTP response code} {client useragent}
    def log_message(self, _format, *_args):
        log_line = f'[{timestamp()}] {self.address_string()} - {_format % _args} ' \
                   f'{self.headers["User-Agent"]}\n'
        self.server.access_log.write(log_line)
        self.server.access_log.flush()

    # log raw requests from cups-browsed instances including POST data
    def log_raw_request(self):
        # rebuild the raw HTTP request and log it to requests.log for debugging purposes
        raw_request = f'[{timestamp()}]\n'
        raw_request += f'{self.requestline}\r\n'
        raw_request += ''.join(f"{key}: {value}\r\n" for key, value in self.headers.items())

        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 0:
            raw_body = self.rfile.read(content_length)
            self.server.request_log.write(raw_request.encode('utf-8') + b'\r\n' + raw_body + b'\r\n\r\n')
        else:
            self.server.request_log.write(raw_request.encode('utf-8'))

        self.server.request_log.flush()

    # response to all requests with a static response explaining that this server is performing a vulnerability scan
    # this is not required, but helps anyone inspecting network traffic understand the purpose of this server
    def send_static_response(self):
        self.send_response(200, 'OK')
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'This is a benign server used for testing cups-browsed vulnerability CVE-2024-47176')

    # handle GET requests (we don't need to but returning our default response helps anyone investigating the server)
    def do_GET(self):
        self.send_static_response()

    # handle POST requests, cups-browsed instances should send post requests to /printers/ and /printers/<callback_url>
    def do_POST(self):
        # we'll just grab all requests starting with /printers/ to make sure we don't miss anything
        # some systems will check /printers/ first and won't proceed to the full callback url if response is invalid
        if self.path.startswith('/printers/'):
            ip, port = self.client_address

            # log the cups-browsed request to cups.log and requests.logs and output to console
            print(f'[{timestamp()}] received callback from vulnerable device: {ip} - {self.headers["User-Agent"]}')
            self.server.cups_log.write(f'[{timestamp()}] {ip}:{port} - {self.headers["User-Agent"]} - {self.path}\n')
            self.server.cups_log.flush()
            self.log_raw_request()

        self.send_static_response()


# custom class for adding file logging capabilities to the HTTPServer class
class CupsCallbackHTTPServer(HTTPServer):
    def __init__(self, server_address, handler_class, log_dir='logs'):
        super().__init__(server_address, handler_class)
        # create 'logs' directory if it doesn't already exist
        log_dir = 'logs'
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # create three separate log files for easy debugging and analysis
        # access.log    - any web requests
        # cups.log      - ip, port, useragent, and request URL for any request sent to CUPS endpoint
        # requests.log  - raw HTTP headers and POST data for any requests sent to the CUPS endpoint (for debugging)
        self.access_log = open(f'{log_dir}/access.log', 'a')
        self.request_log = open(f'{log_dir}/requests.log', 'ab')
        self.cups_log = open(f'{log_dir}/cups.log', 'a')

    def shutdown(self):
        # close all log files on shutdown before shutting down
        self.access_log.close()
        self.request_log.close()
        self.cups_log.close()
        super().shutdown()


# start the callback server to so we can receive callbacks from vulnerable cups-browsed instances
def start_server(callback_server):
    host, port = callback_server.split(':')
    port = int(port)

    if port < 1 or port > 65535:
        raise RuntimeError(f'invalid callback server port: {port}')

    server_address = (host, port)
    _httpd = CupsCallbackHTTPServer(server_address, CupsCallbackRequest)
    print(f'[{timestamp()}] callback server running on port {host}:{port}...')

    # start the HTTP server in a separate thread to avoid blocking the main thread
    server_thread = threading.Thread(target=_httpd.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    return _httpd


def scan_range(ip_range, callback_server, scan_unsafe=False):
    # the vulnerability allows us to add an arbitrary printer by sending command: 0, type: 3 over UDP port 631
    # we can set the printer to any http server as long as the path starts with /printers/ or /classes/
    # we'll use http://host:port/printers/cups_vulnerability_scan as our printer endpoint
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_callback = f'0 3 http://{callback_server}/printers/cups_vulnerability_scan'.encode('utf-8')

    # expand the CIDR notation into a list of IP addresses
    # make scanning only host addresses the default behavior (exclude the network and broadcast address)
    # the user can override this with flag --scan-unsafe
    if scan_unsafe:
        ip_range = list(ipaddress.ip_network(ip_range))
    else:
        ip_range = list(ipaddress.ip_network(ip_range).hosts())

    if len(ip_range) < 1:
        raise RuntimeError("error: invalid ip range")

    print(f'[{timestamp()}] scanning range: {ip_range[0]} - {ip_range[-1]}')

    # send the CUPS command to each IP on port 631 to trigger a callback to our callback server
    for ip in ip_range:
        ip = str(ip)
        udp_socket.sendto(udp_callback, (ip, 631))


# handle CTRL + C abort
def signal_handler(_signal, _frame, _httpd):
    print(f'[{timestamp()}] shutting down server and exiting...')
    _httpd.shutdown()
    sys.exit(0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='python3 scanner.py',
        description='Uses the callback mechanism of CVE-2024-47176 to identify vulnerable cups-browsed instances',
        usage='python3 scanner.py --targets 192.168.0.0/24 --callback 192.168.0.1:1337'
    )

    parser.add_argument('--callback', required=True, dest='callback_server',
                        help='the host:port to host the callback server on (must be reachable from target network) '
                             'example: --callback 192.168.0.1:1337')

    parser.add_argument('--targets', required=True, dest='target_ranges',
                        help='a comma separated list of ranges '
                             'example: --targets 192.168.0.0/24,10.0.0.0/8')

    parser.add_argument('--scan-unsafe', required=False, default=False, action='store_true', dest='scan_unsafe',
                        help='Typically the first and last address in a CIDR are reserved for the network address and '
                             'broadcast address respectively. By default we do not scan these as they should not be '
                             'assigned. However, you can override this behavior by setting --scan-unsafe')

    args = parser.parse_args()

    try:
        # start the HTTP server to captures cups-browsed callbacks
        print(f'[{timestamp()}] starting callback server on {args.callback_server}')
        httpd = start_server(args.callback_server)

        # register sigint handler to capture CTRL + C
        signal.signal(signal.SIGINT, lambda _signal_handler, frame: signal_handler(signal, frame, httpd))

        # split the ranges up by comma and initiate a scan for each range
        targets = args.target_ranges.split(',')
        print(f'[{timestamp()}] starting scan')
        for target in targets:
            scan_range(target, args.callback_server, args.scan_unsafe)

        print(f'[{timestamp()}] scan done, use CTRL + C to callback stop server')

        # loop until user uses CTRL + C to stop server
        while True:
            time.sleep(1)

    except RuntimeError as e:
        print(e)

