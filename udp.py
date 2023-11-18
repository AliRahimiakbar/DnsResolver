import socket
import struct
import threading
import socketserver

HOSTS_FILE_PATH = '/etc/myhosts'
port = 5353

def get_all_ip_address():
    hosts = {}
    with open(HOSTS_FILE_PATH, 'r') as file:
        for line in file:
            try:
                IP_addr, domain = line.split()
                if domain not in hosts:
                    hosts[domain] = []
                hosts[domain].append(IP_addr)
            except:
                break
    return hosts



class DNSRequestHandler(socketserver.BaseRequestHandler):
    request_count = 0

    def handle(self):
        data = self.request[0]
        socket = self.request[1]
        resolver = DNSResolver()
        response = resolver.handle_query(data=data)
        socket.sendto(response, self.client_address)

        self.request_count += 1
        if self.request_count % 2 == 0:
            threading.Thread(target=self.server_thread).start()

    def server_thread(self):
        dns_server = socketserver.ThreadingUDPServer(('127.0.0.1', port), DNSRequestHandler)
        dns_server.serve_forever()



class DNSResolver:

    def __init__(self):
        pass


    def get_ip_address(self, domain_name):
        all_hosts = get_all_ip_address()
        if domain_name in all_hosts:
            ip_address = all_hosts[domain_name]
            return ip_address[0]
        else:
            return 0
        

    def encode_domain(self, domain):
        labels = domain.split('.')
        encoded_labels = []
        for label in labels:
            label_length = len(label)
            encoded_label = struct.pack('!B', label_length) + label.encode()
            encoded_labels.append(encoded_label)
        encoded_domain_name = b''.join(encoded_labels) + b'\x00'
        return encoded_domain_name

    
    
    def create_full_response(self, transaction_id, domain, ip_response, qtype, qclass):
        # Construct the DNS response packet
        response = b''

        # Add the transaction ID (2 bytes)
        response += struct.pack('!H', transaction_id)

        # Add the flags (2 bytes)
        flags = 0b1000000000000000  
        flags |= 0b0000000000000000  
        flags |= 0b0000000000000000  
        flags |= 0b0000000000000000  
        flags |= 0b0000000000000000  
        flags |= 0b0000000000000000  
        flags |= 0b0000000000000000  
        response += struct.pack('!H', flags)

        # Add the question count (2 bytes)
        response += struct.pack('!H', 1)  

        # Add the answer count (2 bytes)
        if ip_response != 0:
           response += struct.pack('!H', 1)  
        else:
            response += struct.pack('!H', 0)

        # Add the authority count (2 bytes)
        response += struct.pack('!H', 0)

        # Add the additional count (2 bytes)
        response += struct.pack('!H', 0)

        # Add the domain name
        response += self.encode_domain(domain)

        # Add the query type (2 bytes)
        response += struct.pack('!H', 1)

        # Add the query class (2 bytes)
        response += struct.pack('!H', 1)

        if ip_response != 0:
            # Add the domain name
            response += self.encode_domain(domain)

            # Add the query type (2 bytes)
            response += struct.pack('!H', 1)

            # Add the query class (2 bytes)
            response += struct.pack('!H', 1)

            # Add the TTL (4 bytes)
            ttl = 600  # Assuming a TTL of 10 min
            response += struct.pack('!I', ttl)

            # Add the data length (2 bytes)
            response += struct.pack('!H', 4)

            # Add the IPv4 address (4 bytes)
            response += socket.inet_aton(ip_response)

        return response



    def handle_query(self, data):
        # Parse Transaction id
        transaction_id = struct.unpack('!H', data[:2])[0]

        self.index = 12
        domain = ''
        while True:
            label_length = data[self.index]
            if label_length == 0:
                break
            elif (label_length & 0xC0) == 0xC0:
                pointer = struct.unpack('!H', data[self.index:self.index + 2])[0]
                pointer &= 0x3FFF
                sub_domain_name, _ = self.read_domain_name(data, pointer)
                domain += sub_domain_name
                self.index += 2
                break
            else:
                label = data[self.index + 1:self.index + 1 + label_length].decode()
                domain += label + "."
                self.index += label_length + 1
        
        domain = domain[:-1]

        self.index += 1
 
        # Parse question type and class 
        qtype = struct.unpack('!H', data[self.index:self.index + 2])[0]
        qclass = struct.unpack('!H', data[self.index + 2:self.index + 4])[0]

        # Parse query and fetch response
        ip_response = self.get_ip_address(domain)     

        response = self.create_full_response(transaction_id=transaction_id, domain=domain, ip_response=ip_response, qtype=qtype,qclass=qclass)

        return response
    


dns_server = socketserver.UDPServer(('127.0.0.1', port), DNSRequestHandler)

dns_server.serve_forever()
