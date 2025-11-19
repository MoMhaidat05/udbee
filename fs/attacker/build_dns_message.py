from dnslib import DNSRecord, QTYPE, DNSHeader, DNSQuestion
from message_fragmentation import fragment_message
import string, random
from log import log_error
def dns_message(message, chunk_size):
    try:
        # Break the message into smaller chunks for DNS transport
        chunks = fragment_message(message, chunk_size)
        records = []
        
        # Convert each chunk into a valid DNS query packet
        for c in chunks:
            # Extract metadata: which piece this is, total pieces, and the actual data
            session_id, index, total, chunk = c.split('|')
            
            # Setting DNS packet header values
            header = DNSHeader(id=int(session_id), qr=0) 
            # Encode all data into a DNS query name (subdomains carry the message)
            domain_name = "".join(i for i in (random.choice(string.ascii_lowercase) for b in range(4)))
            if len(chunk) > 60:
                query_name = f"{index}.{total}.{chunk[0:60]}.{chunk[60:]}.{domain_name}.com"
            else:
                query_name = f"{index}.{total}.{chunk}.{domain_name}.com"

            
            # Create a DNS A record query
            q = DNSQuestion(query_name, QTYPE.TXT)
            
            # Serialize the DNS packet into bytes
            dns_packet = DNSRecord(header=header, q=q)
            dns_packet = dns_packet.pack()
            records.append(dns_packet)
        
        return records
    except Exception as e:
        log_error(str(e))
        return
    
