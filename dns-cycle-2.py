from boofuzz import *
import os
import subprocess
import signal
import struct

LOG_DIR = "/dns"
INTERFACE = ""
IP = ""
PORT = 53
PROCESS = ""
rcode_counts = {}

def parse_dns_response(data): # Parses rcode from response
    # check data is longer than 12, so there is data to parse 
    if len(data) >= 12:
        # 12 bytes: ID (2) + Flags (2) + QDCOUNT (2) + ANCOUNT (2) + NSCOUNT (2) + ARCOUNT (2)

        _, flags, _ = struct.unpack('!HHH', data[:6]) # High endian, 3 unsigned short integers, Flags (2) put into flags variable, ID and QDCOUNT discarded 

        rcode = flags & 0x000F # Retrieves the rcode from flags with AND operation
        binary_rcode = format(rcode, '04b') # Convert to binary format, as string

        return binary_rcode
    return None

def response_callback(target, fuzz_data_logger ,session, sock, *args, **kwargs):

    try:
        data = sock.recv(10000)  
        rcode = parse_dns_response(data)

        if rcode:
            print(f"Parse returns: {rcode}")
            if rcode in rcode_counts:
                rcode_counts[rcode] += 1
            else:
                
                rcode_counts[rcode] = 1

            print_rcode_dict()
            save_rcode_counts()

        else:
            #If RRset flag is set in query, it wont recieve a response from server, parses the query instead
            rcode_request = parse_dns_response(session.last_send)

            print(f"No answer recieved, rcode in request: {rcode_request}")

            if rcode_request in rcode_counts:
                rcode_counts[rcode_request] += 1
            else:
                
                rcode_counts[rcode_request] = 1

            
            print_rcode_dict()
            save_rcode_counts()

          
            

    except Exception as e:
        fuzz_data_logger.log_error(f"Error receiving data: {e}")


def print_rcode_dict():
    for key,value in rcode_counts.items():
        print(key,value)

def save_rcode_counts():
    filename = os.path.join(LOG_DIR, "rcode_counts.txt")
    with open(filename, "w") as f:
        for code, count in rcode_counts.items():
            f.write(f"{code}: {count}\n")



def main():
   
    tcpdump_start = ['tcpdump','-i', INTERFACE, 'host', IP ,'and port', PORT ,'-w', os.path.join(LOG_DIR, "session.pcap")]
    log_file =  os.path.join(LOG_DIR, "FuzzingLog.txt")
    
    logger_text = FuzzLoggerText(file_handle=open(log_file, 'w'))
    logger_console = FuzzLoggerText()


    session = Session(
        fuzz_loggers=[logger_text, logger_console],
        target=Target(
            connection=UDPSocketConnection(
                IP, 
                PORT, 
                bind=("0.0.0.0", 0)
                )
            ),
        post_test_case_callbacks=[response_callback]
    )

    s_initialize("DNS_query")
    s_word(0x4256, name="TransactionID", endian=">")
    s_word(0x0100, name="Flags",fuzzable=True)  # Standard query
    s_word(1, name="Questions", endian=">",fuzzable=True)
    s_word(0, name="Answer", endian=">",fuzzable=True)
    s_group( name="Authority",values=[b"\x00\x00", b"\x00\x01"])
    s_word(0, name="Additional", endian=">",fuzzable=False)

    # Queries
    if s_block_start("queries"):
        s_size("name", length=1,fuzzable=False)
        if s_block_start("name"):
            s_string("google",fuzzable=True)
        s_block_end()
        s_size("domain",length=1,fuzzable=False)
        if s_block_start("domain"):
            s_string("com",fuzzable=True)
        s_block_end()
        s_group("end", values=[b"\x00", b"\xc0\xb0"]) 
        s_word(0x0001, name="Type", endian=">",fuzzable=True)  
        s_word(0x0001, name="Class", endian=">",fuzzable=True)  
    s_block_end()

    if s_block_start("auth_nameservers", dep="Authority", dep_value=b"\x00\x01", group="Authority"):
        s_size("name_nameserver", length=1,fuzzable=False)
        if s_block_start("name_nameserver"):
            s_string("google",fuzzable=True)
        s_block_end()
        s_size("domain_nameserver",length=1,fuzzable=False)
        if s_block_start("domain_nameserver"):
            s_string("com",fuzzable=False)
        s_block_end()
        s_group("end", values=[b"\x00", b"\xc0\xb0"])
        s_word(0x0006, name="Type_auth", endian=">",fuzzable=True)  
        s_word(0x0001, name="Class_auth", endian=">",fuzzable=True)  
        s_dword(3600, name="TTL_auth", endian=">",fuzzable=True)  
        s_size("data_length_auth", length=2)
        if s_block_start("data_length_auth"):
            s_size("nameserver", length=1,fuzzable=False)
            if s_block_start("nameserver"):
                s_string("ns",fuzzable=True)
            s_block_end()
            s_size("nameserver_name", length=1,fuzzable=False)
            if s_block_start("nameserver_name"):
                s_string("google",fuzzable=True)
            s_block_end()
            s_size("nameserver_domain",length=1,fuzzable=False)
            if s_block_start("nameserver_domain"):
                s_string("com",fuzzable=False)
            s_block_end()
            s_dword(3600,"Serial_number",fuzzable=True)
            s_dword(3600,"Refresh_interval",fuzzable=True)
            s_dword(3600,"Retry_interval",fuzzable=True)
            s_dword(3600,"Expire_limit",fuzzable=True)
            s_dword(3600,"Minimum_TTL",fuzzable=True)
            s_dword(3600,"Serial_number",fuzzable=True)
        s_block_end()
    s_block_end()

   


    tcpdump_process = subprocess.Popen(tcpdump_start)
    
    try:
        session.connect(s_get("DNS_query"))
        session.fuzz(max_depth = 1)
    except KeyboardInterrupt:
        print("Ctrl+C pressed, stopping fuzzing and stopping tcpdump.")
    finally:
        tcpdump_process.send_signal(signal.SIGINT)
        tcpdump_process.wait()
    

if __name__ == "__main__":
    main()


   