from boofuzz import *
import os
import subprocess
import signal
import re


LOG_DIR = "/sip"
INTERFACE = ""
IP = ""
PORT = 5060
PROCESS = ""
status_code_counts = {}

def parse_sip_response(data): # Parse status code from response
    match = re.search(rb'SIP/\d.\d (\d{3})', data)
    if match:
        return match.group(1).decode('utf-8')
    return None

def response_callback(target, fuzz_data_logger ,session, sock, *args, **kwargs): # Requires service listening at port 5060 (at client) to work 

    try:
      
        data = sock.recv(10000)  
        status_code = parse_sip_response(data)

        if status_code:
            print(f"Parse returns: {status_code}")
            if status_code in status_code_counts:
                status_code_counts[status_code] += 1
            else:
                
                status_code_counts[status_code] = 1

            print_status_code_dict()
            save_status_code_counts()

        else:

            print(f"No answer recieved")

            if "ERROR" in status_code_counts:
                status_code_counts["ERROR"] += 1
            else:
                
                status_code_counts["ERROR"] = 1

            
            print_status_code_dict()
            save_status_code_counts()

          
            

    except Exception as e:
        fuzz_data_logger.log_error(f"Error receiving data: {e}")


def print_status_code_dict():
    for key,value in status_code_counts.items():
        print(key,value)

def save_status_code_counts():
    filename = os.path.join(LOG_DIR, "status_code_counts.txt")
    with open(filename, "w") as f:
        for code, count in status_code_counts.items():
            f.write(f"{code}: {count}\n")



def main():
    tcpdump_start = ['tcpdump','-i', INTERFACE, 'host', IP ,'and port', PORT ,'-w', os.path.join(LOG_DIR, "session.pcap")]

    log_file =  os.path.join(LOG_DIR, "FuzzingLog.txt")
    logger_text = FuzzLoggerText(file_handle=open(log_file, 'w'))
    logger_console = FuzzLoggerText()

    session = Session(
        target=Target(
            connection=UDPSocketConnection(
                IP,
                PORT, 
                bind=("0.0.0.0",0)
            )  
        ),
        fuzz_loggers=[logger_console,logger_text]
    )
    
 
    # SIP Invite structure, default values generated with chatgpt

    s_initialize(name="SIP Invite")
    with s_block("Invite"):
        s_string("INVITE", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("sip:")
        s_string("user")
        s_delim("@")
        s_string("example.com", fuzzable=True)  # Domain
        s_string(" SIP/2.0\r\n", fuzzable=False)
        s_string("Via: SIP/2.0/UDP ", fuzzable=False)
        s_string("client.example.com:5060;branch=", fuzzable=False)
        s_string("z9hG4bK776asdhds", fuzzable=True)  # Branch
        s_static("\r\n")
        s_string("Max-Forwards: ", fuzzable=False)
        s_string("70", fuzzable=True)  # Max-Forwards 
        s_static("\r\n")
        s_string("From: ", fuzzable=False)
        s_string('"Fuzzer" <sip:', fuzzable=False)
        s_string("fuzzer@example.com", fuzzable=True)  # From 
        s_string(">;tag=12345\r\n", fuzzable=False)
        s_string("To: ", fuzzable=False)
        s_string('"Target" <sip:', fuzzable=False)
        s_string("target@example.com", fuzzable=True)  # To
        s_string(">\r\n", fuzzable=False)
        s_string("Call-ID: ", fuzzable=False)
        s_string("123456789@client.example.com", fuzzable=True)  # Call-ID
        s_static("\r\n")
        s_string("CSeq: ", fuzzable=False)
        s_int(1, fuzzable=True, output_format="ascii")
        s_string(" INVITE", fuzzable=True)  # CSeq 
        s_static("\r\n")
        s_string("Contact: ", fuzzable=False)
        s_string('<sip:', fuzzable=False)
        s_string("fuzzer@client.example.com", fuzzable=True)  # Contact
        s_string(">\r\n", fuzzable=False)
        s_string("Content-Type: ", fuzzable=False)
        s_string("application/sdp", fuzzable=True)  # Content-Type
        s_static("\r\n")
        s_string("Content-Length: ", fuzzable=False)
        s_size("body" , fuzzable=False, endian=">", output_format="ascii")  # Content-Length
        s_static("\r\n\r\n")
        if (s_block_start("body")):
            s_static("v=0\r\n") 
            s_static("o=")
            s_string("user1 53655765 2353687637") 
            s_static(" IN IP4 ") 
            s_string("client.example.com")
            s_static("\r\n")
            s_static("s=-\r\n")
            s_static("c=IN IP4 client.example.com\r\n")
            s_static("t=0 0\r\n")
            s_static("m=audio 1234 ")
            s_string("RTP/AVP 0")
            s_static("\r\n")
            s_static("a=rtpmap:0 PCMU/8000\r\n")
        s_block_end()


    tcpdump_process = subprocess.Popen(tcpdump_start)
    
    try:
        session.connect(s_get("SIP Invite"))
        session.fuzz(max_depth = 1)
    except KeyboardInterrupt:
        print("Ctrl+C pressed, stopping fuzzing and stopping tcpdump.")
    finally:
        tcpdump_process.send_signal(signal.SIGINT)
        tcpdump_process.wait()
    

if __name__ == "__main__":
    main()
