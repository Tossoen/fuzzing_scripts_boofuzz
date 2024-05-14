from boofuzz import *
import os
import subprocess
import signal

LOG_DIR = "/dns"
INTERFACE = ""
IP = ""
PORT = 53
PROCESS = ""

# Stores responses and requests in a txt file
def response_callback(target, fuzz_data_logger ,session, sock, *args, **kwargs):
  
    try:
        data = sock.recv(10000)  

        last_sent_request_data = session.last_send
        
        filename = os.path.join(LOG_DIR, "DNS.txt")
        
        with open(filename, "a") as f:
            f.write("-----------------------------\n")
            f.write("------Request-------\n")
            f.write(last_sent_request_data.decode('utf-8', errors='replace' ))
            f.write("\n\n")
            f.write("------Response------\n")
            f.write(data.decode('utf-8', errors='replace' ))
            f.write("\n\n")
            f.write("-----------------------------\n")
        
        print(f"Callback succeded, file appendededed")
        
    except Exception as e:
        fuzz_data_logger.log_error(f"Error receiving data: {e}")

def main():
   
    tcpdump_start = ['tcpdump','-i', INTERFACE, 'host', IP, 'and', 'port', 53 ,'-w', os.path.join(LOG_DIR, "dns-session.pcap")]
    log_file =  os.path.join(LOG_DIR, "FuzzingLog.txt")
    
    logger_text = FuzzLoggerText(file_handle=open(log_file, 'w'))
    logger_console = FuzzLoggerText()


    options = {
        "proc_name": PROCESS,  
        "start_commands": [f"/etc/init.d/{PROCESS} start"],
        "stop_commands" : [f"/etc/init.d/{PROCESS} stop"]
    }

    procmonn = ProcessMonitor(host=IP, port=26002)
    procmonn.set_options(**options)

    session = Session(
        fuzz_loggers=[logger_text, logger_console],
        target=Target(
            connection=UDPSocketConnection(
                IP, 
                PORT, 
                bind=("0.0.0.0", 0)
                ),
                procmon=procmonn
            ),
        post_test_case_callbacks=[response_callback]
    )

    s_initialize("DNS_query")
    s_word(0x4256, name="TransactionID", endian=">")
    s_word(0x0100, name="Flags") 
    s_word(1, name="Questions", endian=">")
    s_word(0, name="Answer", endian=">",fuzzable=False)
    s_word(0, name="Authority", endian=">",fuzzable=False)
    s_word(0, name="Additional", endian=">",fuzzable=False)

    # Queries
    
    if s_block_start("queries"):
        s_size("name", length=1,fuzzable=False)
        if s_block_start("name"):
            s_string("google")
        s_block_end()
        s_size("domain",length=1,fuzzable=False)
        if s_block_start("domain"):
            s_string("com")
        s_block_end()
        s_group("end", values=[b"\x00", b"\xc0\xb0"]) 
        s_word(0x0001, name="Type", endian=">")  # Type: ANY
        s_word(0x0001, name="Class", endian=">")  # Class: IN
    s_block_end()
    s_repeat("queries", variable=s_mirror(name="reps",primitive_name="Questions"), fuzzable=False, name="aqueries") # <--Not working as intended

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
