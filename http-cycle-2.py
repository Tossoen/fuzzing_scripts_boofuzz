from boofuzz import *
import re
import socket
import os
import datetime
import sys
import subprocess
import signal

LOG_DIR = "/http"
INTERFACE = ""
IP = ""
PORT = 80
PROCESS = ""

status_code_counts = {}

def parse_http_response(data):
    match = re.search(rb'HTTP/[0-9.]+\s+(\d{3})', data)
    if match:
        return match.group(1).decode('utf-8')
    return None


def response_callback(target, fuzz_data_logger, session, sock, *args, **kwargs):

    try:
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S:%f") 
        data = sock.recv(10000)  
        status_code = parse_http_response(data)
        print("Request Data:")
        last_sent_request_data = session.last_send
        print(f"Parse returns: {status_code}")
        if status_code:
            if status_code in status_code_counts:
                status_code_counts[status_code] += 1
            else:
                status_code_counts[status_code] = 1
            
            filename = os.path.join(LOG_DIR, f"{status_code}.txt")
            
            with open(filename, "a") as f:
                f.write("-----------------------------\n")
                f.write(f"Time: {current_time}\n") 
                f.write("------Request-------\n")
                f.write(last_sent_request_data.decode('utf-8'))
                f.write("\n\n")
                f.write("------Response------\n")
                f.write(data.decode('utf-8'))
                f.write("\n\n")
                f.write("-----------------------------\n")
            

            print(f"Received status code {status_code}: {status_code_counts[status_code]} times")
            print_status_code_dict()
            save_status_code_counts()
        else:
            filename = os.path.join(LOG_DIR,"no_response.txt")

            try:
                with open(filename, "a") as f:
                    f.write("-----------------------------\n")
                    f.write(f"Time: {current_time}\n") 
                    f.write("------Request-------\n")
                    f.write(last_sent_request_data.decode('utf-8'))
                    f.write("\n\n")
                    f.write("------Response------\n")
                    f.write(data.decode('utf-8'))
                    f.write("\n\n")
                    f.write("-----------------------------\n")
            except Exception as e:
                fuzz_data_logger.log_error(f"Error writing faulty response data: {e}")
            

    except Exception as e:
        fuzz_data_logger.log_error(f"Error receiving data: {e}")



def main():    
    
  


    log_file =  os.path.join(LOG_DIR, "FuzzingLog.txt")
    
    tcpdump_start = ['tcpdump','-i', INTERFACE, 'host', IP ,'and port', PORT ,'-w', os.path.join(LOG_DIR, "session.pcap")]

    logger_text = FuzzLoggerText(file_handle=open(log_file, 'w'))
    logger_console = FuzzLoggerText()

    session = Session(
        fuzz_loggers=[logger_text, logger_console],
        target=Target(
            connection=SocketConnection(
                IP,
                PORT,
                proto='tcp')
            ),
        post_test_case_callbacks=[response_callback]
        
    )

    ############################################################################################

    s_initialize("Request-With-Body")

    s_group("method",values=["POST","GET","DELETE"])
    if s_block_start("request", group="method"):
        s_delim(" ", fuzzable=False)
        s_static("/",name ="URI")
        s_delim(" ",fuzzable=False)
        s_static("HTTP")
        s_delim("/", fuzzable=False)
        s_float(1.1, s_format=".1f", fuzzable=False)
        s_static("\r\n")

        s_static("Host")
        s_delim(":", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("192.168.56.2", fuzzable=False)
        s_static("\r\n")

        s_static("User-Agent")
        s_delim(":", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.83 Safari/537.1", fuzzable=False)
        s_static("\r\n")

        s_static("\r\n")

        s_string("") #BODY CONTENT

        s_static("\r\n")
        s_static("\r\n")
    s_block_end()

    ##################################################################################

    s_initialize("Request")
    
    s_group("method",values=["GET","POST","DELETE", "TRACE", "OPTIONS"])

    if s_block_start("request-line", group="method"):
        s_delim(" ", fuzzable=False)
        s_static("/")
        s_string("",name ="URI", max_len=100)
        s_delim(" ",fuzzable=False)
        s_static("HTTP")
        s_delim("/", fuzzable=False)
        s_float(1.1, s_format=".1f", fuzzable=False)
        s_static("\r\n")
    s_block_end()


    s_static("Host")
    s_delim(":", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("192.168.56.2", fuzzable=False)
    s_static("\r\n")

    s_static("User-Agent")
    s_delim(":", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.83 Safari/537.1", fuzzable=True, max_len=100)
    s_static("\r\n")
    

    s_static("\r\n")
    

    
    ############################################################################################


    tcpdump_process = subprocess.Popen(tcpdump_start)
    
    try:
        session.connect(s_get("Request-With-Body"))
        session.connect(s_get("Request"))
        session.fuzz(max_depth=2)
    except KeyboardInterrupt:
        print("Ctrl+C pressed, stopping fuzzing and stopping tcpdump.")
    finally:
        tcpdump_process.send_signal(signal.SIGINT)
        tcpdump_process.wait()
    
    
def print_status_code_dict():
    for key,value in status_code_counts.items():
        print(key,value)

def save_status_code_counts():
    filename = os.path.join(LOG_DIR, "status_code_counts.txt")
    with open(filename, "w") as f:
        for code, count in status_code_counts.items():
            f.write(f"{code}: {count}\n")

if __name__ == "__main__":
    main()