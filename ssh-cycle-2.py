from boofuzz import *
import os
import subprocess
import signal

# Define the target IP and port
LOG_DIR = "/ssh"
INTERFACE = ""
IP = ""
PORT = 22
PROCESS = ""

FUZZ_ALGORITHMS = True


options = {
        "proc_name": PROCESS, 
        "start_commands": [f"/etc/init.d/{PROCESS} start"],  
        "start_commands": [f"/etc/init.d/{PROCESS} start"]
}

log_file =  os.path.join(LOG_DIR, "FuzzingLog.txt")
logger = FuzzLoggerText(file_handle=open(log_file, 'w'))
logger_console = FuzzLoggerText()

target = Target(
    connection=SocketConnection(target_ip, ssh_port, proto='tcp'),
    procmon=procmonn
    )


def main():


    session = Session(target=target, fuzz_loggers=[logger, logger_console])

    tcpdump_start = ['tcpdump','-i', INTERFACE, 'host', IP ,'and port', PORT ,'-w', os.path.join(LOG_DIR, "session.pcap")]
    tcpdump_process = subprocess.Popen(tcpdump_start)

   
    ###############################################################################################################
    # Modified #
    s_initialize(name="ProtocolVersionExchange")
    s_static("SSH-")
    s_string("2.0",name="protoversion" ,fuzzable=True)
    s_static("-")
    s_string("A", name="softwareversion",fuzzable=True)
    s_delim("_",fuzzable=True)
    s_float(1.1, s_format=".1f",fuzzable=True)
    s_static("p")
    s_int(1,fuzzable=True)
    s_static(" ")
    s_string("SYSTEM", name="comments",fuzzable=True)
    s_static("\r\n")

    ###############################################################################################################

    s_initialize("KeyExchangeInitClient")
    # Modified #
    s_size("KeyExchangeInit", endian=">", fuzzable=False)
    if s_block_start("KeyExchangeInit"):
        s_static("\x07", name="padding length")
        s_static("\x14", name="Message Code")  # Key Exchange Init (20)
        s_bytes(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", size=32, name="Cookie", fuzzable = True)  # Cookie

        # Key Exchange Algorithms
        s_size("kex_algorithms", endian=">", fuzzable=False)
        s_string("aaaa,bbbbbb,cccccccc", name="kex_algorithms", fuzzable = FUZZ_ALGORITHMS)

        # Server Host Key Algorithms
        s_size("server_host_key_algorithms", endian=">", fuzzable=False)
        s_string("aaaaaa,bbbbbbbb", name="server_host_key_algorithms",fuzzable = FUZZ_ALGORITHMS)

        # Encryption Algorithms (client to server, then server to client)
        s_size("encryption_algorithms_client_to_server", endian=">", fuzzable=False)
        s_string("aaaaaaaaaaaa,bbbbbbbbbbbbbbb,ccccccccccccccc", name="encryption_algorithms_client_to_server",fuzzable = FUZZ_ALGORITHMS)
    
        s_size("encryption_algorithms_server_to_client", endian=">", fuzzable=False)
        s_string("aaaaaaaaaaaa,bbbbbbbbbbbbbbb,ccccccccccccccc", name="encryption_algorithms_server_to_client",fuzzable = FUZZ_ALGORITHMS)

        # MAC Algorithms
        s_size("mac_algorithms_client_to_server", endian=">", fuzzable=False)
        s_string("aaaaaaaaaa,bbbbbbbbbbbb", name="mac_algorithms_client_to_server",fuzzable = FUZZ_ALGORITHMS)
        s_size("mac_algorithms_server_to_client", endian=">", fuzzable=False)
        s_string("aaaaaaaaaa,bbbbbbbbbbbb", name="mac_algorithms_server_to_client",fuzzable = FUZZ_ALGORITHMS)

        # Compression Algorithms
        s_size("compression_algorithms_client_to_server", endian=">", fuzzable=False)
        s_string("aaaaaa", name="compression_algorithms_client_to_server",fuzzable = FUZZ_ALGORITHMS)
        s_size("compression_algorithms_server_to_client", endian=">", fuzzable=False)
        s_string("bbbbbbbbbb", name="compression_algorithms_server_to_client",fuzzable = FUZZ_ALGORITHMS)

        # Languages
        s_size("languages_client_to_server", endian=">", fuzzable=False)
        s_string("", name="languages_client_to_server",fuzzable = FUZZ_ALGORITHMS)
        s_size("languages_server_to_client", endian=">", fuzzable=False)
        s_string("", name="languages_server_to_client",fuzzable = FUZZ_ALGORITHMS)

        # KEX, Padding and Reserved
        s_static("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

    s_block_end()

    ###############################################################################################################
    s_initialize("DiffieHellmanKeyExchangeInitClient")
    s_size("DiffieHellmanKeyExchangeInit", endian=">",fuzzable=False)
    if s_block_start("DiffieHellmanKeyExchangeInit"):
        s_static("\x06")  # Padding length: 6 bytes
        s_static("\x1e")  # Message Code for ECDH Key Exchange Init (30)
    
        # ECDH public key length and value
        s_size("diffiehellmankey", endian=">", fuzzable=False) # ECDH public key length 
        s_bytes(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", name="diffiehellmankey") # ECDH public key value
    
        s_static("\x00\x00\x00\x00\x00\x00")  # 6 bytes of padding
    s_block_end()

    ###############################################################################################################
    
    session.connect(s_get("ProtocolVersionExchange"))
    session.connect(s_get("ProtocolVersionExchange"), s_get("KeyExchangeInitClient"))
    session.connect(s_get("KeyExchangeInitClient"),s_get("DiffieHellmanKeyExchangeInitClient"))
        
    try:
        session.fuzz(max_depth = 1)
    except KeyboardInterrupt:
        print("Ctrl+C pressed, stopping fuzzing and stopping tcpdump.")
    finally:
        tcpdump_process.send_signal(signal.SIGINT)
        tcpdump_process.wait()
    
   
if __name__ == "__main__":
    main()
