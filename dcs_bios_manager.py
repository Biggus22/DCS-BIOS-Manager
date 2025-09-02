# -*- coding: utf-8 -*-
#added support for RS485 masters
import socket
import struct
import serial
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox
from configparser import ConfigParser
import os
import sys
import atexit
import random
import serial.tools.list_ports

# Optional libraries for system tray functionality
try:
    from pystray import Icon as pystray_Icon, Menu as pystray_Menu, MenuItem as pystray_MenuItem
    from PIL import Image, ImageDraw, ImageFont

    HAS_PYSTRAY = True
except ImportError:
    HAS_PYSTRAY = False
    # pystray or Pillow not found. System tray functionality will be disabled.

# Optional libraries for Windows-specific functionality
try:
    import winreg

    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False
    # winreg not found. 'Start with Windows' functionality will be disabled.

try:
    import serial.tools.list_ports

    HAS_LIST_PORTS = True
except ImportError:
    HAS_LIST_PORTS = False
    # pyserial.tools.list_ports not found. COM port detection will be limited.


class DCSBIOSSerialManager(tk.Tk):
    """
    A standalone application for managing DCS-BIOS serial communication.

    This application provides a graphical user interface (GUI) to configure and
    manage multiple serial devices, bridging UDP data from DCS-BIOS to the
    connected serial ports. Now includes RS485 master support.
    """

    # Dictionary of common microcontrollers with their default baud rates.
    MICROCONTROLLER_BAUDRATES = {
        "Arduino Uno": 250000,
        "Arduino Nano": 250000,
        "Arduino Mega": 250000,
        "Arduino Mega (RS485 Master)": 115200,  # RS485 typically uses lower baud rates
        "Raspberry Pi Pico (RP2040)": 115200,
        "Raspberry Pi Pico 2 (RP2350)": 115200,
        "Arduino Pro Micro": 115200,
        "Arduino Leonardo": 115200,
        "ESP32": 115200,
    }

    # === CONFIGURATION ===
    UDP_IP = "0.0.0.0"
    UDP_PORT = 5010
    UDP_DEST_IP = "127.0.0.1"
    UDP_DEST_PORT = 7778
    MULTICAST_GROUP = "239.255.50.10"

    # Registry key for 'Start with Windows' functionality
    RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
    APP_NAME = "DCSBIOSSerialManager"

    # Threshold for mismatched commands before a warning is triggered
    MISMATCH_THRESHOLD = 3

    def __init__(self):
        """Initializes the main application window and its components."""
        super().__init__()
        self.title("DCS BIOS Serial Manager")
        try:
            self.geometry("800x600")
        except tk.TclError:
            self.log_message("Warning: Failed to set window geometry.")

        self.style = ttk.Style(self)
        self.set_windows_theme()

        self.config_file = 'config.ini'
        self.log_file = 'DCSBIOS_serial_log.txt'
        self.devices = []
        self.serial_connections = {}
        self.serial_to_udp_threads = {}
        self.stop_threads = threading.Event()

        # Initialize all control variables at the start
        self.logging_enabled = tk.BooleanVar(value=False)
        self.minimize_to_tray_var = tk.BooleanVar(value=True)
        self.start_with_windows_var = tk.BooleanVar(value=False)
        self.start_minimized_var = tk.BooleanVar(value=False)

        self.tray_icon = None

        self.load_config()
        self.create_widgets()

        # Check if we should start minimized
        if self.start_minimized_var.get() and HAS_PYSTRAY:
            self.withdraw()
            self.create_tray_icon()

        # Set up atexit handler for clean exit
        atexit.register(self.on_exit)

        # Start UDP listener thread
        self.udp_sock = None
        self.setup_udp_socket()
        self.udp_thread = threading.Thread(target=self.udp_to_serial, daemon=True)
        self.udp_thread.start()

    def set_windows_theme(self):
        """Sets a theme that attempts to match the Windows theme."""
        themes = self.style.theme_names()
        if 'azure' in themes:
            self.style.theme_use('azure')
        elif 'clam' in themes:
            self.style.theme_use('clam')
        elif 'winnative' in themes:
            self.style.theme_use('winnative')

    def create_widgets(self):
        """Creates and places all the GUI elements in the window."""
        self.main_frame = ttk.Frame(self, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = ttk.Label(self.main_frame, text="DCS BIOS Serial Manager", font=("Helvetica", 16, "bold"))
        title_label.pack(pady=(0, 10))

        # Device management frame
        device_frame = ttk.LabelFrame(self.main_frame, text="Device Profiles", padding="10")
        device_frame.pack(fill=tk.X, padx=5, pady=5)

        self.device_list_frame = ttk.Frame(device_frame)
        self.device_list_frame.pack(fill=tk.BOTH, expand=True)
        self.update_device_list_display()

        add_device_button = ttk.Button(device_frame, text="Add New Device", command=self.open_add_device_window)
        add_device_button.pack(pady=(5, 0))

        # Options frame
        options_frame = ttk.LabelFrame(self.main_frame, text="Options", padding="10")
        options_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Checkbutton(options_frame, text="Log to external file", variable=self.logging_enabled,
                        command=self.toggle_logging).pack(anchor=tk.W)

        # 'Start with Windows' checkbox
        ttk.Checkbutton(options_frame, text="Start with Windows", variable=self.start_with_windows_var,
                        command=self.toggle_start_with_windows,
                        state=tk.NORMAL if HAS_WINREG else tk.DISABLED).pack(anchor=tk.W)

        # 'Minimize to system tray' checkbox
        ttk.Checkbutton(options_frame, text="Minimize to system tray on close", variable=self.minimize_to_tray_var,
                        command=self.save_config,
                        state=tk.NORMAL if HAS_PYSTRAY else tk.DISABLED).pack(anchor=tk.W)

        # 'Start minimized' checkbox
        ttk.Checkbutton(options_frame, text="Start minimized to tray", variable=self.start_minimized_var,
                        command=self.save_config,
                        state=tk.NORMAL if HAS_PYSTRAY else tk.DISABLED).pack(anchor=tk.W)

        # Log frame
        log_frame = ttk.LabelFrame(self.main_frame, text="Application Log", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        log_scrollbar = ttk.Scrollbar(log_frame)
        log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.log_text = tk.Text(log_frame, wrap=tk.WORD, state=tk.DISABLED, yscrollcommand=log_scrollbar.set)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        log_scrollbar.config(command=self.log_text.yview)

        # Override the close button handler
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def update_device_list_display(self):
        """Clears and redraws the list of devices in the GUI."""
        for widget in self.device_list_frame.winfo_children():
            widget.destroy()

        if not self.devices:
            ttk.Label(self.device_list_frame, text="No devices configured.").pack(pady=10)
            return

        for i, device in enumerate(self.devices):
            device_frame = ttk.Frame(self.device_list_frame, padding="5")
            device_frame.pack(fill=tk.X, pady=2)

            # Use an internal variable for the checkbox state to manage it better
            device['enabled_var'] = tk.BooleanVar(value=device.get('enabled', False))
            device['enabled_var'].trace_add('write', lambda name, index, mode, d=device: self.toggle_device_status(d))

            ttk.Checkbutton(device_frame, variable=device['enabled_var'], command=None).pack(side=tk.LEFT)

            rs485_indicator = " (RS485 Master)" if device.get('is_rs485', False) else ""
            info_label = f"{device['name']}{rs485_indicator} - COM Port: {device.get('com_port', 'N/A')}, Baud: {device['baud_rate']}"
            ttk.Label(device_frame, text=info_label).pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

            edit_button = ttk.Button(device_frame, text="Edit", width=6,
                                     command=lambda d=device: self.open_add_device_window(d))
            edit_button.pack(side=tk.RIGHT, padx=2)

            delete_button = ttk.Button(device_frame, text="Delete", width=6,
                                       command=lambda d=device: self.delete_device(d))
            delete_button.pack(side=tk.RIGHT)

            if device['enabled_var'].get():
                self.start_device_threads(device)
            else:
                self.stop_device_threads(device)

    def get_available_com_ports(self):
        """Returns a list of available COM ports and their full info objects."""
        if not HAS_LIST_PORTS:
            return [], []

        ports = serial.tools.list_ports.comports()
        return [port.device for port in ports], ports

    def get_unused_com_ports(self):
        """Returns a list of available COM ports that are not in use by a configured device."""
        available_ports, _ = self.get_available_com_ports()
        used_ports = {d.get('com_port') for d in self.devices if d.get('com_port')}
        return sorted(list(set(available_ports) - used_ports))

    def open_add_device_window(self, device_to_edit=None):
        """Opens a new window to add or edit a device profile with RS485 support."""
        add_window = tk.Toplevel(self)
        add_window.title("Add/Edit Device")
        add_window.geometry("450x550")  # Increased height for RS485 options
        add_window.grab_set()

        is_editing = device_to_edit is not None

        # Variables for the fields
        name_var = tk.StringVar(value=device_to_edit.get('name', '') if is_editing else '')
        com_port_var = tk.StringVar(value=device_to_edit.get('com_port', '') if is_editing else '')
        baud_rate_var = tk.IntVar(value=device_to_edit.get('baud_rate', 115200) if is_editing else 115200)
        is_rs485_var = tk.BooleanVar(value=device_to_edit.get('is_rs485', False) if is_editing else False)
        rs485_delay_var = tk.DoubleVar(value=device_to_edit.get('rs485_delay', 0.01) if is_editing else 0.01)

        temp_commands = device_to_edit.get('commands', set()) if is_editing else set()

        # Frame for form elements
        form_frame = ttk.Frame(add_window, padding="10")
        form_frame.pack(fill=tk.BOTH, expand=True)

        # Microcontroller type dropdown
        ttk.Label(form_frame, text="Microcontroller Type:").pack(anchor=tk.W)
        mc_options = list(self.MICROCONTROLLER_BAUDRATES.keys()) + ["Custom"]

        default_mc = random.choice(
            list(self.MICROCONTROLLER_BAUDRATES.keys())) if self.MICROCONTROLLER_BAUDRATES else "Custom"
        mc_var = tk.StringVar(value=device_to_edit.get('name', '') if is_editing else default_mc)

        mc_dropdown = ttk.Combobox(form_frame, textvariable=mc_var, values=mc_options, state="readonly")
        mc_dropdown.pack(fill=tk.X, pady=(0, 10))

        def on_mc_change(event):
            self.update_baud_rate(mc_var.get(), baud_rate_var)
            # Auto-detect RS485 from name
            is_rs485_var.set('RS485 Master' in mc_var.get())

        mc_dropdown.bind("<<ComboboxSelected>>", on_mc_change)

        if not is_editing:
            self.update_baud_rate(default_mc, baud_rate_var)
            # Auto-detect RS485 from initial selection
            is_rs485_var.set('RS485 Master' in default_mc)

        # Device Name
        ttk.Label(form_frame, text="Device Name:").pack(anchor=tk.W)
        ttk.Entry(form_frame, textvariable=name_var).pack(fill=tk.X, pady=(0, 10))

        # COM Port Dropdown
        ttk.Label(form_frame, text="COM Port:").pack(anchor=tk.W)
        all_ports, _ = self.get_available_com_ports()

        # Add the current port if editing and it's not in the list
        if is_editing and device_to_edit['com_port'] not in all_ports:
            all_ports.insert(0, device_to_edit['com_port'])

        com_port_combobox = ttk.Combobox(form_frame, textvariable=com_port_var, values=sorted(all_ports),
                                         state="readonly")
        com_port_combobox.pack(fill=tk.X, pady=(0, 10))
        if is_editing and device_to_edit['com_port'] in all_ports:
            com_port_combobox.set(device_to_edit['com_port'])

        # Baud Rate
        ttk.Label(form_frame, text="Baud Rate:").pack(anchor=tk.W)
        baud_entry = ttk.Entry(form_frame, textvariable=baud_rate_var)
        baud_entry.pack(fill=tk.X, pady=(0, 10))

        # RS485 Configuration Frame
        rs485_frame = ttk.LabelFrame(form_frame, text="RS485 Configuration", padding="5")
        rs485_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Checkbutton(rs485_frame, text="This device is an RS485 Master",
                        variable=is_rs485_var).pack(anchor=tk.W)

        ttk.Label(rs485_frame, text="RS485 Transmission Delay (seconds):").pack(anchor=tk.W)
        ttk.Entry(rs485_frame, textvariable=rs485_delay_var, width=10).pack(anchor=tk.W, pady=(0, 5))

        ttk.Label(rs485_frame, text="Recommended: 0.01-0.02 for RS485",
                  font=("Helvetica", 8)).pack(anchor=tk.W)

        # Record Inputs button
        record_button = ttk.Button(form_frame, text="Record Inputs",
                                   command=lambda: self.open_command_fingerprint_window(add_window, com_port_var.get(),
                                                                                        baud_rate_var.get(),
                                                                                        temp_commands))
        record_button.pack(pady=(10, 0))

        def save_device():
            name = name_var.get().strip()
            com_port = com_port_var.get().strip().upper()
            try:
                baud_rate = int(baud_rate_var.get())
                rs485_delay = float(rs485_delay_var.get())
            except ValueError:
                messagebox.showerror("Error", "Baud rate must be a number and RS485 delay must be a decimal.",
                                     parent=add_window)
                return

            if not name or not com_port:
                messagebox.showerror("Error", "Device Name and COM Port are required.", parent=add_window)
                return

            if not temp_commands:
                if not messagebox.askyesno("No Inputs Recorded",
                                           "You have not recorded any inputs for this device. This may cause issues with automatic port detection.\n\nDo you want to save anyway?"):
                    return

            new_device = {
                'name': name,
                'com_port': com_port,
                'baud_rate': baud_rate,
                'enabled': device_to_edit.get('enabled', False) if is_editing else False,
                'commands': temp_commands,
                'is_rs485': is_rs485_var.get(),
                'rs485_delay': rs485_delay
            }

            if is_editing:
                self.devices[:] = [d for d in self.devices if d is not device_to_edit]

            self.devices.append(new_device)
            self.save_config()
            self.update_device_list_display()
            add_window.destroy()

        # The save button is now wider and has more padding
        ttk.Button(form_frame, text="Save" if not is_editing else "Update", command=save_device, width=20).pack(
            pady=(10, 20))

    def open_command_fingerprint_window(self, parent_window, com_port, baud_rate, commands_set):
        """Opens a new window to record a device's inputs."""
        if not com_port or not baud_rate:
            messagebox.showerror("Error", "Please select a COM port and baud rate first.")
            return

        # Store a list of devices that are currently enabled
        was_enabled = [device for device in self.devices if device.get('enabled', False)]
        self.pause_all_active_devices()

        fingerprint_window = tk.Toplevel(parent_window)
        fingerprint_window.title(f"Recording Inputs on {com_port}")
        # Increased height for better log visibility
        fingerprint_window.geometry("400x400")
        fingerprint_window.grab_set()

        recording = threading.Event()
        commands_thread = None

        main_frame = ttk.Frame(fingerprint_window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        info_label = ttk.Label(main_frame, text="Press all digital inputs on your device. Click 'Stop' when finished.")
        info_label.pack(pady=(0, 10))

        log_text = tk.Text(main_frame, wrap=tk.WORD, state=tk.DISABLED, height=10)
        log_text.pack(fill=tk.BOTH, expand=True)

        def update_log(message):
            log_text.configure(state=tk.NORMAL)
            log_text.insert(tk.END, message + "\n")
            log_text.configure(state=tk.DISABLED)
            log_text.see(tk.END)

        def start_recording():
            nonlocal commands_thread
            try:
                ser = serial.Serial(com_port, baud_rate, timeout=0.1)
                commands_set.clear()
                recording.clear()
                update_log("Starting recording...")

                start_button.configure(text="Stop", command=stop_recording)

                commands_thread = threading.Thread(target=self.listen_for_commands,
                                                   args=(ser, recording, commands_set, update_log), daemon=True)
                commands_thread.start()
            except serial.SerialException as e:
                messagebox.showerror("Serial Error", f"Could not open {com_port}: {e}", parent=fingerprint_window)
                fingerprint_window.destroy()

        def stop_recording():
            nonlocal commands_thread
            recording.set()
            if commands_thread and commands_thread.is_alive():
                commands_thread.join(timeout=1)
            update_log("Recording stopped. Found inputs:")
            for cmd in sorted(list(commands_set)):
                update_log(f"- {cmd}")
            start_button.configure(text="Start Recording", command=start_recording)

        def on_close():
            recording.set()
            if commands_thread and commands_thread.is_alive():
                commands_thread.join(timeout=1)
            # Resume devices that were active
            self.resume_paused_devices(was_enabled)
            fingerprint_window.destroy()

        # The start button is now wider
        start_button = ttk.Button(main_frame, text="Start Recording", command=start_recording, width=20)
        start_button.pack(pady=(10, 0))

        fingerprint_window.protocol("WM_DELETE_WINDOW", on_close)

    def pause_all_active_devices(self):
        """Temporarily stops all active device threads and closes their connections."""
        self.log_message("Pausing all active devices for input recording...")
        # Iterate over a copy of the list to avoid issues with modification during iteration
        for device in list(self.devices):
            if device.get('enabled', False):
                device['enabled'] = False
                device['enabled_var'].set(False)  # Update the UI checkbox
                self.stop_device_threads(device)

    def resume_paused_devices(self, was_enabled_list):
        """Restarts the devices that were paused for input recording."""
        self.log_message("Resuming previously active devices...")
        # Use a list of device objects to re-enable them
        for device in was_enabled_list:
            device['enabled'] = True
            device['enabled_var'].set(True)  # Update the UI checkbox

        # A full update of the display will trigger the threads to restart
        self.update_device_list_display()
        self.save_config()

    def listen_for_commands(self, ser, stop_event, commands_set, log_callback):
        """
        Thread function to read from a serial port and capture unique commands.
        Used for the input fingerprinting feature.
        """
        try:
            while not stop_event.is_set():
                if ser.in_waiting > 0:
                    line = ser.readline().decode('utf-8', errors='ignore').strip()
                    if line:
                        command = line.split(' ')[0]
                        if command and command not in commands_set:
                            commands_set.add(command)
                            log_callback(f"Found new input: {command}")
                time.sleep(0.01)
        except Exception as e:
            log_callback(f"[ERROR] During recording: {e}")
        finally:
            if ser and ser.is_open:
                ser.close()

    def update_baud_rate(self, selected_mc, baud_rate_var):
        """Updates the baud rate entry based on the selected microcontroller."""
        if selected_mc != "Custom":
            baud_rate_var.set(self.MICROCONTROLLER_BAUDRATES.get(selected_mc, 115200))
        else:
            baud_rate_var.set(115200)  # Default for Custom

    def toggle_device_status(self, device):
        """Toggles the enabled/disabled status of a device."""
        is_enabled = device['enabled_var'].get()
        device['enabled'] = is_enabled

        if is_enabled:
            self.start_device_threads(device)
        else:
            self.stop_device_threads(device)

        self.save_config()

    def delete_device(self, device_to_delete):
        """Deletes a device profile."""
        if messagebox.askyesno("Delete Device", f"Are you sure you want to delete '{device_to_delete['name']}'?"):
            self.stop_device_threads(device_to_delete)
            self.devices.remove(device_to_delete)
            self.save_config()
            self.update_device_list_display()

    def setup_udp_socket(self):
        """Sets up the UDP socket for receiving DCS-BIOS data."""
        try:
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp_sock.bind((self.UDP_IP, self.UDP_PORT))

            # Join multicast group
            mreq = struct.pack("=4sl", socket.inet_aton(self.MULTICAST_GROUP), socket.INADDR_ANY)
            self.udp_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            self.log_message("UDP listener started.")
        except Exception as e:
            self.log_message(f"[UDP SETUP ERROR] {e}")
            self.udp_sock = None

    def start_device_threads(self, device):
        """Starts the serial-to-UDP thread for a specific device."""
        if device.get('com_port') in self.serial_connections:
            return  # Already running

        # Initialize mismatch counter
        device['mismatch_count'] = 0

        try:
            ser = serial.Serial(device['com_port'], device['baud_rate'], timeout=0.1)
            self.serial_connections[device['com_port']] = ser
            rs485_info = " (RS485 Master)" if device.get('is_rs485', False) else ""
            self.log_message(
                f"Connected to serial: {device['name']}{rs485_info} on {device['com_port']} at {device['baud_rate']} baud")

            stop_event = threading.Event()
            self.serial_to_udp_threads[device['com_port']] = threading.Thread(
                target=self.serial_to_udp, args=(ser, stop_event, device), daemon=True
            )
            self.serial_to_udp_threads[device['com_port']].stop_event = stop_event
            self.serial_to_udp_threads[device['com_port']].start()

        except serial.SerialException as e:
            self.log_message(f"[SERIAL ERROR] Failed to connect to {device['com_port']}: {e}")
            if "PermissionError" in str(e):
                messagebox.showerror("Port in Use",
                                     f"Could not open port {device['com_port']}. It may be in use by another application (e.g., Arduino IDE). "
                                     f"Please close the other application and try again.")

            # Disable the device in the UI and config
            device['enabled_var'].set(False)
            device['enabled'] = False
            self.save_config()
            self.update_device_list_display()

    def stop_device_threads(self, device):
        """Stops the serial-to-UDP thread for a specific device."""
        com_port = device.get('com_port')
        if not com_port or com_port not in self.serial_to_udp_threads:
            return

        self.log_message(f"Stopping thread for {device['name']}...")
        self.serial_to_udp_threads[com_port].stop_event.set()
        # Wait for the thread to join
        if self.serial_to_udp_threads[com_port].is_alive():
            self.serial_to_udp_threads[com_port].join(timeout=1)
        del self.serial_to_udp_threads[com_port]

        if com_port in self.serial_connections:
            try:
                self.serial_connections[com_port].close()
                self.log_message(f"Closed serial connection for {device['name']}")
            except Exception as e:
                self.log_message(f"[SERIAL CLOSE ERROR] {e}")
            del self.serial_connections[com_port]

    def serial_to_udp(self, ser, stop_event, device_info):
        """
        Thread function to read from a serial port and send to UDP with RS485 support.
        Also monitors for mismatched commands.
        """
        device_name = device_info['name']
        known_commands = device_info.get('commands', set())
        is_rs485 = device_info.get('is_rs485', False)

        # RS485 master needs different handling
        if is_rs485:
            read_timeout = 0.5  # Longer timeout for RS485 responses
            ser.timeout = read_timeout

        while not stop_event.is_set():
            try:
                if ser and ser.is_open:
                    if is_rs485:
                        # For RS485, wait for complete responses
                        if ser.in_waiting:
                            # Read all available data at once for RS485
                            data = ser.read(ser.in_waiting)
                            if data:
                                clean_data = data.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
                                decoded_data = clean_data.decode(errors='ignore')

                                self.log_message(f"[{device_name} -> UDP] {decoded_data}", to_file=True)
                                if self.udp_sock:
                                    self.udp_sock.sendto(clean_data, (self.UDP_DEST_IP, self.UDP_DEST_PORT))

                            # Give RS485 slaves time to respond
                            time.sleep(0.01)
                        else:
                            time.sleep(0.01)  # Polling interval for RS485
                    else:
                        # Original logic for non-RS485 devices
                        if ser.in_waiting:
                            data = ser.read(ser.in_waiting)
                            if data:
                                clean_data = data.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
                                decoded_data = clean_data.decode(errors='ignore')

                                # Command mismatch detection
                                if known_commands:
                                    lines = decoded_data.strip().split('\n')
                                    for line in lines:
                                        if line:
                                            command_name = line.split(' ')[0]
                                            if command_name not in known_commands:
                                                device_info['mismatch_count'] += 1
                                                if device_info['mismatch_count'] >= self.MISMATCH_THRESHOLD:
                                                    # Find likely candidate
                                                    likely_device = self.find_likely_device_by_command(command_name)
                                                    if likely_device:
                                                        self.log_message(
                                                            f"[WARNING] Mismatched commands detected on port {ser.port} for device '{device_name}'. "
                                                            f"This may be '{likely_device['name']}' on a different COM port."
                                                        )
                                                    device_info['mismatch_count'] = 0  # Reset to prevent spam

                                self.log_message(f"[{device_name} -> UDP] {decoded_data}", to_file=True)
                                if self.udp_sock:
                                    self.udp_sock.sendto(clean_data, (self.UDP_DEST_IP, self.UDP_DEST_PORT))
                        else:
                            time.sleep(0.005)

            except (serial.SerialException, PermissionError) as e:
                self.log_message(f"[{device_name} SERIAL READ ERROR] {e}. Attempting to reopen serial port...")
                try:
                    ser.close()
                except Exception:
                    pass
                time.sleep(3)
                try:
                    ser = serial.Serial(ser.port, ser.baudrate, timeout=0.1)
                    self.serial_connections[ser.port] = ser
                    self.log_message(f"[{device_name} SERIAL RECOVERY] Reconnected to {ser.port}")
                except Exception as e_recover:
                    self.log_message(f"[{device_name} SERIAL RECOVERY FAILED] {e_recover}")
                    time.sleep(5)
            except Exception as e:
                self.log_message(f"[{device_name} UNEXPECTED SERIAL ERROR] {e}")
                time.sleep(5)

    def find_likely_device_by_command(self, command):
        """Finds a device profile that contains the given command."""
        for device in self.devices:
            if command in device.get('commands', set()):
                return device
        return None

    def is_dcsbios_export_packet(self, data):
        """Checks if the data is a valid DCS-BIOS export packet."""
        return len(data) >= 2 and data[0] == 0x55 and data[1] == 0x55

    def udp_to_serial(self):
        """Thread function to listen for UDP packets and forward to active serial ports with RS485 support."""
        while not self.stop_threads.is_set():
            try:
                if not self.udp_sock:
                    time.sleep(1)
                    continue

                data, addr = self.udp_sock.recvfrom(1024)

                # Only forward if it's a DCS-BIOS export frame
                if not self.is_dcsbios_export_packet(data):
                    continue

                for com_port, ser_conn in self.serial_connections.items():
                    try:
                        if ser_conn and ser_conn.is_open:
                            # Find the device info for this port
                            device_info = None
                            for device in self.devices:
                                if device.get('com_port') == com_port and device.get('enabled', False):
                                    device_info = device
                                    break

                            # Check if this is an RS485 master device
                            is_rs485_master = (device_info and device_info.get('is_rs485', False))

                            if is_rs485_master:
                                # RS485 master needs special timing
                                ser_conn.write(data)
                                ser_conn.flush()  # Ensure data is transmitted immediately
                                rs485_delay = device_info.get('rs485_delay', 0.01)
                                time.sleep(rs485_delay)  # Configurable delay for RS485 master-slave timing
                            else:
                                # Normal serial communication
                                ser_conn.write(data)
                                time.sleep(0.001)

                    except Exception as e:
                        self.log_message(f"[UDP -> {com_port} WRITE ERROR] {e}")

            except Exception as e:
                self.log_message(f"[UDP RECEPTION ERROR] {e}")
                time.sleep(1)

    def toggle_logging(self):
        """Saves the logging configuration."""
        self.save_config()
        self.log_message(f"Logging {'enabled' if self.logging_enabled.get() else 'disabled'}.")

    def log_message(self, message, to_file=False):
        """Logs a message to the GUI log and optionally to a file, without printing to the console."""
        full_message = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}"

        # Update GUI log
        try:
            self.log_text.configure(state=tk.NORMAL)
            self.log_text.insert(tk.END, full_message + "\n")
            self.log_text.configure(state=tk.DISABLED)
            self.log_text.see(tk.END)  # Auto-scroll
        except AttributeError:
            # Log widget not yet created, so we can't write to it.
            pass

        if self.logging_enabled.get() and to_file:
            try:
                with open(self.log_file, 'a') as f:
                    f.write(full_message + "\n")
            except Exception as e:
                self.log_message(f"[LOG FILE ERROR] {e}")

    def load_config(self):
        """Loads configuration from the config.ini file with RS485 support."""
        config = ConfigParser()
        if os.path.exists(self.config_file):
            config.read(self.config_file)
            self.logging_enabled.set(config.getboolean('Settings', 'log_to_file', fallback=False))
            self.minimize_to_tray_var.set(config.getboolean('Settings', 'minimize_to_tray', fallback=True))
            self.start_with_windows_var.set(config.getboolean('Settings', 'start_with_windows', fallback=False))
            self.start_minimized_var.set(config.getboolean('Settings', 'start_minimized', fallback=False))

            self.devices = []
            for section in config.sections():
                if section.startswith('Device:'):
                    device = dict(config.items(section))
                    device['baud_rate'] = int(device['baud_rate'])
                    device['enabled'] = config.getboolean(section, 'enabled', fallback=False)
                    device['is_rs485'] = config.getboolean(section, 'is_rs485', fallback=False)
                    device['rs485_delay'] = config.getfloat(section, 'rs485_delay', fallback=0.01)
                    # Load commands as a set
                    commands_str = device.get('commands', '')
                    device['commands'] = set(commands_str.split(',')) if commands_str else set()
                    self.devices.append(device)
        else:
            self.log_message("config.ini not found. Creating default config.")
            self.save_config()

    def save_config(self):
        """Saves the current configuration to the config.ini file with RS485 support."""
        config = ConfigParser()

        config['Settings'] = {
            'log_to_file': str(self.logging_enabled.get()),
            'minimize_to_tray': str(self.minimize_to_tray_var.get()),
            'start_with_windows': str(self.start_with_windows_var.get()),
            'start_minimized': str(self.start_minimized_var.get())
        }

        for i, device in enumerate(self.devices):
            section_name = f"Device:{i}"
            commands_str = ','.join(device.get('commands', []))
            config[section_name] = {
                'name': device['name'],
                'com_port': device.get('com_port', ''),
                'baud_rate': str(device['baud_rate']),
                'enabled': str(device['enabled_var'].get() if 'enabled_var' in device else device['enabled']),
                'commands': commands_str,
                'is_rs485': str(device.get('is_rs485', False)),
                'rs485_delay': str(device.get('rs485_delay', 0.01))
            }

        try:
            with open(self.config_file, 'w') as configfile:
                config.write(configfile)
        except Exception as e:
            self.log_message(f"[CONFIG SAVE ERROR] {e}")

    def toggle_start_with_windows(self):
        """Adds or removes the application from the Windows startup registry."""
        if not HAS_WINREG:
            self.log_message("'Start with Windows' functionality is not available on this OS.")
            return

        self.save_config()

        app_path = os.path.abspath(sys.argv[0])

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.RUN_KEY, 0, winreg.KEY_WRITE) as key:
                if self.start_with_windows_var.get():
                    winreg.SetValueEx(key, self.APP_NAME, 0, winreg.REG_SZ, f'"{app_path}"')
                    self.log_message("Added to Windows startup.")
                else:
                    try:
                        winreg.DeleteValue(key, self.APP_NAME)
                        self.log_message("Removed from Windows startup.")
                    except FileNotFoundError:
                        self.log_message("Application was not in Windows startup list.")
        except Exception as e:
            messagebox.showerror("Registry Error", f"Failed to modify Windows startup registry: {e}")
            self.start_with_windows_var.set(not self.start_with_windows_var.get())  # Revert checkbox state
            self.save_config()
            self.log_message(f"Registry access failed: {e}")

    def on_close(self):
        """Handles the window close event, minimizing to tray if configured."""
        if HAS_PYSTRAY and self.minimize_to_tray_var.get():
            self.withdraw()
            self.create_tray_icon()
        else:
            self.quit_app()

    def quit_app(self):
        """Exits the application gracefully."""
        self.log_message("Exiting application...")
        self.stop_threads.set()
        for device in self.devices:
            self.stop_device_threads(device)
        self.destroy()
        if self.tray_icon:
            self.tray_icon.stop()

    def on_exit(self):
        """Ensures all resources are released on application exit."""
        self.stop_threads.set()
        for com_port, ser_conn in self.serial_connections.items():
            try:
                ser_conn.close()
            except Exception:
                pass

    def create_tray_icon(self):
        """Creates and manages the system tray icon."""
        if not HAS_PYSTRAY:
            return

        if self.tray_icon:
            self.tray_icon.stop()

        width, height = 64, 64
        image = Image.new('RGB', (width, height), '#0078d7')
        draw = ImageDraw.Draw(image)
        try:
            font = ImageFont.truetype("arial.ttf", 40)
            draw.text((12, 5), "D", font=font, fill='white')
        except IOError:
            draw.text((12, 5), "D", fill='white')

        menu = pystray_Menu(
            pystray_MenuItem("Show", self.show_window, default=True, visible=True),
            pystray_MenuItem("Exit", self.quit_app)
        )
        self.tray_icon = pystray_Icon("DCS BIOS Serial Manager", image, "DCS BIOS Serial Manager", menu)
        self.tray_icon.run_detached()
        self.log_message("Application minimized to system tray.")

    def show_window(self):
        """Restores the main window from the system tray."""
        self.deiconify()
        if self.tray_icon:
            self.tray_icon.stop()
            self.tray_icon = None


if __name__ == '__main__':
    root = DCSBIOSSerialManager()
    try:
        root.mainloop()
    finally:
        root.on_exit()