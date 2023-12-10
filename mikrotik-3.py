import tkinter as tk
from tkinter import ttk
from tkinter import simpledialog
import socket
import ipaddress
import paramiko
import time

class MikrotikGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("MikroTik Winbox Simulator")

        # Attributes initialization
        self.ssh_client = None  
        self.safe_mode_activated = 0 

        root.configure(bg='lightblue')

        # Colors
        style = ttk.Style()
        style.configure('Blue.TButton', background='#6CB4EE')
        style.configure('Green.TButton', background='#17B169')
        style.configure('Yellowish.TButton', background = '#FECDA6')
        style.configure('Yellow.TButton', background='#FFD700')
        style.configure('Gray.TButton', background='#FF9130')

        # MikroTik Credentials
        self.lbl_entry("MikroTik IP:", row=0, col=0, entry_var="ip_input")
        self.lbl_entry("Username:", row=1, col=0, entry_var="user_input")
        self.lbl_entry("Password:", row=2, col=0, entry_var="passwd_input", show="*")
        ttk.Button(root, text="CONNECT", command=self.establish_connection, style='Green.TButton').grid(row=3, column=1, padx=10, pady=5, sticky="ew")

        # Buttons
        ttk.Button(root, text="Display IP Address(es)", command=self.display_information, style='Blue.TButton').grid(row=0, column=3, padx=10, pady=5, sticky="ew")
        ttk.Button(root, text="Alter IP Address", command=self.assign_new_ip_adrs, style='Blue.TButton').grid(row=1, column=3, padx=10, pady=5, sticky="ew")
        ttk.Button(root, text="Alter Identity", command=self.assign_new_identity, style='Blue.TButton').grid(row=2, column=3, padx=10, pady=5, sticky="ew")

        ttk.Button(root, text="Ping", command=self.send_ping, style='Yellowish.TButton').grid(row=6, column=1, padx=10, pady=5, sticky="ew")
        ttk.Button(root, text="Display Services and Ports", command=self.display_services, style='Yellowish.TButton').grid(row=7, column=1, padx=10, pady=5, sticky="ew")
        ttk.Button(root, text="Turn Wi-Fi off", command=self.disable_wifi, style='Yellowish.TButton').grid(row=8, column=1, padx=10, pady=5, sticky="ew")
        ttk.Button(root, text="Backup Configuration", command=self.conf_backup, style='Yellowish.TButton').grid(row=9, column=1, padx=10, pady=5, sticky="ew")
        
        ttk.Button(root, text="Display Interface(s)", command=self.display_interfaces, style='Yellow.TButton').grid(row=6, column=2, padx=10, pady=5, sticky="ew")
        ttk.Button(root, text="Alter the Port of a Service", command=self.assign_new_port, style='Yellow.TButton').grid(row=7, column=2, padx=10, pady=5, sticky="ew")
        ttk.Button(root, text="Reboot", command=self.reboot, style='Yellow.TButton').grid(row=8, column=2, padx=10, pady=5, sticky="ew")
        ttk.Button(root, text="Activate/Deactivate Safe Mode", command=self.activate_safe_mode, style='Yellow.TButton').grid(row=9, column=2, padx=10, pady=5, sticky="ew")

        ttk.Button(root, text="Connect to the Internet", command=self.connect_internet, style='Gray.TButton').grid(row=7, column=3, padx=10, pady=5, sticky="ew")
        ttk.Button(root, text="Disconnect from the Internet", command=self.disconnect_internet, style='Gray.TButton').grid(row=8, column=3, padx=10, pady=5, sticky="ew")

        # Display area
        self.text_display = tk.Text(root, height=15, width=85)
        self.text_display.grid(row=0, column=2, rowspan=4, padx=9, pady=9, sticky="nsew")

    def establish_connection(self):
        mikrotik_ip = self.ip_input.get()
        mikrotik_user = self.user_input.get()
        mikrotik_pass = self.passwd_input.get()

        # Check if the entered IP address is valid
        try:
            ipaddress.ip_address(mikrotik_ip)
        except ValueError:
            self.display_output("Invalid IP address format. Please enter a valid IP.")
            return

        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self.ssh_client.connect(mikrotik_ip, username=mikrotik_user, password=mikrotik_pass, look_for_keys=False)
            self.display_output("Connected successfully.")
        except paramiko.AuthenticationException:
            self.display_output("Authentication failed, check your credentials.")
        except paramiko.SSHException as e:
            self.display_output(f"Unable to establish SSH connection for: {str(e)}")


    def lbl_entry(self, label_text, row, col, entry_var, show=None):
        label = ttk.Label(self.root, text=label_text)
        label.grid(row=row, column=col, sticky="e")

        entry = ttk.Entry(self.root, show=show)
        entry.grid(row=row, column=col + 1)
        setattr(self, entry_var, entry)

    def display_information(self):
        self.send_command("ip address print")

    def display_services(self):
        command = "/ip service print"
        self.send_command(command)

    def assign_new_ip_adrs(self):
        def check_interface(interface):
            available_interfaces = ['ether2', 'ether3', 'ether4']
            return interface in available_interfaces

        def is_valid_ip(ip):
            try:
                socket.inet_aton(ip)
                return True
            except socket.error:
                return False

        interface = simpledialog.askstring("Select Interface", "Interface Name:")
        if interface and check_interface(interface):
            new_ip = simpledialog.askstring("New IP Adrs", f"New IP Adrs for {interface} (x.x.x.x):")
            if is_valid_ip(new_ip):
                self.send_command(f"ip address set [find interface={interface}] address={new_ip}")
            else:
                self.display_output("Invalid IP address format. Please enter a valid IP.")
        else:
            self.display_output("Invalid interface or interface does not exist.")

    def display_interfaces(self):
        self.send_command("interface print detail")

    def assign_new_identity(self):
        new_id = simpledialog.askstring("New ID", "New ID:")
        self.send_command(f"/system identity set name={new_id}")
    
    def disable_wifi(self):
        self.send_command("interface wireless disable 0")

    def reboot(self):
        self.send_command("/system reboot")

    def disconnect_internet(self):
        self.send_command("/interface ethernet disable [find]")

    def connect_internet(self):
        self.send_command("/interface ethernet enable [find]")

    def activate_safe_mode(self):
        if self.ssh_client is not None:
            try:
                shell = self.ssh_client.invoke_shell()

                if self.safe_mode_activated % 2 == 0:
                    # Send Ctrl+X to activate safe mode
                    shell.send('\x18')
                    time.sleep(2)
                    output = shell.recv(4096).decode('utf-8')
                    if "Safe Mode taken" in output:
                        self.display_output("Activated safe mode.")
                        self.safe_mode_activated += 1
                    else:
                        self.display_output("Safe mode state unchanged.")
                else:
                    # Follow-up command to check the current state
                    shell.send('\x04')
                    time.sleep(2)
                    output = shell.recv(4096).decode('utf-8')
                    if "Safe Mode activated" in output:
                        self.display_output("Deactivated safe mode.")
                        self.safe_mode_activated += 1
                    else:
                        self.display_output("Safe mode state unchanged.")
            except Exception as e:
                self.display_output(f"Error occurred while toggling safe mode: {str(e)}")
        else:
            self.display_output("Not connected to MikroTik, connect first.")


    def conf_backup(self):
        self.send_command("/system backup save name=config_backup")

    def send_ping(self):
        def is_valid_ip(ip):
            try:
                socket.inet_aton(ip)
                return True
            except socket.error:
                return False

        destination_ip = simpledialog.askstring("Destination IP", "Destination IP:")

        if destination_ip:
            if is_valid_ip(destination_ip):
                self.send_command(f"/ping count=4 {destination_ip}")
            else:
                self.display_output("Invalid IP address. Please enter a valid IP.")
        else:
            self.display_output("Please enter a destination IP for the ping test.") 

    def display_interface_status(self):
        self.send_command("interface print")

    def assign_new_port(self):
        def check_service_exists(service):
            available_services = ['ftp', 'ssh', 'telnet', 'api', 'www', 'winbox', 'api-ssl'] 
            return service in available_services

        def is_valid_port(port):
            try:
                port_num = int(port)
                return 0 < port_num < 65536  # Ports are in the range 1-65535
            except ValueError:
                return False

        service = simpledialog.askstring("Service", "Service (e.g., ftp):")
        port = simpledialog.askstring("Port", "Enter Port:")

        if service and port:
            if check_service_exists(service):
                if is_valid_port(port):
                    self.send_command(f"/ip service set [find name={service}] port={port}")
                else:
                    self.display_output("Invalid port. Please enter a valid port number.")
            else:
                self.display_output("Service does not exist.")
        else:
            self.display_output("Enter both service and port number!")
    
    def send_command(self, command):
        if self.ssh_client is not None:
            stdin, stdout, stderr = self.ssh_client.exec_command(command)
            output = stdout.read().decode('utf-8')
            self.display_output(f"Command: {command}\nOutput:\n{output}")
        else:
            self.display_output("No connection. Connect first.")

    def display_output(self, message):
        self.text_display.delete(1.0, tk.END)  
        self.text_display.insert(tk.END, message)

if __name__ == "__main__":
    root = tk.Tk()
    app = MikrotikGUI(root)
    root.mainloop()