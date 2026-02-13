##  DHCP Rogue / Spoofing Attack Tool

Este proyecto es una herramienta educativa desarrollada en Python utilizando Scapy y Tkinter para simular un ataque DHCP Rogue/Spoofing dentro de un entorno de laboratorio controlado.

- El script actúa como un servidor DHCP malicioso capaz de interceptar solicitudes DHCP de clientes y responder con configuraciones manipuladas antes que el servidor legítimo.
## Función del Script
La función principal del script es:

- Detectar paquetes DHCP Discover enviados por clientes.
- Enviar respuestas DHCP Offer falsas.
- Confirmar la asignación mediante DHCP ACK malicioso.
- Asignar Gateway y DNS apuntando al atacante.
- Registrar víctimas comprometidas en tiempo real.

Esto permite redirigir el tráfico del cliente hacia el atacante, facilitando escenarios de Man-in-the-Middle (MITM).

---
## Características clave:

Simulación completa de servidor DHCP malicioso.
- Generación dinámica de pool de direcciones IP.
- Respuesta automática a mensajes DHCP Discover y Request.
- Envío múltiple de paquetes para aumentar probabilidad de éxito.
- Base de datos interna de víctimas comprometidas.
- Registro de fecha y hora de compromiso.
- Estadísticas en tiempo real (Offers, ACKs, víctimas).
- Interfaz gráfica avanzada con monitoreo de actividad.
- Validación de ejecución con privilegios root.
---
<img width="350" height="370" alt="image" src="https://github.com/user-attachments/assets/251651ff-5625-4b6d-b2d8-6f655d2c3f30" />


## Video de Demostracion
**https://youtu.be/wA5hWqIrXjE?si=pV4mImiP6brCxlcK**

## Topologia Representada en PnetLAB
<img width="1209" height="830" alt="image" src="https://github.com/user-attachments/assets/89850eeb-ba17-48d7-82e5-cc3e3786cdce" />

##  Router

| Conexión | Interfaz Router | Dispositivo Destino | Interfaz Destino |
|----------|-----------------|---------------------|-------------------|
| LAN      | e0/0            | Switch Principal    | e0/0              |
| WAN      | e0/1            | Net                 | -                 |

**IP LAN:** 23.72.0.1  
**Gateway de la red:** 23.72.0.1  

---

## 🖧 Switch Principal

| Interfaz | Dispositivo Conectado | Interfaz Destino |
|----------|----------------------|------------------|
| e0/0     | Router               | e0/0             |
| e0/1     | Atacante             | eth0             |
| e0/2     | VPC 1                | eth0             |
| e1/0     | VPC 2                | eth0             |
| e1/1     | Víctima              | eth0             |
| e0/3     | Switch 2             | e0/0             |

---

## 🖧 Switch 2

| Interfaz | Dispositivo Conectado | Interfaz Destino |
|----------|----------------------|------------------|
| e0/0     | Switch Principal     | e0/3             |
| e0/2     | VPC 3                | eth0             |

---

## 🧨 Atacante (Linux)

| Interfaz | Conectado a         | Interfaz Destino |
|----------|---------------------|------------------|
| eth0     | Switch Principal    | e0/1             |
| eth1     | Net                 | -                |

**Configuración IP:** DHCP o estática dentro del rango 23.72.0.0/24  
**Gateway:** 23.72.0.1  

---

## 💻 Víctima

| Interfaz | Conectado a        | Interfaz Destino |
|----------|--------------------|------------------|
| eth0     | Switch Principal   | e1/1             |

**Configuración IP:** DHCP  
**Gateway:** 23.72.0.1  

---

## 🖥 Clientes DHCP (VPCs)

### VPC 1

| Interfaz | Conectado a        | Interfaz Destino |
|----------|--------------------|------------------|
| eth0     | Switch Principal   | e0/2             |

Gateway: 23.72.0.1  

---

### VPC 2

| Interfaz | Conectado a        | Interfaz Destino |
|----------|--------------------|------------------|
| eth0     | Switch Principal   | e1/0             |

Gateway: 23.72.0.1  

---

### VPC 3

| Interfaz | Conectado a  | Interfaz Destino |
|----------|--------------|------------------|
| eth0     | Switch 2     | e0/2             |

Gateway: 23.72.0.1  
---
## 📋 Requisitos Técnicos

- Linux (Kali, Ubuntu, Debian)
- Python 3.8 o superior
- Permisos de superusuario (root)
- Entorno de laboratorio aislado
- Acceso al mismo dominio de broadcast que el servidor DHCP legítimo

---

## 📦 Dependencias

Instalar dependencias del sistema:

```bash
sudo apt update
sudo apt install python3-scapy python3-tk
```

requirements.txt:

```
scapy>=2.5.0
```

Instalar con:

```bash
pip install -r requirements.txt
```

---

## 🔐 Permisos

El script debe ejecutarse como root debido al uso de sockets de bajo nivel (Layer 2):

```bash
sudo python3 dhcp_rogue_attack.py
```

Si no se ejecuta con privilegios elevados, el programa finalizará automáticamente.

---

## 🌐 Requisitos de Red

- Servidor DHCP legítimo activo en la red.
- Clientes configurados en modo DHCP.
- Router configurado como Gateway (ejemplo: 23.72.0.1).
- Red LAN correctamente definida (ejemplo: 23.72.0.0/24).
- Todos los dispositivos dentro del mismo dominio de broadcast.
- Switch sin DHCP Snooping habilitado (para fines de prueba).

---

## 🛡 Medidas de Mitigación contra DHCP Rogue/Spoofing

Para prevenir este tipo de ataque se recomienda implementar:

---

### 1️⃣ DHCP Snooping (Recomendado)

Permite marcar como confiable únicamente el puerto donde se encuentra el servidor DHCP legítimo.

Ejemplo Cisco:

```
ip dhcp snooping
ip dhcp snooping vlan 1

interface e0/0
 ip dhcp snooping trust

interface range e0/1 - e0/24
 ip dhcp snooping limit rate 10
```

---

### 2️⃣ Port Security

Limita el número de dispositivos por puerto:

```
switchport port-security
switchport port-security maximum 2
switchport port-security violation shutdown
```

---

### 3️⃣ Dynamic ARP Inspection (DAI)

Previene ataques combinados de ARP Spoofing posteriores al DHCP Rogue.

---

### 4️⃣ Segmentación de Red (VLANs)

Reduce el dominio de broadcast y limita el alcance del atacante.

---

### 5️⃣ 802.1X

Autenticación basada en puerto para impedir dispositivos no autorizados.

---

### 6️⃣ Monitoreo y Detección

Indicadores de posible ataque:

- Múltiples DHCP Offer en la red.
- Gateway incorrecto en clientes.
- DNS inesperado.
- Incremento inusual de respuestas DHCP.
- Cambios en tabla ARP.

---

## 🎯 Enfoque Defensivo

El objetivo de este laboratorio no es únicamente ejecutar el ataque, sino:

- Comprender el funcionamiento interno del protocolo DHCP.
- Analizar cómo se produce la suplantación.
- Detectar configuraciones vulnerables.
- Implementar controles preventivos.
- Validar la efectividad de mecanismos defensivos.

---

## ⚠️ Advertencia

Este proyecto debe utilizarse exclusivamente en entornos de laboratorio autorizados.

El uso indebido en redes reales sin consentimiento constituye una violación legal.

