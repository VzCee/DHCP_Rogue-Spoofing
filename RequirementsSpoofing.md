# 📦 Requirements.txt

## 📦 Requisitos del Laboratorio

Este proyecto requiere un entorno de laboratorio controlado para ejecutar correctamente la herramienta y reproducir la topología de red.

El uso debe realizarse únicamente en redes autorizadas para pruebas de seguridad.

---

# 🖥 Requisitos de Software

## 🔹 Sistema Operativo (Atacante)

- Kali Linux
- Ubuntu
- Debian
- Cualquier distribución Linux compatible con Scapy

> ⚠️ No compatible con Windows sin WSL y configuraciones avanzadas de red.
> 

---

## 🔹 Python

- Python 3.8 o superior
- pip3 actualizado

Verificar versión:

```bash
python3 --version
```

---

## 🔹 Permisos

El script requiere privilegios de superusuario debido al envío y captura de paquetes en Capa 2 (Layer 2).

Ejecutar con:

```bash
sudo python3 dhcp_rogue_attack.py
```

---

# 🐍 Dependencias Python

Instalar dependencias mediante pip:

```bash
pip install -r requirements.txt
```

## 📄 Contenido del archivo `requirements.txt`

```
scapy>=2.5.0
```

---

# 📚 Dependencias del Sistema

En distribuciones basadas en Debian:

```bash
sudo apt update
sudo apt install python3-scapy python3-tk
```

---

# 🌐 Requisitos de Red

- Servidor DHCP legítimo activo
- Clientes configurados en modo DHCP
- Todos los dispositivos en el mismo dominio de broadcast
- Switch sin DHCP Snooping habilitado (para pruebas)
- Red de laboratorio aislada

Ejemplo de red utilizada en pruebas:

```
Red: 23.72.0.0/24
Gateway: 23.72.0.1
IP Atacante: 23.72.0.21
```

---

# 🔎 Verificación de Instalación

Comprobar que Scapy está correctamente instalado:

```bash
python3 -c "import scapy; print('Scapy instalado correctamente')"
```

---

# ⚠️ Advertencia Legal

Este proyecto es exclusivamente educativo.

El uso de esta herramienta en redes reales sin autorización explícita puede constituir delito.