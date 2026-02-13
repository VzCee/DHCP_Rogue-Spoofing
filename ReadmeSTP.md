# 📦 Requirements – STP Claim Root Bridge Attack

## 🖥 Sistema Operativo

- Linux (Kali Linux, Ubuntu, Debian)
- Acceso a red Layer 2
- Entorno de laboratorio controlado (PNETLab, EVE-NG, GNS3 o físico)

---

## 🐍 Versión de Python

- Python 3.8 o superior

Verificar versión:

```bash
python3 --version
```

---

## 📚 Librerías Python

Crear archivo `requirements.txt`:

```
scapy>=2.5.0
tk
```

Instalar dependencias:

```bash
pip install -r requirements.txt
```

---

## 📦 Dependencias del Sistema (Recomendado)

```bash
sudo apt update
sudo apt install python3-scapy python3-tk
```

---

## 🔐 Permisos Necesarios

El script requiere privilegios root para:

- Enviar tramas Ethernet (Layer 2)
- Construir BPDUs personalizados
- Acceder directamente a la interfaz de red

Ejecutar con:

```bash
sudo python3 stp_attack.py
```

---

## 🌐 Requisitos de Red

- Switches con STP habilitado
- Sin BPDU Guard o Root Guard activado (solo para pruebas)
- Todos los dispositivos dentro del mismo dominio Layer 2
- Red aislada de producción

---

## 🧪 Entorno Recomendado

- PNETLab
- EVE-NG
- GNS3
- Laboratorio físico con switches administrables

---

## ⚠️ Uso Responsable

Este proyecto debe ejecutarse únicamente en entornos autorizados y con fines educativos.
