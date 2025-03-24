# 🚀 WinSecureScan - Scanner de Rede Profissional

**WinSecureScan** é uma ferramenta open-source desenvolvida para **auditoria e mapeamento de dispositivos conectados à rede local (LAN)**.  
Ideal para profissionais de segurança, administradores de redes e auditores de infraestrutura, a ferramenta fornece uma visão detalhada da rede em poucos segundos.

---

## 📌 Descrição

A ferramenta realiza a descoberta de dispositivos ativos, coleta de informações como:

- IP e Nome do Host
- Endereço MAC e Fabricante
- Sistema Operacional e Arquitetura (via Nmap)
- Estimativa de tempo de conexão (uptime)
- Geração de relatório automático em JSON

---

## ⚙️ Características

- 🛰️ Descoberta de dispositivos ativos via ARP Scan ou Ping Sweep  
- 🧠 Detecção de SO e arquitetura (32/64 bits) com Nmap  
- 🏷️ Consulta de fabricante via API MAC Vendors  
- 📛 Resolução de nome do host via DNS reverso  
- 📄 Geração de relatório em `relatorio_rede.json`  
- 🔁 Execução contínua com opção de retorno ao menu inicial  
- 🖥️ Compatível com **Windows**, **Linux** e **macOS**

---

## 📦 Requisitos

- Python 3.7+
- `scapy`
- `nmap` (deve estar instalado no sistema)
- `requests`
- `ipaddress`
- `qrcode`
- `pillow`
- `matplotlib`

Instale com:

```bash
pip install -r requirements.txt
