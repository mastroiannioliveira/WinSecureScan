"""
===============================================================================
 NetworkScanner - Ferramenta de Mapeamento e Auditoria de Rede
===============================================================================

 🚀 By Mastroianni Oliveira
 📅 Versão: 2.5 (Última atualização: 2025)
 📜 Licença: MIT
 🌍 Compatibilidade: Windows, Linux, macOS

===============================================================================
"""

import os
import scapy.all as scapy
import nmap
import requests
import json
import platform
import subprocess
import socket
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor

# -------------------- Configuração --------------------

THREADS = 50
OUI_API = "https://api.macvendors.com/"
TIMEOUT_ARP = 1

# -------------------- Funções --------------------

def expandir_intervalo(ip_range):
    """Converte um intervalo do tipo '192.168.15.1-254' em uma lista de IPs."""
    try:
        match = re.match(r"(\d+\.\d+\.\d+)\.(\d+)-(\d+)", ip_range)
        if match:
            base, inicio, fim = match.groups()
            return [f"{base}.{i}" for i in range(int(inicio), int(fim) + 1)]
        else:
            print("[⚠] Formato inválido! Use: 192.168.15.1-254")
            return []
    except Exception as e:
        print(f"[❌] Erro ao processar intervalo: {e}")
        return []

def descobrir_hosts(alvo):
    """Executa ARP Scan ou Ping Sweep para encontrar hosts ativos na rede."""
    try:
        hosts = []
        ips = []

        if "-" in alvo:
            ips = expandir_intervalo(alvo)
        elif "/" in alvo:
            ips = [str(ip) for ip in ipaddress.IPv4Network(alvo, strict=False)]
        else:
            ips = [alvo]

        print(f"[+] Executando ARP Scan na rede {alvo}...")
        try:
            resposta, _ = scapy.arping(alvo, timeout=TIMEOUT_ARP, verbose=False)
            for envio, recepcao in resposta:
                print(f"[✔] Host encontrado via ARP: IP={recepcao.psrc}, MAC={recepcao.hwsrc}")
                hosts.append({"ip": recepcao.psrc, "mac": recepcao.hwsrc})
        except Exception:
            print("[⚠] ARP Scan falhou. Tentando Ping Sweep...")

        if not hosts:
            with ThreadPoolExecutor(max_workers=THREADS) as executor:
                resultados = executor.map(lambda ip: (ip, ping_host(ip)), ips)
                for ip, ativo in resultados:
                    if ativo:
                        print(f"[✔] Host ativo encontrado via Ping: {ip}")
                        hosts.append({"ip": ip, "mac": "Desconhecido"})

        print(f"[✔] {len(hosts)} host(s) encontrado(s).")
        return hosts
    except Exception as e:
        print(f"[❌] Erro ao descobrir hosts: {e}")
        return []

def ping_host(ip):
    """Executa um ping para verificar se o host está ativo."""
    try:
        param = "-n 1" if platform.system().lower() == "windows" else "-c 1"
        output = subprocess.run(f"ping {param} {ip}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        return output.returncode == 0  # Retorna True se o host respondeu
    except:
        return False

def obter_nome_host(ip):
    """Resolve o nome do host via DNS reverso."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Desconhecido"

def buscar_fabricante(mac_address):
    """Consulta a API OUI para buscar fabricante da placa de rede."""
    try:
        resposta = requests.get(OUI_API + mac_address, timeout=3)
        return resposta.text if resposta.status_code == 200 else "Fabricante não encontrado"
    except:
        return "Erro ao buscar fabricante"

def identificar_sistema(ip):
    """Usa Nmap para detectar o sistema operacional e sua arquitetura."""
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments="-O --max-retries 1 --host-timeout 5s")
        if ip in nm.all_hosts():
            os_detalhes = nm[ip].get("osmatch", [])
            if os_detalhes:
                sistema_operacional = os_detalhes[0]["name"]
                arquitetura = os_detalhes[0].get("osclass", [{}])[0].get("arch", "Desconhecida")
                return sistema_operacional, arquitetura
        return "Desconhecido", "Desconhecida"
    except:
        return "Desconhecido", "Desconhecida"

def analisar_host(host):
    """Executa o scan em um único host, coletando todas as informações."""
    ip = host["ip"]
    mac = host["mac"]
    nome_host = obter_nome_host(ip)
    fabricante = buscar_fabricante(mac)
    sistema_operacional, arquitetura = identificar_sistema(ip)

    return {
        "ip": ip,
        "nome_host": nome_host,
        "mac": mac if mac != "Desconhecido" else "Não identificado",
        "fabricante": fabricante if fabricante else "Desconhecido",
        "sistema_operacional": sistema_operacional,
        "arquitetura": arquitetura
    }

# -------------------- Execução Principal --------------------

while True:
    print("""
🚀 NetworkScanner - By Mastroianni Oliveira
🔍 Versão 2.5 - Scanner otimizado e com informações detalhadas
""")

    print("🔹 Digite um IP único, um range CIDR ou um intervalo de IPs (pressione Enter para sair):")
    rede = input().strip()

    if not rede:
        print("[👋] Encerrando o scanner. Até mais!")
        break

    print(f"[🔍] Iniciando scan na rede: {rede}")

    # 🔎 Descobrir todos os dispositivos ativos na rede
    hosts_encontrados = descobrir_hosts(rede)

    if not hosts_encontrados:
        print("[❌] Nenhum dispositivo ativo encontrado. Verifique permissões e firewall.")
        continue

    # 🔄 Processamento paralelo para coletar informações detalhadas de cada host
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        relatorio = list(executor.map(analisar_host, hosts_encontrados))

    # 📄 Salvar relatório com TODOS os dispositivos encontrados
    relatorio_arquivo = "relatorio_rede.json"
    with open(relatorio_arquivo, "w") as f:
        json.dump(relatorio, f, indent=4)

    # 📌 Exibir os resultados no terminal
    for dispositivo in relatorio:
        print("\n📡 Dispositivo Encontrado:")
        print("═════════════════════════════════════════════")
        for chave, valor in dispositivo.items():
            print(f"   {chave.capitalize().replace('_', ' ')}: {valor}")
        print("═════════════════════════════════════════════")

    print(f"\n[✔] Relatório salvo em '{relatorio_arquivo}'.")

    # 🔄 Retorna para a tela inicial após pressionar Enter
    input("\n🔄 Pressione Enter para voltar à tela inicial...\n")
