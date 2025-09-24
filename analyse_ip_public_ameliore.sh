#!/usr/bin/env bash
# analyse_ip_public_ameliore.sh - Version Red Team complète
# Audit réseau et sécurité avancé pour équipes Red Team

set -o pipefail

# Configuration depuis le wrapper
STEALTH_MODE=${STEALTH_MODE:-"N"}
EVASION_MODE=${EVASION_MODE:-"N"}
AGGRESSIVENESS=${AGGRESSIVENESS:-2}

# IP depuis argument ou saisie interactive
IP="${1:-}"
if [[ -z "$IP" ]]; then
  read -p "Entrez l'IP publique à analyser : " IP
fi

if [[ -z "$IP" ]]; then
  echo "[⚠️] Aucune IP fournie, sortie du script."
  exit 1
fi

# Validation IP
if ! [[ "$IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  echo "[ERROR] Format IP invalide"
  exit 1
fi

# --- Configuration timing selon mode ---
if [[ "$STEALTH_MODE" =~ ^[Yy] ]]; then
  NMAP_TIMING="-T1 --scan-delay 2s"
  CURL_DELAY="sleep 2"
  echo "[🥷] Mode furtif activé - scans lents et discrets"
else
  NMAP_TIMING="-T4 --min-rate 1000"
  CURL_DELAY="sleep 0.5"
  echo "[⚡] Mode normal - scans rapides"
fi

# --- Saisie interactive des clés API ---
echo "=== Configuration des clés API ==="
if [[ -z "$SHODAN_API_KEY" ]]; then
  read -p "Clé API Shodan (Enter pour ignorer) : " SHODAN_API_KEY
fi
if [[ -z "$VT_API_KEY" ]]; then
  read -p "Clé API VirusTotal (Enter pour ignorer) : " VT_API_KEY
fi
if [[ -z "$CENSYS_API_ID" ]]; then
  read -p "Censys API ID (Enter pour ignorer) : " CENSYS_API_ID
fi
if [[ -z "$CENSYS_API_SECRET" ]]; then
  read -p "Censys API Secret (Enter pour ignorer) : " CENSYS_API_SECRET
fi
if [[ -z "$SECURITYTRAILS_API_KEY" ]]; then
  read -p "SecurityTrails API Key (Enter pour ignorer) : " SECURITYTRAILS_API_KEY
fi

OUTDIR="redteam_audit_$(date +%Y%m%d_%H%M%S)_${IP//:/_}"
mkdir -p "$OUTDIR"/{recon,vulnscan,enum,evasion,osint,logs}

echo "[🎯] === AUDIT RED TEAM - IP : $IP ==="
echo "[🗂️] Résultats dans : $OUTDIR"
echo "[⚙️] Agressivité : $AGGRESSIVENESS/3"

# --- Fonction pour afficher étape ---
function etape() {
  echo -e "\n🔍 ---- $1 ----"
  echo "   $2"
  echo "$(date '+%H:%M:%S') - Début: $1" >> "$OUTDIR/logs/timeline.log"
}

function safe_run() {
  local cmd="$1"
  local output="$2"
  local description="$3"
  
  echo "[EXEC] $description" >> "$OUTDIR/logs/commands.log"
  echo "[CMD] $cmd" >> "$OUTDIR/logs/commands.log"
  
  eval "$cmd" 2>&1 | tee "$output" || {
    echo "[ERROR] Échec: $description" | tee -a "$OUTDIR/logs/errors.log"
    return 1
  }
  return 0
}

# --- PHASE 1: RECONNAISSANCE PASSIVE ---
echo -e "\n🕵️ === PHASE 1: RECONNAISSANCE PASSIVE ==="

# --- 1) Whois enrichi ---
etape "1) Whois & AS Information" "Propriétaire, AS, plages IP"
safe_run "whois '$IP'" "$OUTDIR/recon/whois.txt" "Whois lookup"

# Recherche ASN
if command -v dig >/dev/null 2>&1; then
  safe_run "dig +short '$IP'" "$OUTDIR/recon/dns_reverse.txt" "DNS reverse"
fi

# --- 2) BGP & AS Information ---
etape "2) BGP & Autonomous System" "Informations routage BGP"
safe_run "curl -s 'https://api.bgpview.io/ip/$IP' | jq '.' 2>/dev/null || curl -s 'https://api.bgpview.io/ip/$IP'" "$OUTDIR/osint/bgp_info.json" "BGP information"

# --- 3) Géolocalisation avancée ---
etape "3) Géolocalisation & Threat Intel" "Position géographique et réputation"
if command -v geoiplookup >/dev/null 2>&1; then
  safe_run "geoiplookup '$IP'" "$OUTDIR/recon/geoip.txt" "GeoIP lookup"
fi

# IP reputation gratuite
safe_run "curl -s 'https://api.abuseipdb.com/api/v2/check?ipAddress=$IP' -H 'Key: YOUR_KEY_HERE' || echo 'AbuseIPDB: clé requise'" "$OUTDIR/osint/abuseipdb.json" "AbuseIPDB check"

# --- 4) Shodan ---
etape "4) Shodan Intelligence" "Services exposés et vulnérabilités"
if [[ -n "$SHODAN_API_KEY" ]]; then
  safe_run "curl -s 'https://api.shodan.io/shodan/host/$IP?key=$SHODAN_API_KEY'" "$OUTDIR/osint/shodan.json" "Shodan lookup"
  eval $CURL_DELAY
else
  echo "SHODAN_API_KEY non fourni" > "$OUTDIR/osint/shodan.txt"
fi

# --- 5) VirusTotal ---
etape "5) VirusTotal Reputation" "Réputation et détections malware"
if [[ -n "$VT_API_KEY" ]]; then
  safe_run "curl -s -H 'x-apikey: $VT_API_KEY' 'https://www.virustotal.com/api/v3/ip_addresses/$IP'" "$OUTDIR/osint/virustotal.json" "VirusTotal lookup"
  eval $CURL_DELAY
else
  echo "VT_API_KEY non fourni" > "$OUTDIR/osint/virustotal.txt"
fi

# --- 6) Censys ---
etape "6) Censys Intelligence" "Certificats SSL et services"
if [[ -n "$CENSYS_API_ID" && -n "$CENSYS_API_SECRET" ]]; then
  safe_run "curl -u '$CENSYS_API_ID:$CENSYS_API_SECRET' 'https://search.censys.io/api/v2/hosts/$IP'" "$OUTDIR/osint/censys.json" "Censys lookup"
  eval $CURL_DELAY
else
  echo "Censys API non configuré" > "$OUTDIR/osint/censys.txt"
fi

# --- 7) SecurityTrails ---
etape "7) SecurityTrails DNS History" "Historique DNS et sous-domaines"
if [[ -n "$SECURITYTRAILS_API_KEY" ]]; then
  safe_run "curl -s -H 'APIKEY: $SECURITYTRAILS_API_KEY' 'https://api.securitytrails.com/v1/ips/nearby/$IP'" "$OUTDIR/osint/securitytrails.json" "SecurityTrails lookup"
  eval $CURL_DELAY
else
  echo "SecurityTrails API non configuré" > "$OUTDIR/osint/securitytrails.txt"
fi

# --- PHASE 2: DÉCOUVERTE ACTIVE ---
echo -e "\n🌐 === PHASE 2: DÉCOUVERTE ACTIVE ==="

# --- 8) Traceroute avancé ---
etape "8) Traceroute multi-protocoles" "Chemin réseau et latence"
if command -v traceroute >/dev/null 2>&1; then
  safe_run "traceroute -I -w 2 -q 1 '$IP'" "$OUTDIR/recon/traceroute_icmp.txt" "Traceroute ICMP"
  [[ $EUID -eq 0 ]] && safe_run "traceroute -U -w 2 -q 1 '$IP'" "$OUTDIR/recon/traceroute_udp.txt" "Traceroute UDP"
  [[ $EUID -eq 0 ]] && safe_run "traceroute -T -w 2 -q 1 -p 80 '$IP'" "$OUTDIR/recon/traceroute_tcp.txt" "Traceroute TCP"
else
  echo "traceroute non installé" > "$OUTDIR/recon/traceroute.txt"
fi

# --- 9) Ping analysis ---
etape "9) ICMP Analysis" "Réponse ICMP et fingerprinting OS"
safe_run "ping -c 10 '$IP' | tee >(tail -1 > '$OUTDIR/recon/ping_stats.txt')" "$OUTDIR/recon/ping_analysis.txt" "Ping analysis"

# --- 10) Nmap découverte des hôtes ---
etape "10) Host Discovery" "Détection de l'hôte et services"
if command -v nmap >/dev/null 2>&1; then
  safe_run "nmap -sn -PE -PP -PM -PO $NMAP_TIMING '$IP'" "$OUTDIR/recon/host_discovery.txt" "Host discovery"
fi

# --- PHASE 3: SCAN DE PORTS AVANCÉ ---
echo -e "\n🔌 === PHASE 3: SCAN DE PORTS ET SERVICES ==="

# --- 11) Nmap Top 1000 avec détection versions ---
etape "11) Top 1000 Ports Scan" "Ports populaires avec versions"
if command -v nmap >/dev/null 2>&1; then
  safe_run "nmap -Pn --top-ports 1000 -sS -sV $NMAP_TIMING -oN '$OUTDIR/vulnscan/nmap_top1000.txt' '$IP'" "/dev/null" "Nmap top 1000"
fi

# --- 12) Nmap scan complet selon agressivité ---
if [[ $AGGRESSIVENESS -ge 2 ]]; then
  etape "12) Full Port Scan" "Scan complet tous ports TCP"
  if command -v nmap >/dev/null 2>&1; then
    safe_run "nmap -Pn -p- -sS -sV $NMAP_TIMING --max-retries 2 -oN '$OUTDIR/vulnscan/nmap_fullports.txt' '$IP'" "/dev/null" "Full port scan"
  fi
fi

# --- 13) Scan UDP ports critiques ---
etape "13) UDP Critical Ports" "Services UDP critiques"
if command -v nmap >/dev/null 2>&1 && [[ $EUID -eq 0 ]]; then
  UDP_PORTS="53,67,68,69,123,137,138,161,162,500,514,1194,4500"
  safe_run "nmap -Pn -sU --top-ports 100 $NMAP_TIMING '$IP'" "$OUTDIR/vulnscan/udp_scan.txt" "UDP scan"
fi

# --- 14) Masscan (si disponible et mode agressif) ---
if [[ $AGGRESSIVENESS -ge 3 ]] && command -v masscan >/dev/null 2>&1 && [[ $EUID -eq 0 ]]; then
  etape "14) Masscan Ultra-Fast" "Scan ultra-rapide tous ports"
  safe_run "masscan -p1-65535 '$IP' --rate=1000 -oL '$OUTDIR/vulnscan/masscan.txt'" "/dev/null" "Masscan"
fi

# --- PHASE 4: ÉNUMÉRATION DES SERVICES ---
echo -e "\n🔍 === PHASE 4: ÉNUMÉRATION DES SERVICES ==="

# --- 15) Énumération HTTP/HTTPS ---
etape "15) Web Services Enumeration" "Analyse des services web"
for port in 80 443 8080 8443 8000 9000; do
  if timeout 5 bash -c "</dev/tcp/$IP/$port" 2>/dev/null; then
    echo "Port $port ouvert - analyse en cours..."
    
    # Headers HTTP
    safe_run "curl -Is --connect-timeout 5 '$IP:$port'" "$OUTDIR/enum/http_headers_${port}.txt" "HTTP headers port $port"
    
    # Nikto si disponible
    if command -v nikto >/dev/null 2>&1 && [[ $AGGRESSIVENESS -ge 2 ]]; then
      safe_run "nikto -h '$IP:$port' -C all" "$OUTDIR/enum/nikto_${port}.txt" "Nikto scan port $port"
    fi
    
    # Dirb/Gobuster pour découverte de répertoires
    if command -v dirb >/dev/null 2>&1 && [[ $AGGRESSIVENESS -ge 2 ]]; then
      safe_run "timeout 300 dirb http://$IP:$port/ /usr/share/dirb/wordlists/common.txt -r" "$OUTDIR/enum/dirb_${port}.txt" "Directory enumeration port $port"
    fi
    
    eval $CURL_DELAY
  fi
done

# --- 16) SSL/TLS Analysis ---
etape "16) SSL/TLS Security Analysis" "Analyse sécurité SSL/TLS"
for port in 443 8443; do
  if timeout 3 bash -c "</dev/tcp/$IP/$port" 2>/dev/null; then
    # SSLScan
    if command -v sslscan >/dev/null 2>&1; then
      safe_run "sslscan '$IP:$port'" "$OUTDIR/enum/sslscan_${port}.txt" "SSL scan port $port"
    fi
    
    # Nmap SSL scripts
    if command -v nmap >/dev/null 2>&1; then
      safe_run "nmap -Pn -p $port --script ssl-enum-ciphers,ssl-cert,ssl-heartbleed,ssl-poodle,ssl-ccs-injection '$IP'" "$OUTDIR/enum/ssl_vulns_${port}.txt" "SSL vulnerabilities port $port"
    fi
  fi
done

# --- 17) SMB Enumeration ---
etape "17) SMB/NetBIOS Enumeration" "Énumération services Windows"
if timeout 3 bash -c "</dev/tcp/$IP/445" 2>/dev/null || timeout 3 bash -c "</dev/tcp/$IP/139" 2>/dev/null; then
  if command -v nmap >/dev/null 2>&1; then
    safe_run "nmap -Pn -p 139,445 --script smb-enum-shares,smb-enum-users,smb-enum-domains,smb-vuln-* '$IP'" "$OUTDIR/enum/smb_enum.txt" "SMB enumeration"
  fi
fi

# --- 18) SSH Analysis ---
etape "18) SSH Service Analysis" "Analyse configuration SSH"
if timeout 3 bash -c "</dev/tcp/$IP/22" 2>/dev/null; then
  safe_run "nmap -Pn -p 22 --script ssh-host-key,ssh-auth-methods '$IP'" "$OUTDIR/enum/ssh_analysis.txt" "SSH analysis"
fi

# --- 19) DNS Enumeration ---
etape "19) DNS Service Analysis" "Énumération serveur DNS"
if timeout 3 bash -c "</dev/tcp/$IP/53" 2>/dev/null; then
  safe_run "nmap -Pn -p 53 --script dns-recursion,dns-zone-transfer '$IP'" "$OUTDIR/enum/dns_analysis.txt" "DNS analysis"
  
  if command -v dig >/dev/null 2>&1; then
    safe_run "dig @$IP version.bind chaos txt" "$OUTDIR/enum/dns_version.txt" "DNS version"
  fi
fi

# --- 20) Database Services ---
etape "20) Database Services Detection" "Détection bases de données"
DB_PORTS=(1433 3306 5432 1521 27017 6379 5984)
for port in "${DB_PORTS[@]}"; do
  if timeout 3 bash -c "</dev/tcp/$IP/$port" 2>/dev/null; then
    echo "Database service détecté sur port $port" >> "$OUTDIR/enum/database_services.txt"
    if command -v nmap >/dev/null 2>&1; then
      safe_run "nmap -Pn -p $port -sV '$IP'" "$OUTDIR/enum/db_service_${port}.txt" "Database service port $port"
    fi
  fi
done

# --- PHASE 5: TESTS DE VULNÉRABILITÉS ---
echo -e "\n🐛 === PHASE 5: TESTS DE VULNÉRABILITÉS ==="

# --- 21) Nmap Vulnerability Scripts ---
etape "21) Nmap Vulnerability Detection" "Scripts vulnérabilités Nmap"
if command -v nmap >/dev/null 2>&1; then
  safe_run "nmap -Pn --script vuln $NMAP_TIMING '$IP'" "$OUTDIR/vulnscan/nmap_vulns.txt" "Vulnerability scripts"
  
  # CVEs récents
  safe_run "nmap -Pn --script vulners '$IP'" "$OUTDIR/vulnscan/nmap_cve.txt" "CVE detection"
fi

# --- 22) Tests vulnérabilités spécifiques ---
etape "22) Specific Vulnerability Tests" "Tests vulnérabilités connues"
if command -v nmap >/dev/null 2>&1; then
  # EternalBlue
  safe_run "nmap -Pn -p 445 --script smb-vuln-ms17-010 '$IP'" "$OUTDIR/vulnscan/eternalblue.txt" "EternalBlue test"
  
  # Heartbleed
  safe_run "nmap -Pn -p 443 --script ssl-heartbleed '$IP'" "$OUTDIR/vulnscan/heartbleed.txt" "Heartbleed test"
  
  # BlueKeep
  safe_run "nmap -Pn -p 3389 --script rdp-vuln-ms12-020 '$IP'" "$OUTDIR/vulnscan/bluekeep.txt" "BlueKeep test"
fi

# --- PHASE 6: TESTS D'ÉVASION (si activés) ---
if [[ "$EVASION_MODE" =~ ^[Yy] ]]; then
echo -e "\n🥷 === PHASE 6: TESTS D'ÉVASION IDS/IPS ==="

# --- 23) Fragmentation IP ---
etape "23) IP Fragmentation Tests" "Tests fragmentation pour évasion"
if command -v nmap >/dev/null 2>&1; then
  safe_run "nmap -Pn -f --top-ports 100 '$IP'" "$OUTDIR/evasion/fragmentation.txt" "IP fragmentation"
fi

# --- 24) Decoy scans ---
etape "24) Decoy Scanning" "Scans avec adresses leurres"
if command -v nmap >/dev/null 2>&1; then
  safe_run "nmap -Pn -D RND:10 --top-ports 100 '$IP'" "$OUTDIR/evasion/decoy_scan.txt" "Decoy scanning"
fi

# --- 25) Timing evasion ---
etape "25) Slow Scan Evasion" "Scan très lent pour évasion"
if command -v nmap >/dev/null 2>&1; then
  safe_run "nmap -Pn -T0 --scan-delay 5s --top-ports 20 '$IP'" "$OUTDIR/evasion/slow_scan.txt" "Ultra-slow scan"
fi

fi # Fin tests évasion

# --- PHASE 7: INFORMATIONS SYSTÈME ---
echo -e "\n🖥️ === PHASE 7: OS & SYSTEM FINGERPRINTING ==="

# --- 26) OS Detection avancé ---
etape "26) Advanced OS Detection" "Détection système d'exploitation"
if command -v nmap >/dev/null 2>&1; then
  safe_run "nmap -Pn -O --osscan-guess --max-os-tries 3 '$IP'" "$OUTDIR/recon/os_detection.txt" "OS detection"
fi

# --- 27) Service version detection ---
etape "27) Service Version Detection" "Versions précises des services"
if command -v nmap >/dev/null 2>&1; then
  safe_run "nmap -Pn -sV --version-intensity 9 --top-ports 100 '$IP'" "$OUTDIR/enum/service_versions.txt" "Service versions"
fi

# --- PHASE 8: TESTS DE CONNECTIVITÉ AVANCÉS ---
echo -e "\n🌐 === PHASE 8: CONNECTIVITÉ & FILTRAGE ==="

# --- 28) Tests protocoles divers ---
etape "28) Protocol Tests" "Tests connectivité protocoles"
{
  echo "=== Test connectivité protocoles ==="
  
  # ICMP
  ping -c 3 "$IP" >/dev/null 2>&1 && echo "ICMP: OK" || echo "ICMP: BLOQUÉ"
  
  # TCP communs
  COMMON_PORTS=(21 22 23 25 53 80 110 143 443 993 995 3389 5900)
  for p in "${COMMON_PORTS[@]}"; do
    timeout 2 bash -c "</dev/tcp/$IP/$p" >/dev/null 2>&1 && echo "TCP/$p: OUVERT" || echo "TCP/$p: FERMÉ/FILTRÉ"
  done
  
} > "$OUTDIR/recon/connectivity_test.txt"

# --- 29) MTU Discovery ---
etape "29) MTU Path Discovery" "Découverte MTU du chemin"
if command -v ping >/dev/null 2>&1; then
  safe_run "ping -c 1 -M do -s 1472 '$IP' && echo 'MTU >= 1500' || ping -c 1 -M do -s 1436 '$IP' && echo 'MTU >= 1464' || echo 'MTU < 1464'" "$OUTDIR/recon/mtu_discovery.txt" "MTU discovery"
fi

# --- PHASE 9: GÉNÉRATION DU RAPPORT ---
echo -e "\n📄 === PHASE 9: GÉNÉRATION DU RAPPORT ==="

# --- 30) Synthèse des découvertes ---
etape "30) Executive Summary" "Synthèse exécutive des résultats"
{
  echo "# RAPPORT D'AUDIT RED TEAM - IP: $IP"
  echo "Date: $(date)"
  echo "Mode: Agressivité $AGGRESSIVENESS/3"
  [[ "$STEALTH_MODE" =~ ^[Yy] ]] && echo "Mode furtif: ACTIVÉ"
  [[ "$EVASION_MODE" =~ ^[Yy] ]] && echo "Tests évasion: ACTIVÉS"
  echo
  
  echo "## PORTS OUVERTS DÉTECTÉS"
  if [ -f "$OUTDIR/vulnscan/nmap_top1000.txt" ]; then
    grep -E "^[0-9]+/(tcp|udp).*open" "$OUTDIR/vulnscan/nmap_top1000.txt" 2>/dev/null || echo "Aucun port ouvert détecté"
  fi
  echo
  
  echo "## SERVICES IDENTIFIÉS"
  if [ -f "$OUTDIR/enum/service_versions.txt" ]; then
    grep -E "^[0-9]+/(tcp|udp).*open.*" "$OUTDIR/enum/service_versions.txt" 2>/dev/null || echo "Pas de services identifiés"
  fi
  echo
  
  echo "## VULNÉRABILITÉS POTENTIELLES"
  if [ -f "$OUTDIR/vulnscan/nmap_vulns.txt" ]; then
    grep -E "VULNERABLE|CVE-" "$OUTDIR/vulnscan/nmap_vulns.txt" 2>/dev/null || echo "Pas de vulnérabilités évidentes détectées"
  fi
  echo
  
  echo "## RÉPUTATION IP"
  if [ -f "$OUTDIR/osint/virustotal.json" ]; then
    echo "VirusTotal: Voir osint/virustotal.json"
  fi
  if [ -f "$OUTDIR/osint/shodan.json" ]; then
    echo "Shodan: Voir osint/shodan.json"
  fi
  
  echo
  echo "## RECOMMANDATIONS"
  echo "1. Analyser tous les ports ouverts identifiés"
  echo "2. Vérifier les versions des services pour des vulnérabilités connues"
  echo "3. Tester l'authentification sur les services identifiés"
  echo "4. Analyser les certificats SSL/TLS"
  echo "5. Vérifier la configuration de sécurité des services web"
  
} > "$OUTDIR/RAPPORT_EXECUTIF.md"

# --- 31) Export PDF si possible ---
etape "31) PDF Generation" "Génération du rapport PDF"
PDF_FILE="$OUTDIR/RedTeam_Audit_${IP//:
