# 🎯 RedTeam IP Audit Tool

## 📋 Description

Outil d'audit IP automatisé conçu spécifiquement pour les équipes Red Team et les professionnels du pentest. Ce toolkit effectue une reconnaissance complète, une découverte de services, une analyse de vulnérabilités et génère des rapports détaillés au format PDF.

### 🚀 Fonctionnalités principales

- **Reconnaissance passive multi-sources** (Shodan, VirusTotal, Censys, BGPView)
- **Découverte active de services** avec Nmap et Masscan
- **Tests de vulnérabilités automatisés** (EternalBlue, Heartbleed, BlueKeep, etc.)
- **Énumération de services** (HTTP/HTTPS, SMB, SSH, DNS, Bases de données)
- **Tests d'évasion IDS/IPS** configurables
- **Mode furtif** pour opérations discrètes
- **Génération de rapports** professionnels en PDF
- **Timeline détaillée** de l'audit
- **Validation légale** intégrée

---

## ⚠️ DISCLAIMER - AVERTISSEMENT LÉGAL

### 🚨 USAGE STRICTEMENT AUTORISÉ UNIQUEMENT

**CET OUTIL EST DESTINÉ EXCLUSIVEMENT :**
- Aux tests de pénétration **AUTORISÉS** 
- Aux audits de sécurité **LÉGAUX**
- À l'analyse de vos **PROPRES SYSTÈMES**
- Aux missions Red Team **CONTRACTUELLES**

### ❌ USAGE INTERDIT

**IL EST FORMELLEMENT INTERDIT d'utiliser cet outil pour :**
- Scanner des systèmes **SANS AUTORISATION ÉCRITE**
- Effectuer des tests sur des infrastructures **TIERCES**
- Mener des activités **ILLÉGALES** ou **MALVEILLANTES**
- Violer les conditions d'utilisation des services tiers

### 📜 RESPONSABILITÉ LÉGALE

**L'utilisateur est SEUL RESPONSABLE de :**
- Obtenir les **AUTORISATIONS LÉGALES** nécessaires
- Respecter la **LÉGISLATION LOCALE** en vigueur
- Utiliser l'outil dans un **CADRE LÉGAL** uniquement
- Les **CONSÉQUENCES** de son utilisation

**⚖️ En utilisant cet outil, vous acceptez ces conditions et déclarez agir dans le cadre légal.**

---

## 📦 Installation

### Prérequis système

- **OS supportés :** Linux (Fedora/RHEL/CentOS recommandés)
- **Droits :** Utilisateur standard (sudo pour l'installation des dépendances)
- **Espace disque :** ~500MB pour les outils + rapports
- **Connexion Internet :** Requise pour OSINT et APIs

### Installation des dépendances

#### Dépendances REQUISES
```bash
# Fedora/RHEL/CentOS
sudo dnf install -y whois nmap traceroute curl bind-utils

# Ubuntu/Debian
sudo apt update && sudo apt install -y whois nmap traceroute curl dnsutils
```

#### Outils Red Team OPTIONNELS (recommandés)
```bash
# Fedora/RHEL/CentOS
sudo dnf install -y pandoc texlive-xetex sslscan GeoIP jq masscan nikto dirb gobuster sqlmap hydra

# Ubuntu/Debian  
sudo apt install -y pandoc texlive-xetex sslscan geoip-bin jq masscan nikto dirb gobuster sqlmap hydra
```

#### Outils spécialisés (installation manuelle)
```bash
# Sublist3r (énumération sous-domaines)
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r && pip3 install -r requirements.txt

# DNSEnum
git clone https://github.com/fwaeytens/dnsenum.git

# Fierce (DNS)
pip3 install fierce
```

### Téléchargement de l'outil

```bash
# Cloner ou télécharger les scripts
wget https://example.com/run_analyse_ip_precheck.sh
wget https://example.com/analyse_ip_public_ameliore.sh

# Rendre exécutables
chmod +x run_analyse_ip_precheck.sh analyse_ip_public_ameliore.sh
```

---

## 🎯 Utilisation

### Lancement rapide
```bash
./run_analyse_ip_precheck.sh
```

### Modes d'opération

#### 1. **Mode Standard** (Agressivité niveau 2)
```bash
# Lancement interactif avec questions
./run_analyse_ip_precheck.sh
# Saisir l'IP cible quand demandé
# Choisir niveau 2 pour un équilibre performance/discrétion
```

#### 2. **Mode Furtif** (Discrétion maximale)
```bash
# Répondre "y" à "Mode furtif"
# Utilise des délais, fragmentation, decoys
# Évite les scans trop agressifs
# Recommandé pour les environnements surveillés
```

#### 3. **Mode Agressif** (Niveau 3)
```bash
# Choisir niveau 3 d'agressivité
# Scans complets et rapides
# Tests d'évasion activés
# Pour environnements de test internes
```

### Paramètres configurables

L'outil demande interactivement :
- **IP cible** : L'adresse IP à auditer
- **Niveau d'agressivité** : 1 (léger), 2 (standard), 3 (agressif)
- **Mode furtif** : Techniques d'évasion discrètes
- **Tests d'évasion** : Bypass IDS/IPS avancés

---

## 📊 Structure des résultats

### Arborescence générée
```
audit_IP_YYYYMMDD_HHMMSS/
├── timeline.log              # Chronologie détaillée
├── RAPPORT_EXECUTIF.md       # Synthèse pour management
├── RedTeam_Audit_IP.pdf      # Rapport PDF complet
├── recon/                    # Reconnaissance passive
│   ├── whois.txt
│   ├── dns_records.txt
│   ├── traceroute.txt
│   └── connectivity_test.txt
├── osint/                    # Intelligence sources ouvertes
│   ├── shodan.json
│   ├── virustotal.json
│   ├── censys.json
│   └── bgpview.json
├── enum/                     # Énumération active
│   ├── nmap_discovery.txt
│   ├── service_versions.txt
│   └── os_fingerprint.txt
├── vulnscan/                 # Analyse vulnérabilités
│   ├── nmap_vulns.txt
│   ├── ssl_analysis.txt
│   └── smb_analysis.txt
├── web/                      # Tests web (si applicable)
│   ├── nikto_scan.txt
│   ├── dirb_enum.txt
│   └── ssl_certs.txt
└── evasion/                  # Tests d'évasion
    ├── firewall_test.txt
    ├── fragmentation.txt
    └── decoy_scan.txt
```

### Types de rapports

#### 📋 **RAPPORT_EXECUTIF.md**
- Synthèse pour le management
- Ports ouverts critiques
- Services à risque identifiés
- Vulnérabilités découvertes
- Recommandations prioritaires

#### 📄 **RedTeam_Audit_IP.pdf**
- Rapport technique complet
- Tous les détails des scans
- Captures d'écrans des outils
- Méthodologie utilisée

#### 📝 **timeline.log**
- Horodatage de chaque action
- Durée des opérations
- Statuts de réussite/échec
- Traçabilité complète

---

## 🔧 Configuration avancée

### APIs externes (optionnelles)

Pour des résultats OSINT enrichis, configurez vos clés API :

```bash
# Variables d'environnement
export SHODAN_API_KEY="votre_clé_shodan"
export VT_API_KEY="votre_clé_virustotal"
export CENSYS_API_ID="votre_id_censys"
export CENSYS_SECRET="votre_secret_censys"
```

### Personnalisation des scans

Modifiez les variables dans `analyse_ip_public_ameliore.sh` :

```bash
# Délais entre scans (secondes)
SCAN_DELAY=1

# Nombre de processus parallèles
MAX_PARALLEL=50

# Timeout des connexions
TIMEOUT=10

# Ports personnalisés
CUSTOM_PORTS="21,22,23,25,53,80,135,139,443,445,993,995,3389,5900"
```

---

## 🛠️ Dépannage

### Problèmes courants

#### ❌ "Commande non trouvée"
```bash
# Vérifier l'installation des dépendances
./run_analyse_ip_precheck.sh
# Suivre les instructions d'installation affichées
```

#### ❌ "Permission denied"
```bash
# Rendre les scripts exécutables
chmod +x *.sh
```

#### ❌ "Pas de résultats OSINT"
```bash
# Vérifier la connectivité Internet
curl -I https://www.shodan.io
# Configurer les clés API si nécessaire
```

#### ❌ "PDF non généré"
```bash
# Installer les dépendances PDF
sudo dnf install -y pandoc texlive-xetex
# Ou utiliser le rapport Markdown
```

### Logs et debug

```bash
# Activer le mode debug
export DEBUG=1
./run_analyse_ip_precheck.sh

# Consulter les logs détaillés
tail -f audit_*/timeline.log
```

---

## 📈 Bonnes pratiques

### ✅ Recommandations d'usage

1. **Toujours obtenir une autorisation écrite** avant tout scan
2. **Commencer par le mode furtif** sur des systèmes de production
3. **Programmer les scans** pendant les heures creuses
4. **Documenter le scope** et les exclusions
5. **Sauvegarder les rapports** pour la traçabilité

### ⚡ Optimisation des performances

```bash
# Scan rapide (reconnaissance légère)
# Choisir agressivité niveau 1

# Scan complet (audit approfondi)
# Choisir agressivité niveau 3 + tests d'évasion

# Scan furtif (environnement surveillé)
# Activer mode furtif + agressivité niveau 1
```

### 🔒 Considérations de sécurité

- **Chiffrer les rapports** sensibles
- **Utiliser un VPN** pour les tests externes
- **Nettoyer les traces** après les tests
- **Respecter les fenêtres de maintenance**

---

## 🤝 Support et contribution

### 📞 Support

- **Issues** : Signaler les bugs via GitHub Issues
- **Documentation** : Wiki du projet
- **Contact** : [labtest@keemail.me]

### 🔄 Mises à jour

```bash
# Vérifier les nouvelles versions
git pull origin main

# Mettre à jour les dépendances
sudo dnf update nmap masscan nikto
```

### 🎁 Contributions

Les contributions sont les bienvenues :
- Fork du projet
- Nouvelles fonctionnalités
- Corrections de bugs
- Améliorations de documentation

---

## 📜 Licence

```
Copyright (c) 2024 RedTeam Security Tools

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🏆 Crédits

Cet outil intègre et orchestre plusieurs outils open-source reconnus :

- **Nmap** - Network exploration and security auditing
- **Masscan** - Fast port scanner
- **Shodan** - Internet-connected device search engine
- **VirusTotal** - File and URL scanning service
- **Nikto** - Web server scanner
- **SSLScan** - SSL/TLS configuration scanner
- **Dirb** - Web directory scanner
- **Gobuster** - Directory/file brute-forcer

**Merci à toute la communauté sécurité qui rend ces outils possibles !**

---

**🎯 Happy Red Teaming! Stay legal, stay ethical! 🎯**

