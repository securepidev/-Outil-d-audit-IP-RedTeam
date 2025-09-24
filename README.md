# 🎯 RedTeam IP Audit Tool

[![Linux](https://img.shields.io/badge/Platform-Linux-blue.svg)](https://www.linux.org/)
[![Bash](https://img.shields.io/badge/Language-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 📋 Description

Suite d'audit de sécurité automatisée conçue pour les équipes Red Team et les professionnels du pentest. Cet outil effectue une reconnaissance complète, une découverte de services, une analyse de vulnérabilités et génère des rapports détaillés, le tout compatible avec **toutes les distributions Linux** grâce à sa détection automatique du gestionnaire de paquets.

### 🐧 Compatibilité Universelle Linux

✅ **Fedora/RHEL/CentOS** (DNF/YUM)  
✅ **Ubuntu/Debian** (APT)  
✅ **Arch Linux** (Pacman)  
✅ **SUSE/openSUSE** (Zypper)  

L'outil détecte automatiquement votre distribution et installe les dépendances avec le bon gestionnaire de paquets.

---

## ⚠️ AVERTISSEMENT LÉGAL

**🚨 USAGE STRICTEMENT AUTORISÉ UNIQUEMENT**

Cet outil est destiné exclusivement aux tests de pénétration autorisés, audits de sécurité légaux et analyse de vos propres systèmes. **L'utilisateur est seul responsable** du respect de la législation locale et de l'obtention des autorisations nécessaires.

---

## 🚀 Installation Rapide

```bash
# 1. Cloner le dépôt
git clone https://github.com/votre-username/redteam-ip-audit.git

# 2. Accéder au dossier
cd [Nouveaux dossier}

# 3. Rendre les scripts exécutables
chmod +x run_analyse_ip_precheck.sh analyse_ip_public_ameliore.sh

# 4. Lancer l'outil
./run_analyse_ip_precheck.sh
```

Le script `precheck` détectera automatiquement votre distribution Linux et installera toutes les dépendances nécessaires avant de lancer l'audit de sécurité.


---

## 🎯 Fonctionnalités Principales

### 🔍 **Reconnaissance Multi-Sources**
- Analyse WHOIS et géolocalisation
- APIs OSINT (Shodan, VirusTotal, Censys)
- Historique DNS et certificats SSL

### ⚡ **Découverte Active**
- Scans de ports optimisés (Nmap + Masscan)
- Détection de services et versions
- Tests de connectivité avancés

### 🐛 **Tests de Vulnérabilités**
- Scripts Nmap vulnérabilités
- Tests spécifiques (EternalBlue, Heartblue, BlueKeep)
- Analyse SSL/TLS complète

### 🥷 **Modes Furtifs et d'Évasion**
- Fragmentation IP et Decoy scanning
- Délais configurables pour éviter la détection
- Contournement IDS/IPS

### 📊 **Rapports Professionnels**
- Rapport exécutif Markdown
- Export PDF automatique (si LaTeX disponible)
- Timeline détaillée avec horodatage

---

## 💻 Utilisation

### Lancement Standard
```bash
./run_analyse_ip_precheck.sh
```

L'outil demande interactivement :
- IP cible à auditer
- Niveau d'agressivité (1-3)
- Activation du mode furtif
- Tests d'évasion IDS/IPS

### Modes d'Opération

| Mode | Description | Usage |
|------|-------------|-------|
| **Niveau 1** | Reconnaissance passive | Environnements sensibles |
| **Niveau 2** | Audit standard | Usage général recommandé |
| **Niveau 3** | Audit complet agressif | Environnements de test |

---

## 📂 Structure des Résultats

```
redteam_audit_YYYYMMDD_HHMMSS_IP/
├── RAPPORT_EXECUTIF.md      # Synthèse management
├── RedTeam_Audit_IP.pdf     # Rapport technique complet
├── timeline.log             # Chronologie détaillée
├── recon/                   # Reconnaissance passive
├── osint/                   # Intelligence ouverte
├── enum/                    # Énumération services
├── vulnscan/               # Analyse vulnérabilités
├── web/                    # Tests applicatifs
└── evasion/                # Tests d'évasion
```

---

## 🔧 Configuration Avancée

### APIs Externes (Optionnelles)
```bash
export SHODAN_API_KEY="votre_clé"
export VT_API_KEY="votre_clé"
export CENSYS_API_ID="votre_id"
```

### Personnalisation
Modifiez les variables dans les scripts pour adapter :
- Délais entre scans
- Ports personnalisés
- Timeouts de connexion
- Niveau de parallélisation

---

## 🛠️ Outils Intégrés

### Requis (Installés automatiquement)
- `nmap` - Scanner réseau
- `whois` - Informations WHOIS  
- `curl` - Requêtes HTTP/API
- `dig` - Requêtes DNS
- `traceroute` - Analyse routage

### Optionnels Red Team
- `masscan` - Scanner ultra-rapide
- `sslscan` - Analyse SSL/TLS
- `nikto` - Scanner web
- `hydra` - Brute force
- `sqlmap` - Test injection SQL
- `gobuster` - Directory busting

---

## 🔍 Dépannage

### Problèmes Courants
```bash
# Vérification des dépendances
./run_analyse_ip_precheck.sh

# Mode debug
export DEBUG=1 && ./run_analyse_ip_precheck.sh

# Logs détaillés
tail -f redteam_audit_*/timeline.log
```

---

## 📈 Bonnes Pratiques

✅ **Toujours obtenir une autorisation écrite**  
✅ **Commencer par le mode furtif**  
✅ **Planifier les scans hors heures de pointe**  
✅ **Documenter le scope et les exclusions**  
✅ **Sauvegarder les rapports pour traçabilité**  

---

## 🤝 Support

- **Issues** : Signalement via GitHub
- **Contact** : [labtest@keemail.me]
- **Documentation** : Wiki du projet

---

## 📜 Licence MIT

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, subject to legal and ethical usage.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
```

---

## 🏆 Crédits

Orchestration de outils open-source reconnus : Nmap, Masscan, Shodan, VirusTotal, Nikto, SSLScan, et autres.

**Merci à la communauté sécurité open-source !**

---

**🎯 Happy Red Teaming! Stay Legal, Stay Ethical! 🎯**

