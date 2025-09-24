#!/usr/bin/env bash
# run_analyse_ip_precheck.sh - Version Red Team complète
# Wrapper qui vérifie dépendances + scope IP avant d'appeler analyse_ip_public_ameliore.sh

set -euo pipefail

SCRIPT="./analyse_ip_public_ameliore.sh"
if [ ! -f "$SCRIPT" ]; then
  echo "[ERROR] Le script de base '$SCRIPT' est introuvable dans le répertoire courant."
  exit 1
fi

# Détection du gestionnaire de paquets
detect_package_manager() {
    if command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    elif command -v yum >/dev/null 2>&1; then
        echo "yum"
    elif command -v apt-get >/dev/null 2>&1; then
        echo "apt-get"
    elif command -v pacman >/dev/null 2>&1; then
        echo "pacman"
    else
        echo "unknown"
    fi
}

PKG_MANAGER=$(detect_package_manager)

# Dépendances avec packages pour différentes distributions
declare -A REQUIRED_CMDS=(
    [whois]="whois"
    [nmap]="nmap" 
    [traceroute]="traceroute"
    [curl]="curl"
    [dig]="bind-utils"
)

declare -A OPTIONAL_CMDS=(
    [pandoc]="pandoc"
    [xelatex]="texlive-xetex"
    [sslscan]="sslscan"
    [geoiplookup]="GeoIP"
    [jq]="jq"
    [masscan]="masscan"
    [nikto]="nikto"
    [dirb]="dirb"
    [gobuster]="gobuster"
    [sqlmap]="sqlmap"
    [hydra]="hydra"
    [dnsenum]="dnsenum"
)

missing_required=()
missing_optional=()

echo "🔍 Vérification des dépendances..."

# Vérification des dépendances requises
for cmd in "${!REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        missing_required+=("$cmd:${REQUIRED_CMDS[$cmd]}")
    fi
done

# Vérification des dépendances optionnelles
for cmd in "${!OPTIONAL_CMDS[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        missing_optional+=("$cmd:${OPTIONAL_CMDS[$cmd]}")
    fi
done

# Fonction d'installation
install_packages() {
    local packages=("$@")
    local pkg_names=()
    
    for item in "${packages[@]}"; do
        pkg_names+=($(echo "$item" | cut -d: -f2))
    done
    
    case "$PKG_MANAGER" in
        dnf)
            echo "Installation avec DNF..."
            sudo dnf install -y "${pkg_names[@]}"
            ;;
        yum)
            echo "Installation avec YUM..."
            sudo yum install -y "${pkg_names[@]}"
            ;;
        apt-get)
            echo "Installation avec APT..."
            sudo apt-get update
            sudo apt-get install -y "${pkg_names[@]}"
            ;;
        pacman)
            echo "Installation avec Pacman..."
            sudo pacman -S --noconfirm "${pkg_names[@]}"
            ;;
        *)
            echo "[ERROR] Gestionnaire de paquets non supporté. Installez manuellement :"
            printf -- "- %s\n" "${pkg_names[@]}"
            return 1
            ;;
    esac
}

# Traitement des dépendances REQUISES
if [ ${#missing_required[@]} -ne 0 ]; then
    echo
    echo "❌ === Dépendances REQUISES manquantes ==="
    for item in "${missing_required[@]}"; do
        cmd=$(echo "$item" | cut -d: -f1)
        pkg=$(echo "$item" | cut -d: -f2)
        echo " - $cmd (paquet: $pkg)"
    done
    echo
    
    if [ "$(id -u)" -eq 0 ]; then
        echo "🔧 Installation automatique des dépendances requises..."
        if install_packages "${missing_required[@]}"; then
            echo "✅ Installation réussie !"
        else
            echo "❌ Échec d'installation. Veuillez installer manuellement."
            exit 2
        fi
    else
        read -p "Voulez-vous installer les dépendances requises maintenant ? [Y/n] " yn
        case "$yn" in
            [Nn]* )
                echo "❌ Installation refusée. Le script ne peut pas continuer."
                exit 2
                ;;
            * )
                if install_packages "${missing_required[@]}"; then
                    echo "✅ Installation réussie !"
                else
                    echo "❌ Échec d'installation. Veuillez installer manuellement."
                    exit 2
                fi
                ;;
        esac
    fi
    
    # Revérification des dépendances requises
    echo "🔄 Vérification post-installation..."
    still_missing=()
    for item in "${missing_required[@]}"; do
        cmd=$(echo "$item" | cut -d: -f1)
        if ! command -v "$cmd" >/dev/null 2>&1; then
            still_missing+=("$cmd")
        fi
    done
    
    if [ ${#still_missing[@]} -ne 0 ]; then
        echo "❌ Certains outils requis ne sont toujours pas disponibles :"
        printf -- "- %s\n" "${still_missing[@]}"
        echo "Veuillez les installer manuellement avant de continuer."
        exit 2
    fi
    
    echo "✅ Toutes les dépendances requises sont maintenant installées !"
fi

# Traitement des dépendances OPTIONNELLES
if [ ${#missing_optional[@]} -ne 0 ]; then
    echo
    echo "⚠️  === Outils Red Team OPTIONNELS absents ==="
    for item in "${missing_optional[@]}"; do
        cmd=$(echo "$item" | cut -d: -f1)
        pkg=$(echo "$item" | cut -d: -f2)
        echo " - $cmd (paquet: $pkg)"
    done
    echo
    echo "Le script fonctionnera mais certaines fonctionnalités Red Team seront limitées."
    
    read -p "Voulez-vous installer les outils Red Team optionnels ? [y/N] " yn
    case "$yn" in
        [Yy]* )
            if install_packages "${missing_optional[@]}"; then
                echo "✅ Installation des outils optionnels réussie !"
                
                # Vérification des outils installés
                installed_count=0
                for item in "${missing_optional[@]}"; do
                    cmd=$(echo "$item" | cut -d: -f1)
                    if command -v "$cmd" >/dev/null 2>&1; then
                        ((installed_count++))
                    fi
                done
                echo "📊 $installed_count/${#missing_optional[@]} outils optionnels installés avec succès"
            else
                echo "⚠️  Certains outils optionnels n'ont pas pu être installés (repos supplémentaires requis ?)"
            fi
            ;;
        * )
            echo "⏭️  Continuation sans les outils Red Team optionnels."
            ;;
    esac
fi

echo "✅ Vérification des dépendances terminée !"

# Configuration Red Team
echo
echo "⚙️  === Configuration Red Team ==="
read -p "Mode furtif activé ? (scans plus lents mais discrets) [y/N] " STEALTH_MODE
read -p "Activer les tests d'évasion IDS/IPS ? [y/N] " EVASION_MODE
read -p "Niveau d'agressivité (1=passif, 2=normal, 3=agressif) [2] : " AGGRESSIVENESS
AGGRESSIVENESS=${AGGRESSIVENESS:-2}

# Export des variables pour le script principal
export STEALTH_MODE EVASION_MODE AGGRESSIVENESS

# Demande IP pour détecter scope
read -p "Entrez l'IP que vous allez analyser : " IP
if [[ -z "$IP" ]]; then
  echo "[ERROR] Aucune IP fournie. Sortie."
  exit 1
fi

# Validation IP
if ! [[ "$IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  echo "[ERROR] Format IP invalide"
  exit 1
fi

# Détecter IP privée RFC1918
if [[ "$IP" =~ ^10\. ]] || [[ "$IP" =~ ^192\.168\. ]] || [[ "$IP" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
  echo "[INFO] IP privée détectée ($IP) - certains tests OSINT seront ignorés"
else
  echo "[INFO] IP publique détectée ($IP) - audit complet disponible"
fi

echo
echo "⚠️  === AVERTISSEMENT LÉGAL ==="
echo "N'utilisez ce script que sur des cibles que vous êtes autorisé(e) à tester."
echo "L'utilisation non autorisée peut violer les lois locales et internationales."
read -p "Confirmez-vous que vous avez l'autorisation de tester cette IP ? [y/N] " confirm
case "$confirm" in
  [Yy]* ) ;;
  * ) echo "❌ Annulation pour des raisons légales."; exit 0 ;;
esac

# Lancer le script de base
echo
echo "🚀 Lancement de l'audit Red Team : $SCRIPT"
bash "$SCRIPT" "$IP"
