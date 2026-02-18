#!/usr/bin/env bash
set -euo pipefail

# ===== Helpers =====
log()  { echo -e "\e[1;32m[+]\e[0m $*"; }
warn() { echo -e "\e[1;33m[!]\e[0m $*"; }
err()  { echo -e "\e[1;31m[x]\e[0m $*" >&2; }

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    err "Run script as root (use sudo -i)."; exit 1
  fi
}

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  cp -a "$f" "${f}.bak.$(date +%Y%m%d-%H%M%S)"
}

comment_conflicting_directives() {
  local d="/etc/ssh/sshd_config.d"
  [[ -d "$d" ]] || return 0
  for f in "$d"/*.conf; do
    [[ -e "$f" ]] || continue
    backup_file "$f"
    sed -i -E \
      's/^[[:space:]]*#?[[:space:]]*(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|MaxAuthTries|LoginGraceTime)[[:space:]].*$/# disabled by installer: &/I' \
      "$f"
  done
}

apply_sshd_directive() {
  local key="$1" val="$2"
  if grep -qiE "^[#[:space:]]*${key}[[:space:]]" /etc/ssh/sshd_config; then
    sed -i -E "s|^[#[:space:]]*${key}[[:space:]].*$|${key} ${val}|I" /etc/ssh/sshd_config
  else
    echo "${key} ${val}" >> /etc/ssh/sshd_config
  fi
}

detect_ipv4() {
  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -n "${ip:-}" ]] && echo "$ip" || curl -s https://api.ipify.org || echo "<IP>"
}

# ===== Check Ubuntu version =====
check_ubuntu_version() {
  if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    if [[ "$ID" == "ubuntu" && "$VERSION_ID" == "24.04" ]]; then
      log "Detected Ubuntu 24.04 LTS"
      return 0
    else
      log "Detected $NAME $VERSION_ID (not Ubuntu 24.04)"
      return 1
    fi
  else
    warn "Cannot detect OS version"
    return 1
  fi
}

# ===== Docker installation function (Ubuntu 24.04 only) =====
install_docker_tools() {
  local user="$1"
  
  log "Installing Docker, Docker Compose, and lazydocker for Ubuntu 24.04..."
  
  # Install prerequisites
  apt install -y apt-transport-https ca-certificates gnupg lsb-release software-properties-common
  
  # Add Docker's official GPG key
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  
  # Add the repository
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
  
  # Install Docker Engine
  apt update
  apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  
  # Add user to docker group
  usermod -aG docker "$user"
  
  # Install lazydocker
  log "Installing lazydocker..."
  
  # Detect architecture
  ARCH=$(uname -m)
  case $ARCH in
    x86_64)
      ARCH="amd64"
      ;;
    aarch64)
      ARCH="arm64"
      ;;
    armv7l)
      ARCH="armv7"
      ;;
    *)
      warn "Unsupported architecture for lazydocker: $ARCH. Skipping lazydocker installation."
      return 0
      ;;
  esac
  
  # Get latest version
  LATEST_VERSION=$(curl -s https://api.github.com/repos/jesseduffield/lazydocker/releases/latest | jq -r .tag_name)
  if [[ -n "$LATEST_VERSION" && "$LATEST_VERSION" != "null" ]]; then
    VERSION_NUMBER=${LATEST_VERSION#v}
    DOWNLOAD_URL="https://github.com/jesseduffield/lazydocker/releases/download/${LATEST_VERSION}/lazydocker_${VERSION_NUMBER}_Linux_${ARCH}.tar.gz"
    
    curl -L "$DOWNLOAD_URL" -o /tmp/lazydocker.tar.gz
    tar -xzf /tmp/lazydocker.tar.gz -C /tmp lazydocker
    mv /tmp/lazydocker /usr/local/bin/
    chmod +x /usr/local/bin/lazydocker
    rm -f /tmp/lazydocker.tar.gz
    log "lazydocker installed successfully"
  else
    warn "Could not fetch latest lazydocker version. Skipping installation."
  fi
  
  # Create docker directory in user home
  sudo -u "$user" mkdir -p "/home/$user/.docker"
  
  log "Docker tools installation completed"
}

# ===== Function to disable ping (ICMP) =====
disable_ping() {
  log "Disabling ping (ICMP echo requests)..."

  # Method 1: Using sysctl (kernel parameter)
  local SYSCTL_CONF="/etc/sysctl.d/99-disable-ping.conf"
  backup_file "$SYSCTL_CONF" || true
  
  cat > "$SYSCTL_CONF" <<'EOF'
# Disable ping responses (ICMP echo requests)
net.ipv4.icmp_echo_ignore_all = 1
net.ipv6.icmp.echo_ignore_all = 1
EOF

  # Apply sysctl settings
  sysctl --system >/dev/null
  
  # Method 2: Also configure UFW to block ICMP (redundant but thorough)
  # Backup original before/after rules
  local UFW_BEFORE="/etc/ufw/before.rules"
  local UFW_BEFORE6="/etc/ufw/before6.rules"
  
  if [[ -f "$UFW_BEFORE" ]]; then
    backup_file "$UFW_BEFORE"
    
    # Add rules to block ICMP in before.rules (insert after the header)
    # Check if rules already exist to avoid duplicates
    if ! grep -q "# Block ICMP ping requests" "$UFW_BEFORE"; then
      sed -i '/^# ok icmp codes for INPUT/i # Block ICMP ping requests\n-A ufw-before-input -p icmp --icmp-type echo-request -j DROP\n' "$UFW_BEFORE"
    fi
  fi
  
  if [[ -f "$UFW_BEFORE6" ]]; then
    backup_file "$UFW_BEFORE6"
    
    # Add rules to block ICMPv6 in before6.rules
    if ! grep -q "# Block ICMPv6 ping requests" "$UFW_BEFORE6"; then
      sed -i '/^# ok icmp codes for INPUT/i # Block ICMPv6 ping requests\n-A ufw-before-input -p icmpv6 --icmpv6-type echo-request -j DROP\n' "$UFW_BEFORE6"
    fi
  fi
  
  # Reload UFW to apply new rules
  ufw reload >/dev/null 2>&1 || true
  
  log "Ping (ICMP) has been disabled"
  
  # Test and show result
  if sysctl net.ipv4.icmp_echo_ignore_all | grep -q "= 1"; then
    log "Verified: ICMP echo ignore is enabled"
  else
    warn "ICMP echo ignore may not be properly configured"
  fi
}

# ===== Function to enable ping (ICMP) =====
enable_ping() {
  log "Enabling ping (ICMP echo requests)..."

  # Method 1: Remove sysctl configuration
  local SYSCTL_CONF="/etc/sysctl.d/99-disable-ping.conf"
  if [[ -f "$SYSCTL_CONF" ]]; then
    mv "$SYSCTL_CONF" "${SYSCTL_CONF}.disabled.$(date +%Y%m%d-%H%M%S)"
  fi
  
  # Set kernel parameters to allow ping
  sysctl -w net.ipv4.icmp_echo_ignore_all=0 >/dev/null
  sysctl -w net.ipv6.icmp.echo_ignore_all=0 >/dev/null
  
  # Method 2: Remove UFW ICMP blocks
  local UFW_BEFORE="/etc/ufw/before.rules"
  local UFW_BEFORE6="/etc/ufw/before6.rules"
  
  if [[ -f "$UFW_BEFORE" ]]; then
    backup_file "$UFW_BEFORE"
    # Remove the ICMP block lines we added
    sed -i '/# Block ICMP ping requests/d' "$UFW_BEFORE"
    sed -i '/-A ufw-before-input -p icmp --icmp-type echo-request -j DROP/d' "$UFW_BEFORE"
  fi
  
  if [[ -f "$UFW_BEFORE6" ]]; then
    backup_file "$UFW_BEFORE6"
    # Remove the ICMPv6 block lines we added
    sed -i '/# Block ICMPv6 ping requests/d' "$UFW_BEFORE6"
    sed -i '/-A ufw-before-input -p icmpv6 --icmpv6-type echo-request -j DROP/d' "$UFW_BEFORE6"
  fi
  
  # Reload UFW to apply changes
  ufw reload >/dev/null 2>&1 || true
  
  # Apply sysctl settings persistently
  sysctl --system >/dev/null
  
  log "Ping (ICMP) has been enabled"
}

# ===== Start =====
require_root
export DEBIAN_FRONTEND=noninteractive

# Check Ubuntu version
IS_UBUNTU_24=false
if check_ubuntu_version; then
  IS_UBUNTU_24=true
fi

log "Updating system and installing dependencies…"
apt update
apt -y upgrade
apt -y install curl ufw sudo openssl jq lsof

# --- Create user (with password!) ---
read -rp "Enter new username (no spaces): " NEWUSER
if id "$NEWUSER" &>/dev/null; then
  warn "User $NEWUSER already exists. You can update password."
else
  adduser --gecos "" "$NEWUSER"   # adduser is interactive; will ask for password
fi

# If adduser didn't ask for password (some images), ask ourselves
if [[ -z "$(getent shadow "$NEWUSER" | cut -d: -f2)" || "$(getent shadow "$NEWUSER" | cut -d: -f2)" == "!" ]]; then
  while true; do
    read -srp "Set password for: ${NEWUSER}: " PW1; echo
    read -srp "Repeat password: " PW2; echo
    [[ "$PW1" == "$PW2" && ${#PW1} -ge 8 ]] && break
    warn "Passwords don't match or are shorter than 8 characters. Try again."
  done
  echo "${NEWUSER}:${PW1}" | chpasswd
  unset PW1 PW2
fi

usermod -aG sudo "$NEWUSER"

# --- SSH keys ---
echo
echo "1) Enter public key"
echo "2) Generate new keypair (ed25519, you can add passphrase)"
read -rp "Choose [1/2]: " KEYMODE
install -d -m 700 "/home/$NEWUSER/.ssh"

if [[ "${KEYMODE:-1}" == "2" ]]; then
  KEYDIR="/root/generated-keys"
  mkdir -p "$KEYDIR"
  ssh-keygen -t ed25519 -f "$KEYDIR/${NEWUSER}_id_ed25519" -C "${NEWUSER}@$(hostname)"
  install -m 600 "$KEYDIR/${NEWUSER}_id_ed25519.pub" "/home/$NEWUSER/.ssh/authorized_keys"
  warn "Download private key and delete it from server: $KEYDIR/${NEWUSER}_id_ed25519"
else
  read -rp "Enter public key: " SSHKEY
  printf '%s\n' "$SSHKEY" > "/home/$NEWUSER/.ssh/authorized_keys"
  chmod 600 "/home/$NEWUSER/.ssh/authorized_keys"
fi
chown -R "$NEWUSER:$NEWUSER" "/home/$NEWUSER/.ssh"

# --- SSH configuration (port and hardening) ---
read -rp "New SSH port (example 5569): " NEWPORT
[[ "$NEWPORT" =~ ^[0-9]+$ ]] || { err "Incorrect port"; exit 1; }

backup_file /etc/ssh/sshd_config
comment_conflicting_directives

apply_sshd_directive "Port" "$NEWPORT"
apply_sshd_directive "PermitRootLogin" "no"
apply_sshd_directive "PasswordAuthentication" "no"
apply_sshd_directive "PubkeyAuthentication" "yes"
apply_sshd_directive "MaxAuthTries" "3"
apply_sshd_directive "LoginGraceTime" "20s"
apply_sshd_directive "ClientAliveInterval" "300"
apply_sshd_directive "ClientAliveCountMax" "2"

# --- Firewall (UFW) ---
log "Setting up UFW…"
ufw --force reset >/dev/null 2>&1 || true
ufw default deny incoming
ufw default allow outgoing

# Don't lock ourselves out during port change: temporarily keep 22/tcp
ufw allow 22/tcp
ufw limit "${NEWPORT}/tcp"
ufw allow 443/tcp

# Apply and enable before restarting sshd
ufw --force enable

# --- Ask about Docker installation (only for Ubuntu 24.04) ---
if [[ "$IS_UBUNTU_24" == true ]]; then
  echo
  read -rp "Do you want to install Docker, Docker Compose, and lazydocker? (y/n): " INSTALL_DOCKER
  if [[ "$INSTALL_DOCKER" =~ ^[Yy]$ ]]; then
    install_docker_tools "$NEWUSER"
  else
    log "Skipping Docker tools installation"
  fi
else
  INSTALL_DOCKER="n"
  log "Skipping Docker tools installation (requires Ubuntu 24.04)"
fi

# --- Ask about disabling ping (ICMP) ---
echo
read -rp "Do you want to disable ping (ICMP echo requests) for better stealth? (y/n): " DISABLE_PING
if [[ "$DISABLE_PING" =~ ^[Yy]$ ]]; then
  disable_ping
else
  log "Keeping ping (ICMP) enabled"
fi

--- Install 3x-ui (optional - uncomment if needed) ---
echo
read -rp "Do you want to install 3x-ui? (y/n): " INSTALL_3XUI
if [[ "$INSTALL_3XUI" =~ ^[Yy]$ ]]; then
  log "Installing 3x-ui…"
  bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)
fi

--- Generate self-signed SSL (optional - uncomment if needed) ---
echo
read -rp "Do you want to generate self-signed SSL certificates? (y/n): " GENERATE_SSL
if [[ "$GENERATE_SSL" =~ ^[Yy]$ ]]; then
  CERTDIR="/etc/ssl/3xui"
  mkdir -p "$CERTDIR"
  IPV4="$(detect_ipv4)"
  CN="${IPV4:-$(hostname)}"
  
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$CERTDIR/selfsigned.key" \
    -out   "$CERTDIR/selfsigned.crt" \
    -subj "/CN=${CN}"
  
  chmod 600 "$CERTDIR/selfsigned.key"
  chmod 644 "$CERTDIR/selfsigned.crt"
  log "Self-signed certificates generated in $CERTDIR"
fi

# --- Enable BBR (via sysctl.d) ---
CONF_BBR="/etc/sysctl.d/99-bbr.conf"
backup_file "$CONF_BBR" || true
cat > "$CONF_BBR" <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
sysctl --system >/dev/null

# --- Restart SSH with syntax check ---
log "Testing SSH configuration..."
sshd -t
log "Restarting SSH service..."
systemctl restart sshd

# --- Final output and post-steps ---
IPV4="$(detect_ipv4)"
IP_SHOW="${IPV4:-<IP>}"

# Prepare Docker section for output
DOCKER_OUTPUT=""
if [[ "$IS_UBUNTU_24" == true ]]; then
  if [[ "$INSTALL_DOCKER" =~ ^[Yy]$ ]]; then
    DOCKER_OUTPUT=$(cat <<EOF

▶ Docker Tools Installed (Ubuntu 24.04):
   - Docker Engine: $(docker --version 2>/dev/null | head -n1 || echo "Check after login")
   - Docker Compose: $(docker compose version 2>/dev/null || echo "Check after login")
   - lazydocker: $(lazydocker --version 2>/dev/null || echo "Check after login")
   
   Your user '$NEWUSER' has been added to the 'docker' group.
   You'll need to log out and back in (or run 'newgrp docker') to use Docker without sudo.

▶ Quick Docker Commands:
   - List containers: docker ps
   - Compose help: docker compose --help
   - TUI for Docker: lazydocker

▶ Docker Post-Install:
   After logging out and back in, verify Docker works:
       docker run hello-world
EOF
)
  else
    DOCKER_OUTPUT="\n▶ Docker Tools: Not installed (skipped by user)"
  fi
else
  DOCKER_OUTPUT="\n▶ Docker Tools: Not installed (requires Ubuntu 24.04 - detected: $(lsb_release -ds 2>/dev/null || echo 'other OS'))"
fi

# Prepare Ping section for output
PING_OUTPUT=""
if [[ "$DISABLE_PING" =~ ^[Yy]$ ]]; then
  PING_OUTPUT="\n▶ Ping (ICMP): Disabled - Server will not respond to ping requests (stealth mode)"
else
  PING_OUTPUT="\n▶ Ping (ICMP): Enabled - Server responds to ping requests"
fi

cat <<EOF

========================================
✅ Complete! Server has been hardened.${DOCKER_OUTPUT}${PING_OUTPUT}

▶ SSH Access:
   ssh -p ${NEWPORT} ${NEWUSER}@${IP_SHOW} -i <path_to_private_key>

   IMPORTANT: Port 22/tcp is temporarily open to prevent lockout.
   If login works on the new port, close port 22:
       sudo ufw delete allow 22/tcp

▶ Firewall (UFW):
   - SSH (limit)    : ${NEWPORT}/tcp
   - VPN/Xray       : 443/tcp
   - Temporarily open: 22/tcp (remove after testing)

▶ Security Recommendations:
   1) Test SSH login with new user and new port.
   2) Remove 22/tcp rule: ufw delete allow 22/tcp
   3) Regular updates: apt update && apt upgrade -y

▶ Network Configuration:
   - BBR Congestion Control: Enabled (improves network performance)
   $(if [[ "$DISABLE_PING" =~ ^[Yy]$ ]]; then echo "  - ICMP Ping: Disabled (server is stealth)"; else echo "  - ICMP Ping: Enabled"; fi)

▶ To re-enable ping if needed:
   sudo sysctl -w net.ipv4.icmp_echo_ignore_all=0
   # And remove the sysctl configuration file:
   sudo rm -f /etc/sysctl.d/99-disable-ping.conf
   sudo sysctl --system

========================================

🌵🌵🌵 All done! Dancing cactus celebrates your secure server! 🌵🌵🌵

        \\   ^__^
         \\  (oo)\_______
            (__)\\       )\\/\\
                ||----w |
                ||     ||
                
EOF