#!/bin/bash                                                                    #
#                                                                              #
# This script automatically installs and configures a high-security router     #
# with the following software: Apache HTTPS, AppArmor, ClamAV, DDclient,       #
# Bind DNS, Kea DHCP, LTSP, MariaDB, Munin, Nagios, NFS, OpenSSL, OpenVPN,     #
# phpMyAdmin, Postfix SMTP, Privoxy, ProFTPD, Shorewall, Snort, Squid,         #
# SquidClamAV, and Webmin.                                                     #
#                                                                              #
################################################################################
#                                                                              #
# Copyfree 2016                                                                #
#                                                                              #
################################################################################
#                                                                              #
# This script supports Ubuntu Server with two Ethernet adapters.               #
#                                                                              #
# If there is any error condition, view install.log for further details.       #
#                                                                              #
# Run this script with the following command: sudo bash LinuxSOHO.sh.          #
#                                                                              #
################################################################################
#                                                                              
# Manually adjust variables:                                                   
#                                                                              
SERVER_ADMIN="Administrator"                                                   
EMAIL_ADDRESS="admin@example.com"                                              
ORGANIZATION="Example"                                                         
# Use only two-digit country code.                                             
COUNTRY="US"                                                                   
# Spell out the state in full.                                                 
STATE="Oregon"                                                                 
HOSTNAME="or-rt1-ub"                                                           
LAN_INTERFACE="enp0s1"                                                         
LAN_IP_ADDRESS="192.168.0.1"                                                   
LAN_NETMASK="255.255.255.0"                                                    
WAN_INTERFACE="enp0s2"                                                         
# Set the fastest Ubuntu mirror.                                               
UBUNTU_MIRROR="http://archive.ubuntu.com"                               
# Set the path to the LTSP virtual machine (VM). This VM is deployed to all LTSP 
# clients.
LTSP_VM_PATH="$HOME/VirtualBox\ VMs/ubuntu/ubuntu-flat.vmdk"
#                                                                              
################################################################################

# Check for an internet connection.
ping -q -w 1 -c 1 8.8.8.8 > /dev/null
if [ $? -ne 0 ]; then
  clear
  echo ""
  echo "Please check your internet connection."
  echo ""
  exit 1
fi

# Set administrator password.
clear
echo ""
read -rsp "Enter your administrator password: " ADMIN_PASSWORD1
clear
echo ""
read -rsp "Re-enter administrator password to verify: " ADMIN_PASSWORD2
while [ "$ADMIN_PASSWORD1" != "$ADMIN_PASSWORD2" ]; do
  clear
  echo ""
  echo "Your passwords do not match; please try again."
  echo ""
  read -rsp "Enter your administrator password: " ADMIN_PASSWORD1
  clear
  echo ""
  read -rsp "Re-enter administrator password to verify: " ADMIN_PASSWORD2
done
ADMIN_PASSWORD=$ADMIN_PASSWORD1

(# Redirect STDOUT and STDERROR logged to terminal and install.log.

echo "Script start time: $(date +%c)"
echo ""

cat > /etc/apt/preferences << EOF.apt.pinning
# This package is deprecated and replaced with Kea DHCP.
Package: isc-dhcp-server
Pin: version *
Pin-Priority: -100
EOF.apt.pinning

# Apt function to fetch binary software packages.
apt_function() {
  APT="apt-get --yes --allow-unauthenticated \
    -o Dpkg::Options::=--force-confdef,overwrite"
  APT_ARRAY=($*)
  $APT ${APT_ARRAY[*]}
  while [ $? -ne 0 ]; do
    clear
    echo ""
    echo "Unable to connect to software repository, please wait."
    echo ""
    sleep 30
    apt clean all
    rm -f /var/cache/apt/{archives,partial}/lock
    dpkg --force-confdef,overwrite --configure -a
    $APT ${APT_ARRAY[*]}
  done
  return 0
}

# Wget function to fetch and extract .tar.gz archives.
WGET="wget --progress=bar:force --continue --tries=0 \
  --no-dns-cache --no-check-certificate --retry-connrefused"
wget_tar_function() {
  $WGET $1 -O /usr/local/src/$2.tar.gz
  cd /usr/local/src
  tar xzf $2.tar.gz
  while [ $? -ne 0 ]; do
    clear
    echo ""
    echo "Unable to connect to software repository, please wait."
    echo ""
    sleep 60
    rm -rf /usr/local/src/$2*
    $WGET $1 -O /usr/local/src/$2.tar.gz
    cd /usr/local/src
    tar xzf $2.tar.gz
  done
  return 0
}

# Wget function to fetch .deb packages.
wget_deb_function() {
  $WGET $1 -O /usr/local/src/$2.deb
  dpkg -i /usr/local/src/$2.deb
  while [ $? -ne 0 ]; do
    clear
    echo ""
    echo "Unable to connect to software repository, please wait."
    echo "" 
    sleep 30
    rm -f /usr/local/src/$2.deb
    $WGET $1 -O /usr/local/src/$2.deb
    dpkg -i /usr/local/src/$2.deb
  done
  rm -f /usr/local/src/$2.deb
  return 0
}

# SVN function to fetch source software packages.
svn_function() {
  SVN_ARRAY=($*)
  svn --trust-server-cert --non-interactive --force export ${SVN_ARRAY[*]}
  while [ $? -ne 0 ]; do
    clear
    echo ""
    echo "Unable to connect to software repository, please wait."
    echo "" 
    sleep 60
    svn --trust-server-cert --non-interactive --force export ${SVN_ARRAY[*]}
  done
  return 0
}

# GIT function to fetch source software packages.
git_function() {
  GIT_ARRAY=($*)
  git clone --verbose ${GIT_ARRAY[*]}
  while [ $? -ne 0 ]; do
    clear
    echo ""
    echo "Unable to connect to software repository, please wait."
    echo "" 
    sleep 60
    git clone --verbose ${GIT_ARRAY[*]}
  done
  return 0
}

# Function to convert subnet mask to CIDR format.
mask2cidr() {
  NBITS=0
  IFS=.
  for IP_ADDRESS_4TH_OCTET in $1; do
    case $IP_ADDRESS_4TH_OCTET in
      255) let NBITS+=8;;
      254) let NBITS+=7;;
      252) let NBITS+=6;;
      248) let NBITS+=5;;
      240) let NBITS+=4;;
      224) let NBITS+=3;;
      192) let NBITS+=2;;
      128) let NBITS+=1;;
      0);;
      *) exit 1
    esac
  done
  echo "$NBITS"
  return 0
}

# Function to get network address.
get_network_address() {
  SAVE_IFS=$IFS
  IFS=.
  typeset -a IP_ADDRESS_ARRAY=($1)
  typeset -a NETMASK_ARRAY=($2)
  IFS=$SAVE_IFS
  echo $((${IP_ADDRESS_ARRAY[0]} & ${NETMASK_ARRAY[0]})).$((${IP_ADDRESS_ARRAY[1]} & \
    ${NETMASK_ARRAY[1]})).$((${IP_ADDRESS_ARRAY[2]} & \
    ${NETMASK_ARRAY[2]})).$((${IP_ADDRESS_ARRAY[3]} & ${NETMASK_ARRAY[3]}))
  return 0
}

# Function to get broadcast address.
get_broadcast_address() {
  SAVE_IFS=$IFS
  IFS=.
  typeset -a IP_ADDRESS_ARRAY=($1)
  typeset -a NETMASK_ARRAY=($2)
  IFS=$SAVE_IFS
  echo $((${IP_ADDRESS_ARRAY[0]} | (255 ^ ${NETMASK_ARRAY[0]}))).$((${IP_ADDRESS_ARRAY[1]} | \
    (255 ^ ${NETMASK_ARRAY[1]}))).$((${IP_ADDRESS_ARRAY[2]} | \
    (255 ^ ${NETMASK_ARRAY[2]}))).$((${IP_ADDRESS_ARRAY[3]} | \
    (255 ^ ${NETMASK_ARRAY[3]})))
  return 0
}

# Set variables.
CIDR=$(mask2cidr $LAN_NETMASK)
LAN_NETWORK_ADDRESS=$(get_network_address $LAN_IP_ADDRESS $LAN_NETMASK)
LAN_BROADCAST=$(get_broadcast_address $LAN_IP_ADDRESS $LAN_NETMASK)
IFS=. read -ra LAN_IP_ADDRESS_OCTETS <<< "$LAN_IP_ADDRESS"
IFS=. read -ra LAN_NETWORK_ADDRESS_OCTETS <<< "$LAN_NETWORK_ADDRESS"
LAN_IP_ADDRESS_4TH_OCTET=${LAN_IP_ADDRESS_OCTETS[3]}
LAN_REVERSE_ZONE=${LAN_IP_ADDRESS_OCTETS[2]}.${LAN_IP_ADDRESS_OCTETS[1]}.\
${LAN_IP_ADDRESS_OCTETS[0]}.in-addr.arpa
DHCP_HOST_MIN=${LAN_NETWORK_ADDRESS_OCTETS[0]}.${LAN_NETWORK_ADDRESS_OCTETS[1]}.\
${LAN_NETWORK_ADDRESS_OCTETS[2]}.1
DHCP_HOST_MAX=${LAN_IP_ADDRESS_OCTETS[0]}.${LAN_IP_ADDRESS_OCTETS[1]}.\
${LAN_IP_ADDRESS_OCTETS[2]}.$(($(echo "$LAN_BROADCAST" | cut -d\. -f4) - 1))
LAN_DOMAIN=$(echo "$ORGANIZATION" | sed 's| ||g' \
| tr '[:upper:]' '[:lower:]').local
WORKGROUP=$(echo "$ORGANIZATION" | sed 's| ||g' \
| tr '[:lower:]' '[:upper:]')
HOSTNAME=$(echo $HOSTNAME | tr '[:upper:]' '[:lower:]')
DYNAMICDNS_HOST=$HOSTNAME.dynu.com
FQDN=$HOSTNAME.$LAN_DOMAIN

# Add the admin user account.
useradd -md /admin admin
echo -ne "$ADMIN_PASSWORD\n$ADMIN_PASSWORD\n" | passwd admin

# Add administrator account for CUPS.
usermod -aG lpadmin admin

# Configure Apache Digest authentication.
/usr/bin/expect <<EOD
spawn htdigest -c /etc/apache2/.htdigest-users "Digest Authentication" admin
expect "$ADMIN_PASSWORD"
send "$1\n"
expect eof
EOD

# Set hostname.
hostnamectl set-hostname "$HOSTNAME"

# Configure hosts.
if [ ! -f /etc/hosts.orig ]; then mv /etc/hosts /etc/hosts.orig; fi
cat << EOF.hosts | column -t > /etc/hosts
127.0.0.1	localhost.localdomain	localhost
$LAN_IP_ADDRESS	$FQDN	$(echo "$HOSTNAME" | tr '[:upper:]' '[:lower:]')
EOF.hosts

# Configure Sysctl.
if [ ! -f /etc/sysctl.conf.orig ]; then 
  mv /etc/sysctl.conf /etc/sysctl.conf.orig
fi
cat > /etc/sysctl.conf << EOF.sysctl.conf
# Set domain name.
kernel.domainname = $LAN_DOMAIN
# Enable IP forwarding.
net.ipv4.ip_forward = 1
# Do not accept ICMP redirects (prevent MITM attacks).
net.ipv4.conf.all.accept_redirects = 0
EOF.sysctl.conf
sysctl -p /etc/sysctl.conf

# Temporarily deactivate the Debconf frontend.
export DEBIAN_FRONTEND=noninteractive

# Update Apt sources.list.
if [ ! -f /etc/apt/sources.list.orig ]; then 
  cp /etc/apt/sources.list /etc/apt/sources.list.orig
fi
sed -i "s|http://*.*.archive.ubuntu.com|$UBUNTU_MIRROR|g" \
  /etc/apt/sources.list

# Add Webmin Apt repository.
echo "deb http://download.webmin.com/download/repository sarge contrib" \
  > /etc/apt/sources.list.d/webmin.list
$WGET -qO- http://www.webmin.com/jcameron-key.asc | sudo tee /etc/apt/trusted.gpg.d/jcameron-key.asc

# Resynchronize the package index files from their sources.
apt_function update

# Define software package variables.
APACHE="apache2 apache2-doc apache2-utils libapache2-mod-authnz-external \
  libapache2-mod-authz-unixgroup libapache2-mod-fcgid libapache2-mod-php8.3"
APPARMOR="apparmor apparmor-notify apparmor-profiles apparmor-utils \
  dh-apparmor"
BIND="bind9 bind9-doc bind9utils"
CHRONY="chrony"
CLAMAV="clamav clamav-daemon clamav-docs clamav-freshclam"
CUPS="cups foomatic-db printer-driver-gutenprint"
DDCLIENT="ddclient libio-socket-ssl-perl"
KEA="kea"
LTSP="ltsp dnsmasq epoptes"
MARIADB="automysqlbackup mariadb-server phpmyadmin"
MUNIN="ethtool libcgi-fast-perl libnet-cidr-perl libnet-ssleay-perl munin \
  munin-node munin-plugins-extra smartmontools"
NAGIOS="nagios4 nagios4-cgi monitoring-plugins"
NFS="libnfsidmap1 nfs-kernel-server nfs4-acl-tools"
OPENSSL="openssl"
OPENVPN="openvpn"
PHP="php8.3 php8.3-dev"
POSTFIX="postfix postfix-doc"
PROFTPD="proftpd-basic proftpd-doc proftpd-mod-clamav"
PROXY="c-icap privoxy squid"
SHOREWALL="shorewall shorewall-doc shorewall-init"
SNORT="oinkmaster snort snort-doc"
SOURCE_CODE_DEPENDS="git gcc make subversion"
SQUIDCLAMAV_DEPENDS="libicapapi-dev libssl-dev libtimedate-perl"
SYSTEM_DEPENDS="apt-utils dkms expect openssh-server vim-scripts"
WEBMIN="at cups mdadm quota quotatool sarg stunnel4 usermin webalizer webmin wodim"

SOFTWARE_PACKAGES="$APACHE $APPARMOR $BIND $CHRONY $CLAMAV $CUPS $DDCLIENT \
  $LTSP $MARIADB $MUNIN $NAGIOS $NFS $OPENSSL $OPENVPN $PHP $POSTFIX $PROFTPD \
  $PROXY $SHOREWALL $SNORT $SOURCE_CODE_DEPENDS $SQUIDCLAMAV_DEPENDS \
  $SYSTEM_DEPENDS $WEBMIN"

# Software package verification.
apt-get -s install $SOFTWARE_PACKAGES > /dev/null
if [ $? -ne 0 ]; then
  clear
  echo ""
  echo "Software packages verification problem detected."
  echo "View software.log for further details."
  echo ""
  echo "Analyze the packages in software.log. For example, if the log contains"
  echo "a package named php8.1, this means that php8.1 is not found on your" 
  echo "Ubuntu mirror. Packages may change over time. Use the 'apt-cache search'"
  echo "command to search for just the package name, without the version number."
  echo "For example, the 'apt-cache search php' command will show if there is"
  echo "an updated PHP package available. For your information, php8.1 is" 
  echo "available on Ubuntu 22.04 mirrors, and php8.3 is available on Ubuntu"
  echo "24.04 mirrors."
  echo ""
  echo "If the log contains the name of a package that does not show up when"
  echo "you search for it with 'apt-cache search', this means the package is"
  echo "most likely deprecated and needs to be removed from this script."
  echo ""
  apt-get -s install $SOFTWARE_PACKAGES 2> software.log
  exit 1
fi

### Define automatic software packages. ###
# squidclamav.darold.net
SQUIDCLAMAV="https://github.com/darold/squidclamav"

clear
echo ""
echo "Installing prerequisite software packages."
echo ""

# Install software prerequisites.
apt_function install $SYSTEM_DEPENDS $SOURCE_CODE_DEPENDS

################################################################################
#                                                                              #
# The following routine installs and configures Chrony, which provides time    #
# synchronization.                                                             #
#                                                                              #
# chrony.tuxfamily.org                                                         #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing Chrony."
echo ""

# Install Chrony.
apt_function install $CHRONY

# Configure chrony.conf.
if [ ! -f /etc/chrony/chrony.conf.orig ]; then 
  cp /etc/chrony/chrony.conf /etc/chrony/chrony.conf.orig
fi
grep -q "allow $LAN_NETWORK_ADDRESS/$CIDR" /etc/chrony/chrony.conf || \
cat >> /etc/chrony/chrony.conf << EOF.chrony.conf

# Allow a subnet from which NTP clients can access the NTP server.
allow $LAN_NETWORK_ADDRESS/$CIDR
EOF.chrony.conf

# Reload configuration.
systemctl restart chrony

################################################################################
#                                                                              #
# The following routine installs AppArmor, a Linux Security Module             #
# implementation of name-based mandatory access controls. AppArmor confines    #
# individual programs to a set of listed files and POSIX 1003.1e draft         #
# capabilities.                                                                #
#                                                                              #
# wiki.apparmor.net                                                            #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing AppArmor."
echo ""

# Install AppArmor.
apt_function install $APPARMOR

################################################################################
#                                                                              #
# The following routine installs and configures Shorewall, a high-level tool   #
# for configuring Netfilter. You describe your firewall/gateway requirements   #
# using entries in a set of configuration files. Shorewall reads those         #
# configuration files and with the help of the iptables utility, Shorewall     #
# configures Netfilter to match your requirements.                             #
#                                                                              #
# shorewall.org                                                                #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing Shorewall."
echo ""

# Install Shorewall.
apt_function install $SHOREWALL

# Configure shorewall.conf.
sed -i "s|LOG_MARTIANS=Yes|LOG_MARTIANS=No|
  s|STARTUP_ENABLED=No|STARTUP_ENABLED=Yes|" /etc/shorewall/shorewall.conf

# Create rules.
cat > /etc/shorewall/rules << EOF.rules
?SECTION NEW
#ACTION           SOURCE  DEST
CUPS(ACCEPT)      lan    \$FW
DHCPfwd(ACCEPT)   lan    \$FW
DNS(ACCEPT)       lan    \$FW
FTP(ACCEPT)       lan    \$FW
HTTP(ACCEPT)      lan    \$FW
HTTPS(ACCEPT)     lan    \$FW
Munin(ACCEPT)     lan    \$FW
MySQL(ACCEPT)     lan    \$FW
Nagios(ACCEPT)    lan    \$FW
NFS(ACCEPT)       lan    \$FW
NTP(ACCEPT)       lan    \$FW
OpenVPN(ACCEPT)   lan    \$FW
Ping(ACCEPT)      lan    \$FW
Squid(ACCEPT)     lan    \$FW
SSH(ACCEPT)       lan    \$FW
Syslog(ACCEPT)    lan    \$FW
TFTP(ACCEPT)      lan    \$FW
Webmin(ACCEPT)    lan    \$FW
REDIRECT          lan     3128  tcp  www - !$LAN_IP_ADDRESS

CUPS(ACCEPT)      lan    \$FW
DHCPfwd(ACCEPT)   vpn    \$FW
DNS(ACCEPT)       vpn    \$FW
FTP(ACCEPT)       vpn    \$FW
HTTP(ACCEPT)      vpn    \$FW
HTTPS(ACCEPT)     vpn    \$FW
Munin(ACCEPT)     vpn    \$FW
MySQL(ACCEPT)     vpn    \$FW
Nagios(ACCEPT)    vpn    \$FW
NFS(ACCEPT)       vpn    \$FW
NTP(ACCEPT)       vpn    \$FW
OpenVPN(ACCEPT)   vpn    \$FW
Ping(ACCEPT)      vpn    \$FW
Squid(ACCEPT)     vpn    \$FW
SSH(ACCEPT)       vpn    \$FW
Syslog(ACCEPT)    vpn    \$FW
TFTP(ACCEPT)      vpn    \$FW
Webmin(ACCEPT)    vpn    \$FW
REDIRECT          vpn     3128  tcp  www - !$LAN_IP_ADDRESS

Ping(DROP)        wan    \$FW
OpenVPN(ACCEPT)   wan    \$FW
FTP(ACCEPT)       wan    \$FW
SSHKnock          wan    \$FW  tcp  22,1700,1701,1701

# PORT MAP
# 8 = ICMP (Internet Control Message Protocol)
# 21 = FTP (File Transfer Protocol is used by ProFTPD)
# 22 = SSH (Secure Shell)
# 25 = SMTP (Simple Mail Transport Protocol is used by Postfix)
# 53 = DNS (Domain Name Service is used by Bind)
# 67, 68 = DHCP (Dynamic Host Configuration Protocol)
# 69 = TFTP (Trivial File Transfer Protocol is used by LTSP)
# 80 = HTTP (Hypertext Transfer Protocol is used by Apache)
# 111 = RPCbind is used by NFS.
# 113 = IDENT (Identification Protocol is blocked to enhance security)
# 123 = NTP (Network Time Protocol)
# 443 = HTTPS (HTTP, secure)
# 514 = Syslog
# 631 = CUPS
# 1194 = OpenVPN
# 2000 = NBD Image Export for LTSP
# 2049 = NFS (Network File System)
# 3128 = Squid
# 3306 = MariaDB
# 4000,4001 = RPC.statd is used by NFS.
# 4002 = RPC.mountd is used by NFS.
# 4949 = Munin
# 5666 = Nagios
# 9571 = Ldminfod (login and locale settings for LTSP)
# 9572 = Nbdswapd (NBD swap for LTSP)
# 10000 = Webmin
# 10809 = NBD-server (Network Block Device)
# 20000 = Usermin
EOF.rules

### Define macros ###

# CUPS macro.
cat > /etc/shorewall/macro.CUPS << EOF.cups.macro
?FORMAT 2
#ACTION  SOURCE  DEST  PROTO  DPORT
PARAM    -       -     tcp    631
EOF.cups.macro

# LTSP macro.
cat > /etc/shorewall/macro.LTSP << EOF.ltsp.macro
?FORMAT 2
#ACTION SOURCE DEST PROTO DPORT
PARAM   -      -    tcp   2000
PARAM   -      -    tcp   9571
PARAM   -      -    tcp   9572
PARAM   -      -    tcp   10809
EOF.ltsp.macro

# Nagios macro.
cat > /etc/shorewall/macro.Nagios << EOF.nagios.macro
?FORMAT 2
#ACTION SOURCE DEST PROTO DPORT
PARAM   -      -    tcp   5666
EOF.nagios.macro

# NFS macro.
cat > /etc/shorewall/macro.NFS << EOF.nfs.macro
?FORMAT 2
#ACTION SOURCE DEST PROTO DPORT
PARAM   -      -    tcp   111
PARAM   -      -    tcp   2049
PARAM   -      -    tcp   4000
PARAM   -      -    tcp   4001
PARAM   -      -    tcp   4002
EOF.nfs.macro

# Usermin macro.
cat > /etc/shorewall/macro.Usermin << EOF.usermin.macro
?FORMAT 2
#ACTION SOURCE DEST PROTO DPORT
PARAM   -      -    tcp   20000
EOF.usermin.macro

# Create zones.
cat > /etc/shorewall/zones << EOF.zones
#ZONE  TYPE
fw     firewall
wan    ipv4
lan    ipv4
vpn    ipv4
EOF.zones

# Create interfaces.
cat << EOF.interfaces | column -t > /etc/shorewall/interfaces
#ZONE	INTERFACE	BROADCAST	OPTIONS
lan	$LAN_INTERFACE	detect	tcpflags,nosmurfs,routefilter
wan	$WAN_INTERFACE	detect	dhcp,tcpflags,nosmurfs,routefilter
vpn	tun+	detect
EOF.interfaces

# Create policy.
cat > /etc/shorewall/policy << EOF.policy
#SOURCE  DEST  POLICY  LOG
\$FW     all   ACCEPT
lan      wan   ACCEPT
vpn      lan   ACCEPT
wan      all   DROP    info
all      all   REJECT  info
EOF.policy

# Create snat.
cat << EOF.snat | column -t > /etc/shorewall/snat
#ACTION	SOURCE	DEST
MASQUERADE	$LAN_NETWORK_ADDRESS/$CIDR	$WAN_INTERFACE
EOF.snat

# Create tunnels.
cat << EOF.tunnels | column -t > /etc/shorewall/tunnels
#TYPE	ZONE	GATEWAY
openvpnserver:1194	wan	0.0.0.0/0
EOF.tunnels

# Create action.SSHKnock.
touch /etc/shorewall/action.SSHKnock

# Create actions.
cat > /etc/shorewall/actions << EOF.actions
#ACTION
SSHKnock
EOF.actions

# Create SSHKnock.
cat > /etc/shorewall/SSHKnock << EOF.sshknock
use Shorewall::Chains;

if ( \$level ) {
  log_rule_limit( \$level,
  \$chainref,
  'SSHKnock',
  'ACCEPT',
  '',
  \$tag,
  'add',
  '-p tcp --dport 22   -m recent --rcheck --name SSH ' );

  log_rule_limit( \$level,
  \$chainref,
  'SSHKnock',
  'DROP',
  '',
  \$tag,
  'add',
  '-p tcp ! --dport 22 ' );
}

add_rule( \$chainref, '-p tcp --dport 22 -m recent --rcheck --seconds 60 \
  --name SSH -j ACCEPT' );
# For security purposes, use a unique set of ports for port knocking.
# Reference shorewall.net/PortKnocking.html and soloport.com/iptables.html.
add_rule( \$chainref, '-p tcp --dport 1700 -m recent --name SSH \
  --remove -j DROP' );
add_rule( \$chainref, '-p tcp --dport 1701 -m recent --name SSH \
  --set    -j DROP' );
add_rule( \$chainref, '-p tcp --dport 1702 -m recent --name SSH \
  --remove -j DROP' );

1;
EOF.sshknock

# Shorewall startup.
sed -i "s|startup=0|startup=1|" /etc/default/shorewall
pgrep shorewall > /dev/null
if [ $? -eq 1 ]; then
  shorewall start
else
  shorewall restart
fi

################################################################################
#                                                                              #
# The following routine installs and configures OpenSSL, which implements      #
# cryptographic functions and provides a Certificate Authority.                #
#                                                                              #
# openssl.org                                                                  #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing OpenSSL."
echo ""

# Install OpenSSL.
apt_function install $OPENSSL

# Create CA directory structure.
mkdir -p /etc/ssl/crl
mkdir -p /etc/ssl/certs
mkdir -p /etc/ssl/private

# Configure openssl.cnf.
if [ ! -f /etc/ssl/openssl.cnf.orig ]; then
  cp /etc/ssl/openssl.cnf /etc/ssl/openssl.cnf.orig
fi
sed -ri "s|(default_bits\s+).+$|\1= 8192|
  s|365|7300|
  s|./demoCA|/etc/ssl|
  s|$dir/crlnumber|$dir/crl/crlnumber|
  s|$dir/crl.pem|$dir/crl/crl.pem|
  s|$dir/cacert.pem|$dir/certs/ca-cert.pem|
  s|$dir/private/cakey.pem#|$dir/private/ca-key.pem #|" /etc/ssl/openssl.cnf

# Create CA key and certificate.
# Note: the CA expiration must be longer than the server certificate expiration
# (e.g., 7301 days for CA expiration and 7300 days for server certificate 
# expiration).
openssl genrsa -out /etc/ssl/private/ca-key.pem \
  -aes256 -passout pass:$ADMIN_PASSWORD 8192
openssl req -new -x509 -key /etc/ssl/private/ca-key.pem \
  -passin pass:$ADMIN_PASSWORD -subj "/C=$COUNTRY/ST=$STATE/O=$ORGANIZATION/\
OU=PKI/CN=$HOSTNAME/emailAddress=$EMAIL_ADDRESS" -days 7301 \
  -out /etc/ssl/certs/ca-cert.pem
ln -fs /etc/ssl/certs/ca-cert.pem /etc/ssl/certs/"$(openssl x509 -noout -hash \
  -in /etc/ssl/certs/ca-cert.pem)".0
chmod 400 /etc/ssl/private/ca-key.pem

# Converting the CA certificate to x509 format is necessary when importing 
# the ca-cert into a client via http, e.g., http://rt1.example.local/ca-cert.crt.
mkdir -p /var/www/html
openssl x509 -in /etc/ssl/certs/ca-cert.pem -out /var/www/html/ca-cert.crt

# Create the Certificate Revocation List (CRL).
touch /etc/ssl/index.txt
echo "01" > /etc/ssl/crl/crlnumber
openssl ca -gencrl -passin pass:"$ADMIN_PASSWORD" -out /etc/ssl/crl/crl.pem
ln -fs /etc/ssl/crl/crl.pem /etc/ssl/"$(openssl crl -noout -hash \
  -in /etc/ssl/crl/crl.pem)".r0
ln -fs /etc/ssl/crl/crl.pem /var/www/html/crl.pem
sed -i "s|nsCaRevocationUrl.*$\
|nsCaRevocationUrl\t\t http://$DYNAMICDNS_HOST/crl.pem|" /etc/ssl/openssl.cnf

# Create server key and certificate.
openssl req -newkey rsa:8192 -nodes -days 7300 -keyout /etc/ssl/private/tls-key.pem \
  -out newreq.pem -subj "/C=$COUNTRY/ST=$STATE/O=$ORGANIZATION/\
OU=TLS/CN=$FQDN/emailAddress=$EMAIL_ADDRESS" --addext "extendedKeyUsage = serverAuth" \
  --addext "subjectAltName = email:copy, DNS:$DYNAMICDNS_HOST, DNS:*.$LAN_DOMAIN"
openssl x509 -req -days 7300 -in newreq.pem -CA /etc/ssl/certs/ca-cert.pem \
  -CAkey /etc/ssl/private/ca-key.pem -passin pass:"$ADMIN_PASSWORD" -CAcreateserial \
  -out /etc/ssl/certs/tls-cert.pem
ln -fs /etc/ssl/certs/tls-cert.pem /etc/ssl/certs/"$(openssl x509 -noout \
  -hash -in /etc/ssl/certs/tls-cert.pem)".0  
rm -f newcert.pem newreq.pem
chmod 440 /etc/ssl/private/tls-key.pem

# Update AppArmor's profile for <abstractions/ssl_certs>.
if [ ! -f /etc/apparmor.d/abstractions/ssl_certs.orig ]; then 
  cp /etc/apparmor.d/abstractions/ssl_certs \
    /etc/apparmor.d/abstractions/ssl_certs.orig
fi
grep -q "/etc/ssl/certs/ca-cert.pem" /etc/apparmor.d/abstractions/ssl_certs || \
cat >> /etc/apparmor.d/abstractions/ssl_certs << EOF.apparmor.ssl
  /etc/ssl/certs/ca-cert.pem r,
  /etc/ssl/crl/crl.pem r,
  /etc/pkcs11/modules/* r,
EOF.apparmor.ssl
systemctl restart apparmor

# Create Diffie-Hellman parameters.
openssl dhparam -dsaparam -out /etc/ssl/dh 8192

################################################################################
#                                                                              #
# The following routine installs and configures Apache, a robust,              #
# commercial-grade, featureful, and freely available source code               #
# implementation of an HTTP (Web) server.                                      #
#                                                                              #
# apache.org                                                                   #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing Apache."
echo ""

# Install Apache.
apt_function install $APACHE $PHP

# Enable necessary Apache modules.
a2enmod cgi expires rewrite ssl fcgid authnz_external

# Enable mcrypt extension (phpMyAdmin Depends).
phpenmod mcrypt 

# Add ServerName to default sites.
if [ ! -f /etc/apache2/sites-available/000-default.conf.orig ]; then 
  cp /etc/apache2/sites-available/000-default.conf \
    /etc/apache2/sites-available/000-default.conf.orig
fi
sed -i "s|#ServerName www.example.com|ServerName $FQDN|" \
  /etc/apache2/sites-available/000-default.conf
if [ ! -f /etc/apache2/sites-available/default-ssl.conf.orig ]; then 
  cp /etc/apache2/sites-available/default-ssl.conf \
    /etc/apache2/sites-available/default-ssl.conf.orig
fi
grep -q "ServerName" /etc/apache2/sites-available/default-ssl.conf || \
  sed -i "/ServerAdmin/ a\ \n\tServerName $FQDN" \
    /etc/apache2/sites-available/default-ssl.conf

# Add External authentication.
grep -q "DefineExternalAuth" /etc/apache2/sites-available/000-default.conf || \
  sed -i "/ServerName $FQDN/ a\ \n\tDefineExternalAuth pwauth pipe \
/usr/sbin/pwauth" /etc/apache2/sites-available/000-default.conf
grep -q "DefineExternalAuth" /etc/apache2/sites-available/default-ssl.conf || \
  sed -i "/ServerName $FQDN/ a\ \n\tDefineExternalAuth pwauth pipe \
/usr/sbin/pwauth" /etc/apache2/sites-available/default-ssl.conf

# Add OpenSSL RewriteEngine.
grep -q "RewriteEngine On" /etc/apache2/sites-available/000-default.conf || \
  sed -i "/ServerName $FQDN/ a\ \n\tRewriteEngine On\n\tRewriteCond %{HTTPS} \
!=on\n\tRewriteRule ^/?(.*) https://%{SERVER_NAME}/\$1 [R,L]" \
  /etc/apache2/sites-available/000-default.conf

# Configure default-ssl.conf.
sed -i "s|/etc/ssl/certs/ssl-cert-snakeoil.pem|/etc/ssl/certs/tls-cert.pem|
  s|/etc/ssl/private/ssl-cert-snakeoil.key|/etc/ssl/private/tls-key.pem|
  s|#SSLCACertificateFile .*$|SSLCACertificateFile /etc/ssl/certs/ca-cert.pem|
  s|#SSLCARevocationFile .*$|SSLCARevocationFile /etc/ssl/crl/crl.pem|" \
    /etc/apache2/sites-available/default-ssl.conf
grep -q "SSLCARevocationCheck" \
  /etc/apache2/sites-available/default-ssl.conf || \
  sed -i "/SSLCARevocationFile/ a\ \tSSLCARevocationCheck chain" \
    /etc/apache2/sites-available/default-ssl.conf

# Enable default-ssl VirtualHost.
a2ensite default-ssl

# Configure ports.conf.
cat > /etc/apache2/ports.conf << EOF.ports.conf
Listen 80
<IfModule ssl_module>
  Listen 443
</IfModule>
EOF.ports.conf

# Add the www-data user to ssl-cert group so the daemon can read the TLS key.
usermod -aG ssl-cert www-data

# Reload configuration.
systemctl restart apache2

################################################################################
#                                                                              #
# The following routine installs and configures MariaDB and phpMyAdmin.        #
#                                                                              #
# MariadB provides a relational database management system (RDBMS) that runs   #
# as a server providing multi-user access to a number of databases.            #
#                                                                              #
# phpMyAdmin provides a graphical user interface to manage MariaDB.            #
#                                                                              #
# mariadb.com                                                                  #
# phpmyadmin.net                                                               #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing MariaDB."
echo ""

# Install MariaDB.
apt_function install $MARIADB

# Configure bind address.
if [ ! -f /etc/mysql/my.cnf.orig ]; then 
  cp /etc/mysql/my.cnf /etc/mysql/my.cnf.orig
fi
sed -ri "s|(bind-address\s+).+$|\1= $LAN_IP_ADDRESS|" \
  /etc/mysql/mariadb.conf.d/50-server.cnf
service mariadb force-reload

# Set MariaDB's root password.
mysqladmin --user=root password "$ADMIN_PASSWORD"

# Add MariaDB's administrator account.
mysql --user=root --password="$ADMIN_PASSWORD" << EOF.mysql_admin
CREATE USER 'admin'@'$LAN_IP_ADDRESS' IDENTIFIED VIA mysql_native_password USING '$ADMIN_PASSWORD';
GRANT ALL PRIVILEGES ON *.* TO 'admin'@'$LAN_IP_ADDRESS';
FLUSH PRIVILEGES; 
EOF.mysql_admin

# Change database backup compression.
sed -i "s|COMP=gzip|COMP=bzip2|" /etc/default/automysqlbackup

# Create a controluser for phpMyAdmin.
mysql --user=root --password="$ADMIN_PASSWORD" << EOF.controluser
CREATE USER 'pma'@'localhost' IDENTIFIED VIA mysql_native_password USING '$ADMIN_PASSWORD';
GRANT SELECT, INSERT, UPDATE, DELETE ON `phpmyadmin`.* TO 'pma'@'localhost';
FLUSH PRIVILEGES;
EOF.controluser

# Create PMA database and tables.
mysql < /usr/share/phpmyadmin/sql/create_tables.sql

# Configure phpMyAdmin's Debconf.
if [ ! -f /etc/dbconfig-common/phpmyadmin.conf.orig ]; then
  cp /etc/dbconfig-common/phpmyadmin.conf /etc/dbconfig-common/phpmyadmin.conf.orig
fi
sed -i "/dbc_install=/ c\dbc_install='false'
  /dbc_dbuser=/ c\dbc_dbuser='pma'
  /dbc_dbpass=/ c\dbc_dbpass='$ADMIN_PASSWORD'
  /dbc_dballow=/ c\dbc_dballow='localhost'
  /dbc_dbname=/ c\dbc_dbname='phpmyadmin'
  /dbc_dbadmin=/ c\dbc_dbadmin='admin'" /etc/dbconfig-common/phpmyadmin.conf

# Create config-db.php.
/usr/sbin/dbconfig-generate-include /etc/dbconfig-common/phpmyadmin.conf -f php \
  > /etc/phpmyadmin/config-db.php

# Configure phpMyAdmin's apache.conf.
if [ ! -f /etc/phpmyadmin/apache.conf.orig ]; then
  cp /etc/phpmyadmin/apache.conf /etc/phpmyadmin/apache.conf.orig
fi
grep -q "DirectoryIndex" /etc/phpmyadmin/apache.conf || \
sed -i "/DirectoryIndex/ a\    Require ip 127.0.0.0/8 $LAN_NETWORK_ADDRESS/$CIDR" \
  /etc/phpmyadmin/apache.conf
ln -fs /etc/phpmyadmin/apache.conf /etc/apache2/conf-available/phpmyadmin.conf
a2enconf phpmyadmin

# Add the mysql user to the ssl-cert group so the daemon can read the TLS key.
usermod -aG ssl-cert mysql

# Reload configuration.
systemctl restart mariadb
systemctl restart apache2

################################################################################
#                                                                              #
# The following routine installs and configures ClamAV, which provides an      #
# effective malware scanner.                                                   #
#                                                                              #
# clamav.net                                                                   #
# wbmclamav.labs.libre-entreprise.org                                          #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing malware scanner."
echo ""

# Install the malware scanner.
apt_function install $CLAMAV

# Configure clamd.conf.
if [ ! -f /etc/clamav/clamd.conf.orig ]; then 
  cp /etc/clamav/clamd.conf /etc/clamav/clamd.conf.orig
fi
sed -i "s|DetectPUA false|DetectPUA true|
  s|HeuristicScanPrecedence false|HeuristicScanPrecedence true|
  s|StructuredDataDetection false|StructuredDataDetection true|" \
    /etc/clamav/clamd.conf

# Enable SafeBrowsing.
if [ ! -f /etc/clamav/freshclam.conf.orig ]; then 
  cp /etc/clamav/freshclam.conf /etc/clamav/freshclam.conf.orig
fi
grep -q "SafeBrowsing yes" /etc/clamav/freshclam.conf || \
  echo "SafeBrowsing yes" >> /etc/clamav/freshclam.conf

# Update malware signatures.
clear
echo ""
echo "Please wait for FreshClam to update ClamAV malware signatures."
echo ""
freshclam

# Reload configuration.
systemctl restart clamav-daemon
systemctl restart clamav-freshclam

################################################################################
#                                                                              #
# The following routine installs and configures Privoxy, Squid, and            #
# SquidClamAV.                                                                 #
#                                                                              #
# Privoxy filters unwanted advertisements and internet junk that suck up       #
# precious bandwidth.                                                          #
#                                                                              #
# Squid creates a cache of frequently accessed web pages, which improves       #
# performance and helps conserve bandwidth.                                    #
#                                                                              #
# SquidClamAV stops malware before it reaches your workstations.               #
#                                                                              #
# privoxy.org                                                                  #
# squid-cache.org                                                              #
# squidclamav.darold.net/index.html                                            #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing Proxy."
echo ""

# Install Proxy.
apt_function install $PROXY

# Configure squid.conf.
if [ ! -f /etc/squid/squid.conf.orig ]; then 
  cp /etc/squid/squid.conf /etc/squid/squid.conf.orig
fi
sed -i "s|#acl localnet src 192.168.0.0/16\
|acl localnet src $LAN_NETWORK_ADDRESS/$CIDR|
  /http_access allow localnet/ s|^#||" /etc/squid/squid.conf

# Configure add-on.conf.
cat > /etc/squid/conf.d/add-on.conf << EOF.add-on.conf
# SquidClamAV configuration.
url_rewrite_children $(nproc --all)
url_rewrite_access allow all
icap_enable on
icap_send_client_ip on
icap_send_client_username on
icap_client_username_encode off
icap_client_username_header X-Authenticated-User
icap_preview_enable on
icap_preview_size 1024
icap_service service_req reqmod_precache bypass=1 icap://127.0.0.1:1344\
/squidclamav
adaptation_access service_req allow all
icap_service service_resp respmod_precache bypass=1 icap://127.0.0.1:1344\
/squidclamav
adaptation_access service_resp allow all

# Define Privoxy as parent proxy (without ICP).
cache_peer 127.0.0.1 parent 8118 7 no-query

# Define ACL for protocol FTP.
acl ftp proto FTP

# Do not forward FTP requests to Privoxy.
always_direct allow ftp

# Forward all the rest to Privoxy.
never_direct allow all
EOF.add-on.conf

# Create Squid's cache directories.
systemctl stop squid
squid -z
systemctl start squid

# Install SquidClamAV.
apt_function install $SQUIDCLAMAV_DEPENDS
cd /usr/local/src
if [ -d squidclamav ]; then rm -rf squidclamav; fi
git_function $SQUIDCLAMAV
cd squidclamav
sh configure --prefix=/usr --sysconfdir=/etc --datadir=/usr/share --with-c-icap
make && make install
cd ..
rm -rf squidclamav

# Configure squidclamav.conf.
if [ ! -f /etc/c-icap/squidclamav.conf.orig ]; then 
  cp /etc/c-icap/squidclamav.conf /etc/c-icap/squidclamav.conf.orig
fi
sed -i "s|redirect http://.*$|redirect http://$LAN_IP_ADDRESS/cgi-bin/clwarn.cgi|
  s|safebrowsing 0|safebrowsing 1|" /etc/c-icap/squidclamav.conf

# Configure c-icap.conf.
if [ ! -f /etc/c-icap/c-icap.conf.orig ]; then 
  cp /etc/c-icap/c-icap.conf /etc/c-icap/c-icap.conf.orig
fi
sed -i "s|ServerAdmin .*$|ServerAdmin $EMAIL_ADDRESS|
  s|ServerName YourServerName|ServerName $FQDN|" /etc/c-icap/c-icap.conf
grep -q "# Enable SquidClamAV" /etc/c-icap/c-icap.conf || \
cat >> /etc/c-icap/c-icap.conf << EOF.c-icap.conf

# Enable SquidClamAV.
Service squidclamav squidclamav.so
EOF.c-icap.conf

# Setup clwarn.cgi.
chgrp www-data /usr/lib/cgi-bin
cp -f /usr/libexec/squidclamav/clwarn.cgi.en_EN /usr/lib/cgi-bin/clwarn.cgi

# Configure Privoxy's configuration.
if [ ! -f /etc/privoxy/config.orig ]; then 
  cp /etc/privoxy/config /etc/privoxy/config.orig
fi
sed -i "s|#admin-address .*$|admin-address $EMAIL_ADDRESS|
  s|enable-proxy-authentication-forwarding 0\
|enable-proxy-authentication-forwarding 1|" /etc/privoxy/config
chown privoxy /etc/privoxy/*.action

# Configure Privoxy's match-all.action.
if [ ! -f /etc/privoxy/match-all.action.orig ]; then 
  cp /etc/privoxy/match-all.action /etc/privoxy/match-all.action.orig
fi
sed -i "s|+set-image-blocker{pattern}|+set-image-blocker{blank}|" \
  /etc/privoxy/match-all.action

# Add the proxy user to the www-data group so the daemon can read the http.keytab.
usermod -aG proxy www-data

# Reload configuration.
systemctl restart apache2
systemctl restart privoxy

# c-icap startup.
sed -i "s|START=no|START=yes|" /etc/default/c-icap
pgrep c-icap > /dev/null
if [ $? -eq 1 ]; then
  systemctl start c-icap
else
  systemctl restart c-icap
fi

################################################################################
#                                                                              #
# The following routine installs and configures NFS (Network File System),     #
# which allows for fast, seamless sharing of files across a network.           #
#                                                                              #
# ietf.org/rfc/rfc3530.txt                                                     #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing NFS."
echo ""

# Install NFS.
apt_function install $NFS

# Add NFS exports.
if [ ! -f /etc/fstab.orig ]; then 
  cp /etc/fstab /etc/fstab.orig
fi
mkdir -p /nfs/home
echo "/nfs $LAN_NETWORK_ADDRESS/$CIDR(rw)" > /etc/exports
echo "/nfs/home $LAN_NETWORK_ADDRESS/$CIDR(rw)" >> /etc/exports
mount --bind /home /nfs/home
grep -q "/nfs/home" /etc/fstab || \
  echo "/home /nfs/home none bind 0 0" >> /etc/fstab
exportfs -a

# Configure idmapd.conf.
if [ ! -f /etc/idmapd.conf.orig ]; then 
  cp /etc/idmapd.conf /etc/idmapd.conf.orig
fi
sed -i "s|Domain = .*$|Domain = $LAN_DOMAIN|" /etc/idmapd.conf

# nfs-kernel-server startup.
pgrep nfsd > /dev/null
if [ $? -eq 1 ]; then
  systemctl start nfs-kernel-server
else
  systemctl restart nfs-kernel-server
fi

################################################################################
#                                                                              #
# The following routine installs and configures ProFTPD, a                     # 
# highly configurable, secure FTP server.                                      #
#                                                                              #
# proftpd.org                                                                  #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing ProFTPD."
echo ""

# Install ProFTPD.
apt_function install $PROFTPD

# Configure proftpd.conf.
if [ ! -f /etc/proftpd/proftpd.conf.orig ]; then 
  cp /etc/proftpd/proftpd.conf /etc/proftpd/proftpd.conf.orig
fi
sed -ri "s|(ServerName\s+).+$|\1\"$FQDN\"|
  /tls.conf/ s|^#||
  s|(PersistenPasswd\s+).+$|\1on|" /etc/proftpd/proftpd.conf

# Configure tls.conf.
if [ ! -f /etc/proftpd/tls.conf.orig ]; then 
  cp /etc/proftpd/tls.conf /etc/proftpd/tls.conf.orig
fi
sed -ri "s|(TLSRSACerfificateFile\s+).+$|\1/etc/ssl/certs/tls-cert.pem|
  s|(TLSRSACerfificateKeyFile\s+).+$|\1/etc/ssl/certs/tls-key.pem|" \
    /etc/proftpd/tls.conf

# Reload configuration.
systemctl restart proftpd

################################################################################
#                                                                              #
# The following routine installs and configures Munin, a networked resource    #
# monitoring tool that can help analyze resource trends and performance        #
# problems.                                                                    #
#                                                                              #
# munin-monitoring.org                                                         #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing Munin."
echo ""

# Install Munin.
apt_function install $MUNIN

# Install plugins.
rm -f /etc/munin/plugins/*
ln -fs /usr/share/munin/plugins/load /etc/munin/plugins
ln -fs /usr/share/munin/plugins/memory /etc/munin/plugins
ln -fs /usr/share/munin/plugins/cpu* /etc/munin/plugins
ln -fs /usr/share/munin/plugins/diskstat* /etc/munin/plugins
ln -fs /usr/share/munin/plugins/smart* /etc/munin/plugins
ln -fs /usr/share/munin/plugins/fw* /etc/munin/plugins
ln -fs /usr/share/munin/plugins/tcp /etc/munin/plugins
ln -fs /usr/share/munin/plugins/apache* /etc/munin/plugins
ln -fs /usr/share/munin/plugins/bind* /etc/munin/plugins
ln -fs /usr/share/munin/plugins/mysql* /etc/munin/plugins
ln -fs /usr/share/munin/plugins/nfsd* /etc/munin/plugins
ln -fs /usr/share/munin/plugins/openvpn /etc/munin/plugins
ln -fs /usr/share/munin/plugins/postfix* /etc/munin/plugins
ln -fs /usr/share/munin/plugins/snort* /etc/munin/plugins
ln -fs /usr/share/munin/plugins/squid* /etc/munin/plugins

# Configure munin.conf.
if [ ! -f /etc/munin/munin.conf.orig ]; then 
  cp /etc/munin/munin.conf /etc/munin/munin.conf.orig
fi
sed -i "s|\[localhost.localdomain\]|\[$FQDN\]|
  s|address 127.0.0.1|address $LAN_IP_ADDRESS|" /etc/munin/munin.conf

# Configure munin-node.conf.
if [ ! -f /etc/munin/munin-node.conf.orig ]; then 
  cp /etc/munin/munin-node.conf /etc/munin/munin-node.conf.orig
fi
sed -i "s|# cidr_allow 192.*$|cidr_allow $LAN_NETWORK_ADDRESS/$CIDR|
  s|#host_name localhost.localdomain|host_name $FQDN|
  s|host \*|host $LAN_IP_ADDRESS|" /etc/munin/munin-node.conf

# Update apache24.conf.
if [ ! -f /etc/munin/apache24.conf.orig ]; then
  cp /etc/munin/apache24.conf /etc/munin/apache24.conf.orig
fi
grep -q "AuthType Digest" /etc/munin/apache24.conf || \
sed -i "0,/Require local/{//d} 
    /<Directory \/var\/cache\/munin\/www>/ a\<RequireAll>\n\
    SSLRequireSSL\n\
    Require ip 127.0.0.0/8 $LAN_NETWORK_ADDRESS/$CIDR\n\
    AuthDigestDomain \"Munin\"\n\
    AuthDigestProvider file\n\
    AuthUserFile \"/etc/apache2/.htpasswd.users\"\n\
    AuthGroupFile \"/etc/groups\"\n\
    AuthName \"Digest Authentication\"\n\
    AuthType Digest\n\
    Require valid-user\n\
</RequireAll>" /etc/munin/apache24.conf

# Reload configuration.
systemctl restart apache2
systemctl restart munin-node

################################################################################
#                                                                              #
# The following routine installs and configures Nagios, a powerful monitoring  #
# system that enables organizations to identify and resolve IT infrastructure  #
# problems before they affect critical business processes.                     #
#                                                                              #
# nagios.org                                                                   #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing Nagios."
echo ""

# Install Nagios.
apt_function install $NAGIOS

# Backup the original configuration to prepare for the new custom configuration.
mv -u /etc/nagios4/conf.d /etc/nagios4/conf.d.orig
mkdir -p /etc/nagios4/conf.d

# Configure cgi.cfg.
if [ ! -f /etc/nagios4/cgi.cfg.orig ]; then 
  cp /etc/nagios4/cgi.cfg /etc/nagios4/cgi.cfg.orig
fi
sed -i "s|use_ssl_authentication=0|use_ssl_authentication=1|
  s|nagiosadmin|admin|" /etc/nagios4/cgi.cfg

# Configure apache2.conf.
if [ ! -f /etc/nagios4/apache2.conf.orig ]; then 
  cp /etc/nagios4/apache2.conf /etc/nagios4/apache2.conf.orig
fi
grep -q "SSLRequireSSL" /etc/nagios4/apache2.conf || \
sed -i "/Require ip/ c\    Require ip 127.0.0.0/8 $LAN_NETWORK_ADDRESS/$CIDR
    /AuthDigestDomain/d
    /AuthDigestProvider/d
    /AuthUserFile/d
    /AuthGroupFile/d
    /AuthName/d
    /AuthType/d
    /Require all/d
    /#Require/d  
    /AllowOverride/ a\    <RequireAll>\n\
      SSLRequireSSL\n\
      AuthDigestDomain \"Nagios\"\n\
      AuthDigestProvider file\n\
      AuthUserFile \"/etc/apache2/.htpasswd.users\"\n\
      AuthGroupFile \"/etc/groups\"\n\
      AuthName \"Digest Authentication\"\n\
      AuthType Digest\n\
      Require valid-user\n\
    </RequireAll>" /etc/nagios4/apache2.conf
ln -fs /etc/nagios4/apache2.conf /etc/apache2/conf-available/nagios4-cgi.conf

# Configure hosts.cfg.
cat > /etc/nagios4/conf.d/hosts.cfg << EOF.hosts.cfg
# Host definitions.
define host {
  host_name              $HOSTNAME
  alias                  Ubuntu Router
  address                $LAN_IP_ADDRESS
  max_check_attempts     5
  check_period           24x7
  check_command          check_host_status
  contacts               root
  contact_groups         admins
  notification_interval  30
  notification_period    24x7
}
EOF.hosts.cfg

# Configure extinfo.cfg.
cat > /etc/nagios4/conf.d/extinfo.cfg << EOF.extinfo.cfg
# Extended Host and Service information.
define hostextinfo {
  notes            Ubuntu Linux servers
  icon_image       base/Ubuntu.png
  icon_image_alt   Ubuntu Linux
  vrml_image       ubuntu.png
  statusmap_image  base/ubuntu.gd2
}
EOF.extinfo.cfg

# Configure check_commands.cfg.
chmod u+s  /usr/lib/nagios/plugins/check_dhcp # Must be run as setuid root.
chmod u+s  /usr/lib/nagios/plugins/check_host 
cat > /etc/nagios4/conf.d/check_commands.cfg << EOF.check_commands.cfg
define command {
  command_name check_host_status
  command_line /usr/lib/nagios/plugins/check_host -H 127.0.0.1
}

define command {
  command_name check_dhcp_status
  command_line /usr/lib/nagios/plugins/check_dhcp -i $LAN_INTERFACE
}

define command {
  command_name check_smtp_status
  command_line /usr/lib/nagios/plugins/check_smtp -H 127.0.0.1
}

define command {
  command_name check_mysql_status
  command_line /usr/lib/nagios/plugins/check_mysql -H localhost -u \$ARG1\$ \
-p \$ARG2\$
}

define command {
  command_name check_nagios_status
  command_line /usr/lib/nagios/plugins/check_nagios -e \$ARG1\$ -F \$ARG2\$ \
-C \$ARG3\$
}
EOF.check_commands.cfg

# Configure services.cfg.
cat > /etc/nagios4/conf.d/services.cfg << EOF.services.cfg
# Check that hosts are running.
define service {
  host_name              $HOSTNAME
  service_description    Host Service
  check_command          check_host_status
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins	
}

# Check that the DNS service is running.
define service {
  host_name              $HOSTNAME
  service_description    DNS Service
  check_command          check_dns
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins	
}

# Check that the DHCP service is running.
define service {
  host_name              $HOSTNAME
  service_description    DHCP Service
  check_command          check_dhcp_status
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins	
}

# Check that the FTP service is running.
define service {
  host_name              $HOSTNAME
  service_description    FTP Service
  check_command          check_ftp
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins	
}

# Check that the Apache service is running.
define service {
  host_name              $HOSTNAME
  service_description    HTTP Service
  check_command          check_http
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins	
}

# Check that the SMTP service is running.
define service {
  host_name              $HOSTNAME
  service_description    SMTP Service
  check_command          check_smtp_status
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins	
}

# Check that the MariaDB service is running.
define service {
  host_name              $HOSTNAME
  service_description    MariaDB Service
  check_command          check_mysql_status!root!$ADMIN_PASSWORD
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins	
}

# Check that the Nagios service is running.
define service {
  host_name              $HOSTNAME
  service_description    Nagios Service
  check_command          check_nagios_status!5!/var/log/nagios4/nagios.log!\
/usr/sbin/nagios4
  max_check_attempts     5
  check_interval         5
  retry_interval         3
  check_period           24x7	
  notification_interval  30
  notification_period    24x7
  contacts               root
  contact_groups         admins	
}
EOF.services.cfg
chmod 600 /etc/nagios4/conf.d/services.cfg
chown nagios /etc/nagios4/conf.d/services.cfg

# Configure contacts.cfg.
cat > /etc/nagios4/objects/contacts.cfg << EOF.contacts.cfg
define contact {
  host_notifications_enabled     1
  service_notifications_enabled  1
  contact_name                   root
  service_notification_period    24x7
  host_notification_period       24x7
  service_notification_options   w,u,c,r
  host_notification_options      d,r
  service_notification_commands  notify-service-by-email
  host_notification_commands     notify-host-by-email
  email                          root@localhost
}

define contactgroup {
  contactgroup_name admins
  alias Nagios Administrators
  members root
}
EOF.contacts.cfg

# Reload configuration.
systemctl restart nagios4
systemctl restart apache2

################################################################################
#                                                                              #
# The following routine installs and configures DDclient, a Perl client used   #
# to update dynamic DNS entries for accounts on Dynamic DNS Network Services'  #
# free DNS service.                                                            #
#                                                                              #
# sourceforge.net/apps/trac/ddclient                                           #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing DDclient."
echo ""

# Install DDclient.
apt_function install $DDCLIENT

# Configure ddclient.conf.
if [ ! -f /etc/ddclient.conf.orig ]; then 
  mv /etc/ddclient.conf /etc/ddclient.conf.orig
fi
cat > /etc/ddclient.conf << EOF.ddclient
daemon=60 # Check every 60 seconds.
syslog=yes # Log update messages to syslog.
mail=root # Mail all messages to root.
mail-failure=root # Mail failed update messages to root.
pid=/var/run/ddclient.pid # Record PID in file.
ssl=yes # Use ssl-support. Works with ssl-library.
use=if, if=$WAN_INTERFACE # Get IP from the hardware interface.
server=api.dynu.com # IP update server.
protocol=dyndns2             
login=$EMAIL_ADDRESS # Your username.
password=$(echo -n "$ADMIN_PASSWORD" | openssl dgst -sha256 | awk '{ print $2 }') # Password hash.
$DYNAMICDNS_HOST # Register DYNAMICDNS_HOST with https://www.dynu.com/en-US/DynamicDNS.
EOF.ddclient
chmod 600 /etc/ddclient.conf
chown root:root /etc/ddclient.conf

# Reload configuration.
systemctl restart ddclient

################################################################################
#                                                                              #
# The following routine installs and configures OpenVPN, which implements      #
# virtual private network (VPN) techniques for creating secure point-to-point  #
# or site-to-site connections in routed or bridged configurations and remote   #
# access facilities.                                                           #
#                                                                              #
# openvpn.net                                                                  #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing OpenVPN."
echo ""

# Install OpenVPN
apt_function install $OPENVPN

# Configure server.conf.
cat > /etc/openvpn/server/server.conf << EOF.server.conf
topology subnet
port 1194
proto udp
server 10.8.0.0 $LAN_NETMASK
ifconfig-pool-persist ipp.txt
push "dhcp-option DNS $LAN_IP_ADDRESS"
push "route $LAN_NETWORK_ADDRESS $LAN_NETMASK"
dev tun
persist-tun
crl-verify /etc/ssl/crl/crl.pem
dh /etc/ssl/dh
ca /etc/ssl/certs/ca-cert.pem
cert /etc/ssl/certs/tls-cert.pem
key /etc/ssl/private/tls-key.pem
tls-auth /etc/ssl/private/ta.key 0
keepalive 10 120
user nobody
group nogroup
status openvpn-status.log
verb 3
explicit-exit-notify 1
EOF.server.conf

# Create the clientvpn script. 
# (Run this script to generate client configuration and TLS certificates 
# necessary to connect to your OpenVPN server.)
cat > /etc/openvpn/clientvpn << EOF.clientvpn
#!/bin/bash

# Create client.conf.
cat > /etc/openvpn/client/client.conf << EOF.client.conf
client
dev tun
persist-tun
proto udp
remote $DYNAMICDNS_HOST 1194
resolv-retry infinite
nobind
ca ca-cert.pem
cert client-cert.pem
key client-key.pem
tls-auth ta.key 1
remote-cert-tls server
user nobody
group nogroup
verb 3
mute-replay-warnings
EOF.client.conf

clear
echo ""
read -p "Type the FQDN of your client (e.g., or-ws1-ub.example.local), \
followed by [ENTER]: " HOSTNAME

# Create TLS certificate and key.
openssl req -new -nodes -keyout client-key.pem -out newreq.pem \
  -subj "/C=$COUNTRY/ST=$STATE/O=$ORGANIZATION/OU=TLS/CN=\$HOSTNAME/\
emailAddress=$EMAIL_ADDRESS"
openssl ca -batch -out newcert.pem -passin pass:$ADMIN_PASSWORD -infiles newreq.pem
mv newcert.pem client-cert.pem
rm -f newcert.pem newreq.pem

# Archive files to copy over to your client's OpenVPN directory.
cp -u /etc/ssl/certs/ca-cert.pem /etc/ssl/private/ta.key ./
tar -czvf \$HOSTNAME.tar.gz ta.key ca-cert.pem client-cert.pem \
  client-key.pem client.conf
rm -f client.conf ca-cert.pem client-cert.pem client-key.pem ta.key
EOF.clientvpn
chmod 700 /etc/openvpn/clientvpn
chown root:root /etc/openvpn/clientvpn

# Add the nobody user to the ssl-cert group so the daemon can read the TLS key.
usermod -aG ssl-cert nobody

# Create shared-secret key.
openvpn --genkey secret /etc/ssl/private/ta.key
chmod 440 /etc/ssl/private/ta.key
chown nobody /etc/ssl/private/ta.key
chgrp ssl-cert /etc/ssl/private/ta.key

# Reload configuration.
pgrep openvpn > /dev/null
if [ $? -eq 1 ]; then
  systemctl start openvpn
else
  systemctl restart openvpn
fi

################################################################################
#                                                                              #
# The following routine installs and configures the Linux Terminal Server      #
# Project (LTSP), which adds thin-client support to Linux servers. LTSP is a   #
# flexible, cost-effective solution that is empowering schools, businesses,    #
# and organizations all over the world to easily install and deploy desktop    #
# workstations.                                                                #
#                                                                              #
# ltsp.org                                                                     #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing LTSP."
echo ""

# Install LTSP.
apt_function install $LTSP

# Install ltsp.conf.
install -m 660 -g sudo /usr/share/ltsp/common/ltsp/ltsp.conf /etc/ltsp/ltsp.conf

# Install ltsp-dnsmasq.conf.
ltsp dnsmasq --real-dhcp=0 --dns-server="0.0.0.0"

# Install iPXE binaries and configuration.
ltsp ipxe

# Configure NFS exports.
ltsp nfs

# Create the ltsp.img initrd add-on.
mkdir -p /etc/ltsp/bin
cp /usr/bin/sshfs /etc/ltsp/bin/sshfs-"$(uname -m)"
ltsp initrd

# Add admin user to epoptes group.
gpasswd -a admin epoptes

# Create a SquashFS image from a virtual machine.
ln -fs "$LTSP_VM_PATH" /srv/ltsp/ubuntu.img
ltsp image ubuntu

################################################################################
#                                                                              #
# The following routine installs and configures Bind DNS for your LAN and WAN. #
# BIND (Berkeley Internet Name Domain) is an implementation of the Domain Name #
# System (DNS) protocols and provides an openly redistributable reference      #
# implementation of the major components of the Domain Name System.            #
#                                                                              #
# isc.org/bind                                                                 #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing Bind DNS."
echo ""

# Install Bind DNS.
apt_function install $BIND

# Configure named.conf.
cat > /etc/bind/named.conf << EOF.named.conf
include "/etc/bind/zones.rfc1918";
include "/etc/bind/named.conf.log";
include "/etc/bind/named.conf.local";
include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.default-zones";
EOF.named.conf

# Configure DNS forwarders.
NAMESERVERS=$(awk '/^nameserver/{print $2}' /etc/resolv.conf)
NS1=$(echo "$NAMESERVERS" | awk '{print $1}')
NS2=$(echo "$NAMESERVERS" | awk '{print $2}')
if [ -z "$NS2" ]; then
  NAMESERVERS="$NS1"
else
  NAMESERVERS="$NS1; $NS2"
fi

# Configure named.conf.options.
cat > /etc/bind/named.conf.options << EOF.named.conf.options
options {
  directory "/var/cache/bind";
  forwarders { $NAMESERVERS; 208.67.222.222; 208.67.220.220; 208.67.222.220; \
208.67.220.222; 8.8.8.8; 8.8.4.4; };
  auth-nxdomain no;    # Conform to RFC1035.
  transfer-format many-answers;
  max-transfer-time-in 60;
  notify no;
  version "Not currently available.";
};
EOF.named.conf.options

# Configure named.conf.local.
cat > /etc/bind/named.conf.local << EOF.named.conf.local

zone "$LAN_DOMAIN" {
  type master;
  file "/var/lib/bind/db.$LAN_DOMAIN.";
};

zone "$LAN_REVERSE_ZONE" {
  type master;
  file "/var/lib/bind/db.$LAN_REVERSE_ZONE.";
};
EOF.named.conf.local

# Create named.conf.log.
cat > /etc/bind/named.conf.log << EOF.named.conf.log
logging {
  channel update_debug {
    file "/var/log/named/update_debug.log" versions 3 size 100k;
      severity debug;
      print-severity  yes;
      print-time      yes;
    };
    channel security_info {
      file "/var/log/named/security_info.log" versions 1 size 100k;
      severity info;
      print-severity  yes;
      print-time      yes;
    };
    channel bind_log {
    file "/var/log/named/bind.log" versions 3 size 1m;
      severity info;
      print-category  yes;
      print-severity  yes;
      print-time      yes;
    };

    category default { bind_log; };
    category lame-servers { null; };
    category update { update_debug; };
    category update-security { update_debug; };
    category security { security_info; };
};
EOF.named.conf.log
mkdir -p /var/log/named
chown bind /var/log/named

# Configure Logrotate.
cat > /etc/logrotate.d/bind << EOF.logrotate.d
/var/log/named/*.log {
  compress
  create 0644 named named
  daily
  dateext
  missingok
  notifempty
  rotate 30
  sharedscripts
  postrotate
    /usr/sbin/rndc reconfig > /dev/null 2>/dev/null || true
  endscript
}
EOF.logrotate.d

# Create forward DNS zone.
cat << EOF.db.LAN_DOMAIN | column -t > /var/cache/bind/db."$LAN_DOMAIN".
\$TTL 3600  ; 1 hour
\$ORIGIN $LAN_DOMAIN.
@	IN	SOA	$FQDN. hostmaster.$LAN_DOMAIN. (
			$(date +%Y%m%d00) ; serial
			900        ; refresh (15 minutes)
			900        ; retry (15 minutes)
			604800     ; expire (1 week)
			3600       ; minimum (1 hour)
			)
	IN	NS		$FQDN.
$HOSTNAME	IN	A		$LAN_IP_ADDRESS
EOF.db.LAN_DOMAIN

# Create reverse DNS zone.
cat << EOF.db.LAN_REVERSE_ZONE | column -t > /var/cache/bind/db."$LAN_REVERSE_ZONE".
\$TTL 3600  ; 1 hour
\$ORIGIN $LAN_REVERSE_ZONE.
@	IN	SOA	$FQDN. hostmaster.$LAN_DOMAIN. (
			$(date +%Y%m%d00) ; serial
			900        ; refresh (15 minutes)
			900        ; retry (15 minutes)
			604800     ; expire (1 week)
			3600       ; minimum (1 hour)
			)
	IN	NS		$FQDN.
$LAN_IP_ADDRESS_4TH_OCTET	IN	PTR		$FQDN.
EOF.db.LAN_REVERSE_ZONE

# Reload configuration.
systemctl restart bind9

################################################################################
#                                                                              #
# The following routine installs and configures Kea DHCP, a collection of      #
# software that implements all aspects of the DHCP (Dynamic Host Configuration #
# Protocol) suite.                                                             #
#                                                                              #
# isc.org/kea                                                                  #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing Kea DHCP Server."
echo ""

# Install Kea DHCP Server.
apt_function install $KEA

# Configure kea-api-password.
echo "$ADMIN_PASSWORD" > /etc/kea/kea-api-password

# Configure kea-dhcp4.conf.
if [ ! -f /etc/kea/kea-dhcp4.conf.orig ]; then
  mv /etc/kea/kea-dhcp4.conf /etc/kea/kea-dhcp4.conf.orig
fi
cat > /etc/kea/kea-dhcp4.conf << EOF.kea-dhcp4.conf
{
  "Dhcp4": {
    "interfaces-config": {
    "interfaces": [ "$LAN_INTERFACE" ]
    },

    "control-socket": {
      "socket-type": "unix",
      "socket-name": "/run/kea/kea4-ctrl-socket"
    },

    "lease-database": {
      "type": "memfile",
      "lfc-interval": 3600
    },

    "valid-lifetime": 600,
    "max-valid-lifetime": 7200,

    "subnet4": [{
      "id": 1,
      "subnet": "$LAN_NETWORK_ADDRESS/$CIDR",
      "pools": [{
        "pool": "$DHCP_HOST_MIN - $DHCP_HOST_MAX"
      }],

      "option-data": [{
        "name": "routers",
        "data": "$LAN_IP_ADDRESS"
      },{
        "name": "domain-name-servers",
        "data": "$LAN_IP_ADDRESS"
      },{
        "name": "domain-name",
        "data": "$LAN_DOMAIN"
      }]

      "reservations": [{
        "hw-address": "$(ip addr show $LAN_INTERFACE | grep link/ether | awk '{ print $2 }')",
        "ip-address": "$LAN_IP_ADDRESS"
      }]
    }]
  }
}
EOF.kea-dhcp4.conf

# Reload configuration.
systemctl restart kea-dhcp4-server

################################################################################
#                                                                              #
# The following routine installs and configures Snort, which provides an       #
# open-source network intrusion detection and prevention system capable of     #
# performing real-time traffic analysis and packet logging on IP networks.     #
#                                                                              #
# snort.org                                                                    #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing Snort."
echo ""

# Install Snort.
apt_function install $SNORT

# Configure Snort's MariaDB database.
mysql --user=root --password="$ADMIN_PASSWORD" << EOF.snortdb
DROP DATABASE IF EXISTS snortdb;
CREATE DATABASE snortdb;
CREATE USER 'snort'@'localhost' IDENTIFIED VIA mysql_native_password USING '$ADMIN_PASSWORD';
GRANT CREATE,INSERT,SELECT,DELETE,UPDATE ON `snortdb`.* TO 'snort'@'localhost';
FLUSH PRIVILEGES;
EOF.snortdb

# Configure snort.debian.conf.
if [ ! -f /etc/snort/snort.debian.conf.orig ]; then 
  cp /etc/snort/snort.debian.conf /etc/snort/snort.debian.conf.orig
fi
sed -i "s|DEBIAN_SNORT_HOME_NET=.*$\
|DEBIAN_SNORT_HOME_NET=\"$LAN_NETWORK_ADDRESS/$CIDR\"|
  s|DEBIAN_SNORT_INTERFACE=.*$|DEBIAN_SNORT_INTERFACE=\
\"$LAN_INTERFACE $WAN_INTERFACE\"|" /etc/snort/snort.debian.conf

# Remove the pending Snort database configuration file.
rm -f /etc/snort/db-pending-config

# Configure oinkmaster.conf.
sed -i "/Community-Rules-CURRENT.tar.gz/ s|^# ||" /etc/oinkmaster.conf

# Create the Oinkmaster cron job.
echo "@daily root oinkmaster -o /etc/snort/rules \
-b /etc/snort/backup 2>&1 | logger -t oinkmaster" > \
  /etc/cron.d/oinkmaster_updater

# Reload configuration.
systemctl restart snort

################################################################################
#                                                                              #
# The following routine installs and configures Postfix, a scalable, secure    #
# implementation of an SMTP Mail Transfer Agent.                               #
#                                                                              #
# postfix.org                                                                  #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing Postfix."
echo ""

# Install Postfix.
apt_function install $POSTFIX

# Create root alias and update the local alias database.
if [ ! -f /etc/aliases.orig ]; then 
  cp /etc/aliases /etc/aliases.orig
fi
grep -q "root: $EMAIL_ADDRESS" /etc/aliases || \
  echo "root: $EMAIL_ADDRESS" >> /etc/aliases
newaliases

# Configure mailname.
echo "$FQDN" > /etc/mailname

# Configure main.cf.
if [ ! -f /etc/postfix/main.cf.orig ]; then 
  cp /etc/postfix/main.cf /etc/postfix/main.cf.orig
fi
cat > /etc/postfix/main.cf << EOF.main.cf
myorigin = $mydomain
myhostname = $FQDN
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
mydestination = \$myhostname, localhost.\$mydomain, localhost
inet_interfaces = $LAN_IP_ADDRESS
mynetworks = 127.0.0.0/8 $LAN_NETWORK_ADDRESS/$CIDR
recipient_delimiter = +
EOF.main.cf

# Reload configuration.
systemctl restart postfix

################################################################################
#                                                                              #
# The following routine installs and configures Webmin, a web-based interface  #
# for system administration. Using any browser that supports tables and forms  #
# (and Java for the File Manager module), you can set up user accounts,        #
# Apache, DNS, file sharing, and so on.                                        #
#                                                                              #
# webmin.com                                                                   #
#                                                                              #
################################################################################

clear
echo ""
echo "Installing Webmin."
echo ""

# Install Webmin.
apt_function install $WEBMIN

# Configure miniserv.conf.
if [ ! -f /etc/webmin/miniserv.conf.orig ]; then 
  cp /etc/webmin/miniserv.conf /etc/webmin/miniserv.conf.orig
fi
sed -i "/keyfile=/ c\keyfile=/etc/ssl/private/tls-key.pem" \
  /etc/webmin/miniserv.conf
grep -q "certfile" /etc/webmin/miniserv.conf || \
  sed -i "/keyfile=/ \
a\certfile=/etc/ssl/certs/tls-cert.pem\nssl_redirect=1" \
    /etc/webmin/miniserv.conf
grep -q "allow=127.0.0.1 LOCAL" /etc/webmin/miniserv.conf || \
  echo "allow=127.0.0.1 LOCAL" >> /etc/webmin/miniserv.conf

# Configure miniserv.users.
echo "admin:x:0::::::::" > /etc/webmin/miniserv.users

# Configure Stunnel.
if [ ! -f /etc/webmin/config.orig ]; then 
  cp /etc/webmin/config /etc/webmin/config.orig
fi
sed -i "/stunnel_path=/ c\stunnel_path=/usr/bin/stunnel4
  /pem_path=/ c\pem_path=/etc/ssl/certs/tls-cert.pem" /etc/webmin/config
sed -i "s|ENABLED=0|ENABLED=1|" /etc/default/stunnel4
cp -u /usr/share/doc/stunnel4/examples/stunnel.conf-sample \
  /etc/stunnel/stunnel.conf
if [ ! -f /etc/stunnel/stunnel.conf.orig ]; then 
  cp /etc/stunnel/stunnel.conf /etc/stunnel/stunnel.conf.orig
fi
sed -i "/cert =/ c\cert = /etc/ssl/certs/tls-cert.pem
  /key =/ c\key = /etc/ssl/private/tls-key.pem
  /CAfile =/ c\CAfile = /etc/ssl/certs/ca-cert.pem
  /CRLfile =/ c\CRLfile = /etc/ssl/crl/crl.pem" /etc/stunnel/stunnel.conf


# Set administrator password for Webmin.
webmin passwd --user admin --password $ADMIN_PASSWORD

# Set administrator password for MariaDB.
if [ ! -f /etc/webmin/mysql/config.orig ]; then 
  cp /etc/webmin/mysql/config /etc/webmin/mysql/config.orig
fi
grep -q "pass=$ADMIN_PASSWORD" /etc/webmin/mysql/config || \
  echo "pass=$ADMIN_PASSWORD" >> /etc/webmin/mysql/config
chmod 600 /etc/webmin/mysql/config

# Configure admin.acl.
cat > /etc/webmin/admin.acl << EOF.admin.acl
rpc=2
nodot=0
webminsearch=1
uedit_mode=0
gedit_mode=0
feedback=2
otherdirs=
readonly=0
fileunix=root
uedit=
negative=0
root=/
uedit2=
gedit=
gedit2=
EOF.admin.acl

# Configure webmin.acl.
echo "admin: backup-config change-user webmincron usermin webminlog webmin \
servers acl init passwd quota mount fsdump logrotate mailcap pam proc at \
cron package-updates software man syslog system-status useradmin \
security-updates virtualmin-awstats apache bind8 mysql postfix mailboxes \
sshd squid sarg virtual-server webalizer bandwidth exports net xinetd \
inetd stunnel shorewall tcpwrappers idmapd filter burner grub lilo raid lvm \
fdisk lpadmin smart-status time vgetty shell custom file tunnel phpini cpan \
htaccess-htpasswd telnet status ajaxterm \
updown proftpd" > /etc/webmin/webmin.acl

# Configure installed.cache.
cat > /etc/webmin/installed.cache << EOF.installed.cache
quota=1
proc=1
tcpwrappers=1
ajaxterm=1
mailboxes=1
usermin=1
bind8=1
stunnel=1
nis=1
at=1
raid=1
lpadmin=1
man=1
backup-config=1
postfix=1
sshd=1
telnet=1
software=1
lvm=1
custom=1
cpan=1
shell=1
grub=1
shorewall=1
file=1
mailcap=1
phpini=1
init=1
webminlog=1
webmin=1
idmapd=1
apache=1
fdisk=1
syslog=1
procmail=0
smart-status=1
webalizer=1
pam=1
updown=1
samba=0
filter=1
xinetd=0
webmincron=1
mount=1
acl=1
inetd=1
dhcpd=0
system-status=1
passwd=1
htaccess-htpasswd=1
change-user=1
status=1
mysql=1
logrotate=1
bandwidth=1
burner=1
time=1
package-updates=1
cron=1
useradmin=1
squid=1
exports=1
net=1
firewall=1
servers=1
tunnel=1
fsdump=1
sarg=1
proftpd=1
EOF.installed.cache

# Reload configuration.
systemctl restart webmin
systemctl restart stunnel4
systemctl restart apache2

# Create web-access menu.
cat > /var/www/html/index.html << EOF.index.html
<html>
  <body>
    <div align="center">
      <a href="https://$LAN_IP_ADDRESS:631/admin" target="_blank">CUPS</a> |
      <a href="https://$LAN_IP_ADDRESS/munin" target="_blank">Munin</a> |
      <a href="https://$LAN_IP_ADDRESS/nagios4" target="_blank">Nagios</a> |
      <a href="https://$LAN_IP_ADDRESS/phpmyadmin" target="_blank">phpMyAdmin</a> |
      <a href="https://$LAN_IP_ADDRESS:10000" target="_blank">Webmin</a>
    </div>
  </body>
</html>
EOF.index.html

echo "Script end time: $(date +%c)"

# Activate the Debconf frontend.
unset DEBIAN_FRONTEND

# Log in to the GUI.
clear
echo ""
echo "Access your Ubuntu Linux server at https://$LAN_IP_ADDRESS"
echo ""
echo "Log in to the GUI with the following:"
echo ""
echo "username = admin"
echo "password = enter your administrator password"
echo ""

# End of redirect (STDOUT and STDERROR logged to terminal and install.log).
) 2>&1 | tee install.log 

exit 0
