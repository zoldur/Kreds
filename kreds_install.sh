#!/bin/bash

TMP_FOLDER=$(mktemp -d)
CONFIG_FILE="kreds.conf"
COIN_DAEMON="/usr/local/bin/kredsd"
COIN_CLI="/usr/local/bin/kreds-cli"
COIN_REPO="https://github.com/KredsBlockchain/kreds-core.git"
DEFAULTCOINPORT=3950
RPCPORT=3850
DEFAULTCOINUSER="kreds"

NODEIP=$(curl -s4 icanhazip.com)


RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'


function get_ip() {
  declare -a NODE_IPS
  for ips in $(netstat -i | awk '!/Kernel|Iface|lo/ {print $1," "}')
  do
    NODE_IPS+=($(curl --interface $ips --connect-timeout 2 -s4 icanhazip.com))
  done

  if [ ${#NODE_IPS[@]} -gt 1 ]
    then
      echo -e "${GREEN}More than one IP. Please type 0 to use the first IP, 1 for the second and so on...${NC}"
      INDEX=0
      for ip in "${NODE_IPS[@]}"
      do
        echo ${INDEX} $ip
        let INDEX=${INDEX}+1
      done
      read -e choose_ip
      NODEIP=${NODE_IPS[$choose_ip]}
  else
    NODEIP=${NODE_IPS[0]}
  fi
}


function compile_error() {
if [ "$?" -gt "0" ];
 then
  echo -e "${RED}Failed to compile $@. Please investigate.${NC}"
  exit 1
fi
}


function checks() {
if [[ $(lsb_release -d) != *16.04* ]]; then
  echo -e "${RED}You are not running Ubuntu 16.04. Installation is cancelled.${NC}"
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}$0 must be run as root.${NC}"
   exit 1
fi

if [ -n "$(pidof $COIN_DAEMON)" ] || [ -e "$COIN_DAEMOM" ] ; then
  echo -e "${GREEN}\c"
  read -e -p "Kreds is already installed. Do you want to add another MN? [Y/N]" NEW_COIN
  echo -e "{NC}"
  clear
else
  NEW_COIN="new"
fi
}

function prepare_system() {
echo -e "Checking if swap space is needed."
PHYMEM=$(free -g|awk '/^Mem:/{print $2}')
SWAP=$(free -g|awk '/^Swap:/{print $2}')
if [ "$PHYMEM" -lt "2" ] && [ -n "$SWAP" ]
  then
    echo -e "${GREEN}Server is running with less than 2G of RAM without SWAP, creating 2G swap file.${NC}"
    SWAPFILE=$(mktemp)
    dd if=/dev/zero of=$SWAPFILE bs=1024 count=2M
    chmod 600 $SWAPFILE
    mkswap $SWAPFILE
    swapon -a $SWAPFILE
else
  echo -e "${GREEN}Server running with at least 2G of RAM, no swap needed.${NC}"
fi
clear

echo -e "Prepare the system to install Kreds master node."
apt-get update >/dev/null 2>&1
DEBIAN_FRONTEND=noninteractive apt-get update > /dev/null 2>&1
DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y -qq upgrade >/dev/null 2>&1
apt install -y software-properties-common >/dev/null 2>&1
echo -e "${GREEN}Adding bitcoin PPA repository"
apt-add-repository -y ppa:bitcoin/bitcoin >/dev/null 2>&1
echo -e "Installing required packages, it may take some time to finish.${NC}"
apt-get update >/dev/null 2>&1
apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" make software-properties-common \
build-essential libtool autoconf libssl-dev libboost-dev libboost-chrono-dev libboost-filesystem-dev libboost-program-options-dev \
libboost-system-dev libboost-test-dev libboost-thread-dev sudo automake git wget pwgen curl libdb4.8-dev bsdmainutils libdb4.8++-dev \
libminiupnpc-dev libgmp3-dev ufw fail2ban python-virtualenv pkg-config libeven-dev >/dev/null 2>&1
if [ "$?" -gt "0" ];
  then
    echo -e "${RED}Not all required packages were installed properly. Try to install them manually by running the following commands:${NC}\n"
    echo "apt-get update"
    echo "apt -y install software-properties-common"
    echo "apt-add-repository -y ppa:bitcoin/bitcoin"
    echo "apt-get update"
    echo "apt install -y make build-essential libtool software-properties-common autoconf libssl-dev libboost-dev libboost-chrono-dev libboost-filesystem-dev \
libboost-program-options-dev libboost-system-dev libboost-test-dev libboost-thread-dev sudo automake git pwgen curl libdb4.8-dev \
bsdmainutils libdb4.8++-dev libminiupnpc-dev libgmp3-dev ufw fail2ban python-virtualenv pkg-config libevent-dev"
 exit 1
fi

clear
}

function compile_node() {
  echo -e "Download binaries. This may take some time. Press a key to continue."
  git clone $COIN_REPO $TMP_FOLDER >/dev/null 2>&1
  cd $TMP_FOLDER
  ./autogen.sh
  compile_error Kreds autogen.sh
  ./configure 
  compile_error Kreds configure
  make
  compile_error Kreds make
  make install
  cd -
  rm -rf $TMP_FOLDER
}

function enable_firewall() {
  echo -e "Installing fail2ban and setting up firewall to allow ingress on port ${GREEN}$COINPORT${NC}"
  ufw allow $COINPORT/tcp comment "Kreds MN port" >/dev/null
  ufw allow $RPCPORT/tcp comment "Kreds RPC port" >/dev/null
  ufw allow ssh comment "SSH" >/dev/null 2>&1
  ufw limit ssh/tcp >/dev/null 2>&1
  ufw default allow outgoing >/dev/null 2>&1
  echo "y" | ufw enable >/dev/null 2>&1
  systemctl enable fail2ban >/dev/null 2>&1
  systemctl start fail2ban >/dev/null 2>&1
}

function configure_systemd() {
  cat << EOF > /etc/systemd/system/$COINUSER.service
[Unit]
Description=Kred service
After=network.target

[Service]
User=$COINUSER
Group=$COINUSER

Type=forking
PIDFile=$COINFOLDER/$COINUSER.pid

ExecStart=$COIN_DAEMON -daemon -pid=$COINFOLDER/$COINUSER.pid -conf=$COINFOLDER/$CONFIG_FILE -datadir=$COINFOLDER
ExecStop=-$COIN_CLI -conf=$COINFOLDER/$CONFIG_FILE -datadir=$COINFOLDER stop

Restart=always
PrivateTmp=true
TimeoutStopSec=60s
TimeoutStartSec=2s
StartLimitInterval=120s
StartLimitBurst=5

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  sleep 3
  systemctl start $COINUSER.service
  systemctl enable $COINUSER.service

  if [[ -z "$(ps axo user:15,cmd:100 | egrep ^$COINUSER | grep $COIN_DAEMON)" ]]; then
    echo -e "${RED}COIN is not running${NC}, please investigate. You should start by running the following commands as root:"
    echo -e "${GREEN}systemctl start $COINUSER.service"
    echo -e "systemctl status $COINUSER.service"
    echo -e "less /var/log/syslog${NC}"
    exit 1
  fi
}

function ask_port() {
read -p "Kreds Port: " -i $DEFAULTCOINPORT -e COINPORT
: ${COINPORT:=$DEFAULTCOINPORT}
}

function ask_user() {
  read -p "Kreds user: " -i $DEFAULTCOINUSER -e COINUSER
  : ${COINUSER:=$DEFAULTCOINUSER}

  if [ -z "$(getent passwd $COINUSER)" ]; then
    USERPASS=$(pwgen -s 12 1)
    useradd -m $COINUSER
    echo "$COINUSER:$USERPASS" | chpasswd

    COINHOME=$(sudo -H -u $COINUSER bash -c 'echo $HOME')
    DEFAULTCOINFOLDER="$COINHOME/.kreds"
    read -p "Configuration folder: " -i $DEFAULTCOINFOLDER -e COINFOLDER
    : ${COINFOLDER:=$DEFAULTCOINFOLDER}
    mkdir -p $COINFOLDER
    chown -R $COINUSER: $COINFOLDER >/dev/null 2>&1
  else
    clear
    echo -e "${RED}User exits. Please enter another username: ${NC}"
    ask_user
  fi
}

function check_port() {
  declare -a PORTS
  PORTS=($(netstat -tnlp | grep $NODEIP | awk '/LISTEN/ {print $4}' | awk -F":" '{print $NF}' | sort | uniq | tr '\r\n'  ' '))
  ask_port

  while [[ ${PORTS[@]} =~ $COINPORT ]] || [[ ${PORTS[@]} =~ $[RPCPORT] ]]; do
    clear
    echo -e "${RED}Port in use, please choose another port:${NF}"
    ask_port
  done
}

function create_config() {
  RPCUSER=$(pwgen -s 8 1)
  RPCPASSWORD=$(pwgen -s 15 1)
  cat << EOF > $COINFOLDER/$CONFIG_FILE
rpcuser=$RPCUSER
rpcpassword=$RPCPASSWORD
rpcallowip=127.0.0.1
rpcport=$[COINPORT-1]
listen=1
server=1
bind=$NODEIP
daemon=1
port=$COINPORT
EOF
}

function create_key() {
  echo -e "Enter your ${RED}Masternode Private Key${NC}. Leave it blank to generate a new ${RED}Masternode Private Key${NC} for you:"
  read -e COINKEY
  if [[ -z "$COINKEY" ]]; then
  su $COINUSER -c "$COIN_DAEMON -conf=$COINFOLDER/$CONFIG_FILE -datadir=$COINFOLDER"
  sleep 10
  if [ -z "$(ps axo user:15,cmd:100 | egrep ^$COINUSER | grep $COIN_DAEMON)" ]; then
   echo -e "${RED}Kreds server couldn't start. Check /var/log/syslog for errors.{$NC}"
   exit 1
  fi
  COINKEY=$(su $COINUSER -c "$COIN_CLI -conf=$COINFOLDER/$CONFIG_FILE -datadir=$COINFOLDER masternode genkey")
  su $COINUSER -c "$COIN_CLI -conf=$COINFOLDER/$CONFIG_FILE -datadir=$COINFOLDER stop"
fi
}

function update_config() {
  sed -i 's/daemon=1/daemon=0/' $COINFOLDER/$CONFIG_FILE
  cat << EOF >> $COINFOLDER/$CONFIG_FILE
maxconnections=256
masternode=1
externalip=$NODEIP
masternodeprivkey=$COINKEY
EOF
  chown -R $COINUSER: $COINFOLDER >/dev/null
}


function important_information() {
 echo
 echo -e "================================================================================================================================"
 echo -e "Kreds Masternode is up and running as user ${GREEN}$COINUSER${NC} and it is listening on port ${GREEN}$COINPORT${NC}."
 echo -e "${GREEN}$COINUSER${NC} password is ${RED}$USERPASS${NC}"
 echo -e "Configuration file is: ${RED}$COINFOLDER/$CONFIG_FILE${NC}"
 echo -e "Start: ${RED}systemctl start $COINUSER.service${NC}"
 echo -e "Stop: ${RED}systemctl stop $COINUSER.service${NC}"
 echo -e "VPS_IP:PORT ${RED}$NODEIP:$COINPORT${NC}"
 echo -e "MASTERNODE PRIVATEKEY is: ${RED}$COINKEY${NC}"
 echo -e "Please check Kreds is running with the following command: ${GREEN}systemctl status $COINUSER.service${NC}"
 echo -e "================================================================================================================================"
}

function setup_node() {
  get_ip
  ask_user
  check_port
  create_config
  create_key
  update_config
  enable_firewall
  configure_systemd
  important_information
}


##### Main #####
clear

checks
if [[ ("$NEW_COIN" == "y" || "$NEW_COIN" == "Y") ]]; then
  setup_node
  exit 0
elif [[ "$NEW_COIN" == "new" ]]; then
  prepare_system
  compile_node
  setup_node
else
  echo -e "${GREEN}Kreds already running.${NC}"
  exit 0
fi

