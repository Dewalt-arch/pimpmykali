#!/bin/bash
#
# pimpmykali.sh  Author: Dewalt
# git clone https://github.com/Dewalt-arch/pimpmykali 
# Usage: sudo ./pimpmykali.sh  ( defaults to the menu system )
# command line arguments are valid
#
# Full Revision history can be found in changelog.txt
# Standard Disclaimer: Author assumes no liability for any damage

# revision var
    revision="2.0.3"

# prompt colors
    red=$'\e[1;31m'
    green=$'\e[1;32m'
    blue=$'\e[1;34m'
    magenta=$'\e[1;35m'
    cyan=$'\e[1;36m'
    yellow=$'\e[1;93m'
    white=$'\e[0m'
    bold=$'\e[1m'
    norm=$'\e[21m'
    reset=$'\e[0m'
    spaces='       '

# status indicators
    greenplus='\e[1;33m[++]\e[0m'
    greenminus='\e[1;33m[--]\e[0m'
    redminus='\e[1;31m[--]\e[0m'
    redexclaim='\e[1;31m[!!]\e[0m'
    redstar='\e[1;31m[**]\e[0m'
    blinkexclaim='\e[1;31m[\e[5;31m!!\e[0m\e[1;31m]\e[0m'
    fourblinkexclaim='\e[1;31m[\e[5;31m!!!!\e[0m\e[1;31m]\e[0m'

# variables needed in the script
    force=0
    check=""
    section=""
    type=""
    menu=""
    pipnowarn="--no-python-version-warning"
    export PYTHONWARNINGS="ignore"
    nessusd_service_active=0

# variables moved from local to global
    finduser=$(logname)
    detected_env=""
    menuinput=""
   
    pyver=$(python3 --version | awk '{print$2}' | cut -d "." -f1-2)
   
    archtype=$(uname -m)
    if [ "$archtype" == "aarch64" ]; 
      then 
        arch="arm64"
    fi

    if [ "$archtype" == "x86_64" ]; 
      then
        arch="amd64"
    fi

# logging
    LOG_FILE=pimpmykali.log
    exec > >(tee ${LOG_FILE}) 2>&1

# silent mode
    silent=''                  # uncomment to see all output
    #silent='>/dev/null 2>&1' # uncomment to hide all output
    export DEBIAN_FRONTEND=noninteractive
    export PYTHONWARNINGS=ignore

# minimize apt updates
    APT_UPDATE_RAN=0

# Variables used with --auto, --autonoroot and make_rootgreatagain functions
    SPEEDRUN=0
    ENABLE_ROOT=0


check_distro() {
    distro=$(uname -a | grep -i -c "kali") # distro check
    if [ $distro -ne 1 ]
     then echo -e "\n ${redexclaim} Kali Linux Not Detected - WSL/WSL2/Anything else is unsupported ${redexclaim} \n"; exit
    fi

    # check for tracelabs osint vm, if found exit
    findhostname=$(hostname)
    findrelease=$(cat /etc/os-release | grep -i -c -m1 "2022.1")
    if [[ "$finduser" == "osint" ]] && [[ "$findhostname" == "osint" ]] && [[ $findrelease -ge 1 ]]
     then 
      echo -e "\n  ${redexclaim} Tracelabs Osint VM Detected, exiting"
      exit
    fi 
    }


check_for_root() {
    if [ "$EUID" -ne 0 ]
      then echo -e "\n\n Script must be run with sudo ./pimpmykali.sh or as root \n"
      exit
    else
      # Remove any prior hold on metasploit-framework at startup
      eval apt-mark unhold metasploit-framework >/dev/null 2>&1
    fi
    }


clean_vars() {
    APP=""
    EXIT_STATUS=""
    FUNCTYPE=""
    }


check_exit_status() {
    case ${EXIT_STATUS} in 
        0) ;; 
        1) echo -e "\n${spaces}${redexclaim} ${APP} ${FUNCTYPE} General Error Exit Status: ${EXIT_STATUS}\n"; exit 1;;
        2) echo -e "\n${spaces}${redexclaim} ${APP} ${FUNCTYPE} Misuse of Shell commands, Exit Status: ${EXIT_STATUS}\n"; exit 2;;
      100) echo -e "\n${spaces}${redexclaim} ${APP} ${FUNCTYPE} Mirror sync in progress try again later, Exit Status: ${EXIT_STATUS}\n"; exit 100;;
      126) echo -e "\n${spaces}${redexclaim} ${APP} ${FUNCTYPE} Command Invoked Cannot Execute, Exit Status ${EXIT_STATUS}\n"; exit 126;;
      127) echo -e "\n${spaces}${redexclaim} ${APP} ${FUNCTYPE} Command Not Found, Exit Staus: ${EXIT_STATUS}\n"; exit 127;;
      128) echo -e "\n${spaces}${redexclaim} ${APP} ${FUNCTYPE} Invalid Arguement to Exit, Exit Status: ${EXIT_STATUS}\n"; exit 128;;
      255) echo -e "\n${spaces}${redexclaim} ${APP} ${FUNCTYPE} Exit status out of range, Exit Status: ${EXIT_STATUS}\n"; exit 255;;
        *) echo -e "\n${spaces}${redexclaim} Exit Status ${EXIT_STATUS} for ${APP} ${FUNCTYPE} status: failed\n";;
    esac
    }


is_installed() {
    app="$@"

    for each_app in ${app}
    do
      echo -e "\n  ${greenplus} Checking if ${each_app} is installed"

      is_app_installed=$(apt-cache policy ${each_app} | grep -i -c "Installed: (none)")

      if [[ $is_app_installed -ge 1 ]]
      then
        clean_vars
        APP="apt"
        FUNCTYPE="install ${each_app}"
        echo -e "${spaces}${greenplus} Installing ${each_app}"
        apt-get --quiet install -y ${each_app} >/dev/null 2>&1
        EXIT_STATUS="$?"
        check_exit_status ${APP} ${FUNCTYPE} ${EXIT_STATUS}
      else
        echo -e "${spaces}${greenplus} $each_app is installed"
      fi
    done
    }


is_installed_remove() {
    app="$@"

    for each_app in ${app}
    do
      echo -e "\n  ${greenplus} Checking if ${each_app} is installed"
      is_app_installed=$(apt-cache policy ${each_app} | grep -i -c "100 \/var\/lib\/dpkg\/status")

      if [[ $is_app_installed -ge 1 ]]
      then
        clean_vars
        APP="apt"
        FUNCTYPE="remove ${each_app}"
        echo -e "${spaces}${greenplus} Removing ${each_app} \n"
        apt remove -y ${each_app} >/dev/null 2>&1
        EXIT_STATUS="$?"
        check_exit_status ${APP} ${FUNCTYPE} ${EXIT_STATUS}
      else
        echo -e "${spaces}${greenminus} ${each_app} is not installed \n"
      fi
    done
    }


is_installed_reinstall() {
    app="$@"

    for each_app in ${app}
    do
      echo -e "\n  ${greenplus} Checking if ${each_app} is installed"
      is_app_installed=$(apt-cache policy ${each_app} | grep -i -c "100 \/var\/lib\/dpkg\/status")

      if [[ $is_app_installed -ge 1 ]]
      then
        clean_vars
        APP="apt"
        FUNCTYPE="reinstall ${each_app}" >/dev/null 2>&1
        echo -e "${spaces}${greenplus} Reinstalling ${each_app}"
        apt reinstall -y ${each_app} >/dev/null 2>&1
        EXIT_STATUS="$?"
        check_exit_status ${APP} ${FUNCTYPE} ${EXIT_STATUS}
      else
        echo -e "${spaces}${greenminus} ${each_app} is already installed \n"
      fi
    done
    }


apt_update() {
    echo -e "\n  ${greenplus} running: apt update \n"
    APP="apt"
    FUNCTYPE="update"
    eval apt -y update
    EXIT_STATUS="$?"
    check_exit_status ${APP} ${FUNCTYPE} ${EXIT_STATUS}
    clean_vars
    export APT_UPDATE_RAN=1
    }


apt_upgrade() {
    echo -e "\n  ${greenplus} running: apt upgrade \n"
    APP="apt"
    FUNCTYPE="upgrade"
    eval apt -y upgrade
    EXIT_STATUS="$?"
    check_exit_status ${APP} ${FUNCTYPE} ${EXIT_STATUS}
    clean_vars
    }


apt_autoremove() {
    echo -e "\n  ${greenplus} running: apt autoremove \n"
    APP="apt"
    FUNCTYPE="autoremove"
    eval apt -y autoremove
    EXIT_STATUS="$?"
    check_exit_status ${APP} ${FUNCTYPE} ${EXIT_STATUS}
    clean_vars
    }


apt_fixbroken() {
    APP="apt"
    FUNCTYPE="--fix-broken install"
    eval apt -y --fix-broken install >/dev/null 2>&1
    EXIT_STATUS="$?"
    check_exit_status ${APP} ${FUNCTYPE} ${EXIT_STATUS}
    clean_vars
    }


fix_missing() {
    fix_kali_lightdm_theme_and_background
    fix_sources 
    setup_binfmt_mount
    fix_hushlogin
    fix_grub
    fix_smbconf
    fix_libwacom
    apt_autoremove
    check_installed_linuxheaders
    check_installed_dkms
    install_pip2
    install_pip3
    fix_pip2_pip3
    install_pipx
    install_pip2_modules
    install_pip3_modules
    install_golang
    eval apt -y remove kali-undercover >/dev/null 2>&1
    is_installed "libu2f-udev virt-what neo4j dkms build-essential autogen automake python3-setuptools python$pyver-dev libguestfs-tools cifs-utils dbus-x11"
    fix_gedit
    fix_root_connectionrefused
    fix_htop
    fix_nmap
    fix_rockyou
    fix_theharvester
    silence_pcbeep
    disable_power_checkde
    fix_spike
    fix_set
    fix_amass
    fix_httprobe
    fix_assetfinder
    fix_chrome
    fix_gowitness
    fix_mitm6
    fix_linwinpeas
    fix_neo4j
    fix_bloodhound
    fix_proxychains
    fix_sshuttle
    fix_chisel
    fix_cme
    fix_netexec
    fix_ssh_widecompat
    fix_waybackurls
    fix_dockercompose
    fix_ghidra
    fix_locate
    fix_seclists
    fix_flameshot
    install_plumhound
    install_enumforlinux_ng
    install_enumforlinux
    install_sqlmap
    install_hydra
    install_wfuzz
    install_ffuf
    install_gobuster
    install_vscode
    }


fix_all() {
    make_rootgreatagain 
    fix_missing
    apt_autoremove 
    apt_fixbroken
    virt_what
    check_vm
    }


fix_dockercompose() {
    DOCKERCOMPOSE_RELEASE_URL="https://github.com/docker/compose/releases/"
    DOCKERCOMPOSE_RELEASE_HTML=$(curl -s "$DOCKERCOMPOSE_RELEASE_URL")
    DOCKERCOMPOSE_LATEST_VERSION=$(echo "$DOCKERCOMPOSE_RELEASE_HTML" | grep -oP 'href="/docker/compose/releases/tag/v\K[0-9.]+(?=")' | head -n 1)
    if [ -z "$DOCKERCOMPOSE_LATEST_VERSION" ]; then
      echo -e "\n  ${redexclaim} Error: Unable to find the latest Docker Compose version from Github"
      exit 1
    fi
    DOCKERCOMPOSE_DOWNLOAD_URL="https://github.com/docker/compose/releases/download/v$DOCKERCOMPOSE_LATEST_VERSION/docker-compose-$(uname -s)-$(uname -m)"
    
    if command -v docker-compose &> /dev/null;
      then
        SYSTEM_DOCKERCOMPOSE_VER=$(docker-compose --version | awk '{print $4}' | tr -d "v")
        EXIT_STATUS="$?"
      else
        EXIT_STATUS="127"
    fi

    case ${EXIT_STATUS} in
        0)
          # exit code 0, docker compose is installed, compare versions and upgrade if newer is available
          echo -e "\n\n  ${greenplus} Local $(whereis docker-compose) found. Comparing versions..."
          if [[ "$DOCKERCOMPOSE_LATEST_VERSION" > "$SYSTEM_DOCKERCOMPOSE_VER" ]]; then
              echo -e "${spaces}${greenminus} Installed Docker Compose Ver = $SYSTEM_DOCKERCOMPOSE_VER"
              echo -e "${spaces}${greenminus} Github Latest Docker Compose = $DOCKERCOMPOSE_LATEST_VERSION"
              echo -e "${spaces}${greenplus} Installing latest DockerCompose \n"
             
              is_installed "build-essential python3-dev docker.io python3-setuptools python3-wheel python3-wheel-common cython3 python3-pip python3-pip-whl"
              echo -e "${spaces}${greenplus} Latest Docker Compose version: $DOCKERCOMPOSE_LATEST_VERSION"
              echo -e "${spaces}${greenplus} Downloading Docker Compose: $DOCKERCOMPOSE_DOWNLOAD_URL to /usr/local/bin/docker-compose"
              curl -L "$DOCKERCOMPOSE_DOWNLOAD_URL" -o /usr/local/bin/docker-compose
              echo -e "${spaces}${greenplus} Making /usr/local/bin/docker-compose executable"
              chmod +x /usr/local/bin/docker-compose
              echo -e "${spaces}${greenplus} Docker Compose installed successfully $(docker-compose --version | awk {'print $4'})"
          else
              echo -e "${spaces}${greenminus} Installed Docker Compose Ver = $SYSTEM_DOCKERCOMPOSE_VER"
              echo -e "${spaces}${greenminus} Github Latest Docker Compose = $DOCKERCOMPOSE_LATEST_VERSION"
              echo -e "${spaces}${greenplus} Versions Match, exiting"
          fi
          ;;
      127)
            # exit code 127 docker-compose is not found, install from
            echo -e "\n\n  ${redexclaim} Docker Compose command not found, installing..."
            
            is_installed "build-essential python3-dev docker.io python3-setuptools python3-wheel python3-wheel-common cython3 python3-pip python3-pip-whl"
            echo -e "\n  ${greenplus} Latest Docker Compose version: $DOCKERCOMPOSE_LATEST_VERSION"
            echo -e "${spaces}${greenplus} Downloading Docker Compose: $DOCKERCOMPOSE_DOWNLOAD_URL to /usr/local/bin/docker-compose\n"
            curl -L "$DOCKERCOMPOSE_DOWNLOAD_URL" -o /usr/local/bin/docker-compose
            echo -e "${spaces}${greenplus} Making /usr/local/bin/docker-compose executable"
            chmod +x /usr/local/bin/docker-compose
            echo -e "${spaces}${greenplus} Docker Compose installed successfully $(docker-compose --version | awk {'print $4'})"
            ;;
        *)
            # catch all other exit codes
            echo -e "\n  ${redexclaim} Unknown error code ${EXIT_STATUS}"
            ;;
    esac
    }


fix_kali_lightdm_theme_and_background () {
    APP="sed"
    FUNCTYPE="update lightdm-gtk-greeter.conf"
    sed s:"Kali-Light":"Kali-Dark":g -i /etc/lightdm/lightdm-gtk-greeter.conf
    EXIT_STATUS="$?"
    check_exit_status ${APP} ${FUNCTYPE} ${EXIT_STATUS}
    clean_vars
    }


install_rustup() {
    echo -e "\n  ${greenminus} Installing Rust"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -sSf | sh -s -- -y
    APP="rustup"
    FUNCTYPE="install"
    sudo -i -u $finduser curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -sSf | sh -s -- -y
    EXIT_STATUS="$?"
    check_exit_status ${APP} ${FUNCTYPE} ${EXIT_STATUS}
    clean_vars
    }


install_cargo() {
    is_installed "cargo libssl-dev"
    }


fix_libwacom() {
    is_installed "libwacom-common"
    }


fix_neo4j() {
    is_installed "neo4j"
    }


fix_bloodhound() {
    is_installed "bloodhound"
    }


fix_proxychains() {
    is_installed "proxychains"
    }


fix_sshuttle() { 
    is_installed "sshuttle" 
    }


fix_chisel() {
    is_installed "chisel"
    }


fix_cme() {
    is_installed "crackmapexec"
     }    


fix_nxc_symlinks() { 
    findrealuser=$(logname) 
    getshell=$(echo $SHELL | cut -d "/" -f4)

    nxcbin_path="$HOME/.local/share/pipx/venvs/netexec/bin/"
    localbin_path="$HOME/.local/bin/"

    nxc_symlink_array=( 'netexec' 'NetExec' 'nxc' 'nxcdb' )
    for nxc_symlink_array_file in ${cme_symlink_array[@]}; do
      echo $cme_symlink_array_file > /tmp/nxcsymlink.tmp
      # sanity check 
      # runuser $findrealuser $getshell -c 'echo -e "\n $HOME/.local/share/pipx/venvs/crackmapexec/bin/$(cat /tmp/cmesymlink.tmp) $HOME/.local/bin/$(cat /tmp/cmesymlink.tmp)"'
      echo -e "${spaces}${greenplus} Creating symlink for user $findrealuser to ~/.local/bin/$nxc_symlink_array_file  " 
      runuser $findrealuser $getshell -c 'symlink_file=$(cat /tmp/nxcsymlink.tmp); ln -sf $HOME/.local/share/pipx/venvs/netexec/bin/$symlink_file $HOME/.local/bin/$symlink_file'
    done

    rm -f /tmp/nxcsymlink.tmp
    }


fix_netexec() {
    findrealuser=$(logname)
    echo -e "\n  ${greenplus} Installing Netexec (nxc)" 

    # root installation 
    if [[ $findrealuser == "root" ]];
     then
       echo -e "${spaces}${greenplus} Starting ${findrealuser} user installation"
       is_installed "pipx python3-venv python3-poetry"
       pipx install git+https://github.com/Pennyw0rth/NetExec --force
       getshell=$(echo $SHELL | cut -d "/" -f4)
       check_for_local_bin_path=$(cat "$HOME/.$getshell"rc | grep -i "PATH=" | grep -i "\$HOME\/\.local\/bin" -c)

       if [[ $check_for_local_bin_path -eq 0 ]];
        then
         echo "export PATH=\$HOME/.local/bin:\$PATH" >> $HOME/.$getshell"rc"
        else 
         echo "\n  ${redexclaim} Path already exists for user ${findrealuser}"
       fi
       fix_nxc_symlinks 
      fi

     # user installation 
     if [[ $findrealuser != "root" ]];
      then
        echo -e "${spaces}${greenplus} Starting $findrealuser user installation"
        is_installed "pipx python3-venv python3-poetry"

        sudo -i -u $findrealuser sh -c 'pipx install git+https://github.com/Pennyw0rth/NetExec --force'
        getshell=$(echo $SHELL | cut -d "/" -f4)
        subshell=$(runuser $findrealuser $getshell -c 'echo $SHELL | cut -d "/" -f4')
        checkforlocalbinpath=$(cat /home/$findrealuser/.$subshell"rc" | grep -i PATH= | grep -i "\$HOME\/\.local\/bin:\$PATH" -c)
        
        if [[ $checkforlocalbinpath -eq 0 ]]
          then
            runuser $findrealuser $getshell -c 'subshell=$(echo $SHELL | cut -d "/" -f4); echo "export PATH=\$HOME/.local/bin:\$PATH" >> $HOME/.$subshell"rc"'
            runuser $findrealuser $getshell -c 'subshell=$(echo $SHELL | cut -d "/" -f4); source $HOME/.$subshell"rc"' 
          else 
            echo -e "\n $redexclaim Path already exists "
        fi
        
        fix_nxc_symlinks 
      fi
    }


fix_assetfinder() {
    is_installed "assetfinder"
    }


fix_httprobe() {
    is_installed "httprobe"
    }


fix_amass() {
    is_installed "amass"
    }


fix_mitm6() {
    is_installed "mitm6"
    }


fix_gedit() {
    is_installed "gedit"
    }


fix_set() {
    echo -e "\n  ${greenplus} Installing Social Engineering Toolkit" 
    is_installed "libssl-dev set gcc-mingw-w64-x86-64-win32"
    }


fix_ssh_widecompat() { 
    echo -e "\n  ${greenplus} Setting SSH for wide compatibility"
    eval cp -f /usr/share/kali-defaults/etc/ssh/ssh_config.d/kali-wide-compat.conf /etc/ssh/ssh_config.d/kali-wide-compat.conf
    echo -e "${spaces}${greenplus} Restarting SSH service for wide compatibility"
    APP="systemctl"
    FUNCTYPE="restart ssh"
    eval systemctl restart ssh
    EXIT_STATUS="$?"
    check_exit_status ${APP} ${FUNCTYPE} ${EXIT_STATUS}
    clean_vars
    }


fix_waybackurls() {
    echo -e "\n  ${greenplus} Installing waybackrust \n"
    WAYBACKRUST_URL="https://github.com/Neolex-Security/WaybackRust/releases/download/v0.2.12/waybackrust-x86_64-unknown-linux-gnu.tar.gz"
    WAYBACKRUST_DEST="/tmp/waybackrust-x86_64-unknown-linux-gnu.tar.gz"

    if [ ! -f /usr/bin/waybackrust ] 
      then 
        APP="wget"
        FUNCTYPE="download"
        wget --quiet "$WAYBACKRUST_URL" -O $WAYBACKRUST_DEST
        EXIT_STATUS="$?"
        check_exit_status ${APP} ${FUNCTYPE} ${EXIT_STATUS}
        clean_vars
    fi

    if [ -f $WAYBACKRUST_DEST ]
      then
        APP="tar"
        FUNCTYPE="extract"
        tar xvfz $WAYBACKRUST_DEST -C /usr/bin >/dev/null 2>&1
        EXIT_STATUS="$?"
        check_exit_status ${APP} ${FUNCTYPE} ${EXIT_STATUS}
        clean_vars
    fi

    if [ -f /usr/bin/waybackrust ] 
      then
        echo -e "${spaces}${greenplus} /usr/bin/waybackrust found, making executable"
        chmod +x /usr/bin/waybackrust
        echo -e "${spaces}${greenplus} $(waybackrust --version) installed"
      else 
        echo -e "${spaces}${greenplus} /usr/bin/waybackrust not found" 
    fi 
    }


fix_linwinpeas() {
    # get all the peas!!!
    current_build=$(curl -s https://github.com/peass-ng/PEASS-ng/releases | grep -i "refs/heads/master" -m 1 | awk '{ print $5 }' | cut -d "<" -f1)
    releases_url="https://github.com/peass-ng/PEASS-ng/releases/download/$current_build"
	  dest_linpeas="/opt/linpeas"
	  dest_winpeas="/opt/winpeas"
    
    # linpeas to /opt/linpeas
	  echo -e "\n  ${greenplus} Downloading all the linpeas from build $current_build"
    [ ! -d $dest_linpeas ] && mkdir $dest_linpeas || echo > /dev/null 
    
    linpeas_arr=('linpeas.sh' 'linpeas_darwin_amd64' 'linpeas_darwin_arm64' 'linpeas_fat.sh' 'linpeas_linux_386' 'linpeas_linux_amd64' 'linpeas_linux_arm')
      for linpeas_file in ${linpeas_arr[@]}; do
        clean_vars
        APP="download"
        FUNCTYPE=$(echo ${linpeas_file})
        echo -e "${spaces}${greenplus} Downloading $linpeas_file to $dest_linpeas/$linpeas_file"
        wget -q $releases_url/$linpeas_file -O $dest_linpeas/$linpeas_file
        EXIT_STATUS="$?"
        check_exit_status ${APP} ${FUNCTYPE} ${EXIT_STATUS}
        clean_vars
        chmod +x $dest_linpeas/$linpeas_file 
     done

    # winpeas to /opt/winpeas
	  echo -e "\n  ${greenplus} Downloading all the winpeas from build $current_build"
    [ ! -d $dest_winpeas ] && mkdir $dest_winpeas || echo > /dev/null 
    
    winpeas_arr=('winPEAS.bat' 'winPEASany.exe' 'winPEASany_ofs.exe' 'winPEASx64_ofs.exe' 'winPEASx86.exe' 'winPEASx86_ofs.exe')
      for winpeas_file in ${winpeas_arr[@]}; do
        clean_vars
        APP="download"
        FUNCTYPE=$(echo ${winpeas_file})
        echo -e "${spaces}${greenplus} Downloading $winpeas_file to $dest_winpeas/$winpeas_file"
        wget -q $releases_url/$winpeas_file -O $dest_winpeas/$winpeas_file
        EXIT_STATUS="$?"
        check_exit_status ${APP} ${FUNCTYPE} ${EXIT_STATUS}
        clean_vars
        chmod +x $dest_winpeas/$winpeas_file 
     done
    }


fix_chrome() {
    echo -e "\n  ${greenplus} Checking if google-chrome is installed "
    if [[ "$arch" == "arm64" ]];
      then 
        echo -e "${spaces}${redexclaim} Google-Chrome is not available for this platform $arch -- skipping"
      elif [[ "$arch" == "amd64" ]];
        then
          if [[ -f /usr/bin/google-chrome ]];
            then
              echo -e "${spaces}${greenminus} google-chrome already installed, skipping"
            else
              clean_vars
              APP="google-chrome"
              FUNCTYPE="download"
              echo -e "\n  ${greenplus} Gowitness dependancy google-chrome for $arch \n"
              eval wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb -O /tmp/google-chrome-stable_current_amd64.deb
              EXIT_STATUS="$?"
              check_exit_status ${APP} ${FUNCTYPE} ${EXIT_STATUS}
              clean_vars

              is_installed "libu2f-dev"

              echo -e "${spaces}${greenplus} Installing Google-Chrome"
              APP="dpkg"
              FUNCTYPE="install google-chrome-stable_current_amd64.deb" 
              eval dpkg -i /tmp/google-chrome-stable_current_amd64.deb
              EXIT_STATUS="$?"
              check_exit_status ${APP} ${FUNCTYPE} ${EXIT_STATUS}
              clean_vars
              rm -f /tmp/google-chrome-stable_current_amd64.deb
          fi
    fi 
    }


fix_hushlogin() {
    echo -e "\n  ${greenplus} Checking for .hushlogin"
    if [ $finduser = "root" ]
     then
      if [ -f /root/.hushlogin ]
       then
        echo -e "${spaces}${greenminus} /$finduser/.hushlogin exists - skipping"
      else
        echo -e "${spaces}${greenplus} Creating file /$finduser/.hushlogin"
        touch /$finduser/.hushlogin
      fi
    else
      if [ -f /home/$finduser/.hushlogin ]
       then
        echo -e "${spaces}${greenminus} /home/$finduser/.hushlogin exists - skipping"
      else
        echo -e "${spaces}${greenplus} Creating file /home/$finduser/.hushlogin"
        touch /home/$finduser/.hushlogin
      fi
    fi
    }


disable_power_gnome() {
    # CODE CONTRIBUTION : pswalia2u - https://github.com/pswalia2u
    fix_hushlogin
    echo -e "\n  ${greenplus} Gnome detected - Disabling Power Savings"
    # ac power
    sudo -i -u $finduser gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-type nothing      # Disables automatic suspend on charging)
     echo -e "  ${greenplus} org.gnome.settings-daemon.plugins.power sleep-inactive-ac-type nothing"
    sudo -i -u $finduser gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-timeout 0         # Disables Inactive AC Timeout
     echo -e "  ${greenplus} org.gnome.settings-daemon.plugins.power sleep-inactive-ac-timeout 0"
    # battery power
    sudo -i -u $finduser gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-battery-type nothing # Disables automatic suspend on battery)
     echo -e "  ${greenplus} org.gnome.settings-daemon.plugins.power sleep-inactive-battery-type nothing"
    sudo -i -u $finduser gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-battery-timeout 0    # Disables Inactive Battery Timeout
     echo -e "  ${greenplus} org.gnome.settings-daemon.plugins.power sleep-inactive-battery-timeout 0"
    # power button
    sudo -i -u $finduser gsettings set org.gnome.settings-daemon.plugins.power power-button-action nothing         # Power button does nothing
     echo -e "  ${greenplus} org.gnome.settings-daemon.plugins.power power-button-action nothing"
    # idle brightness
    sudo -i -u $finduser gsettings set org.gnome.settings-daemon.plugins.power idle-brightness 0                   # Disables Idle Brightness
     echo -e "  ${greenplus} org.gnome.settings-daemon.plugins.power idle-brightness 0"
    # screensaver activation
    sudo -i -u $finduser gsettings set org.gnome.desktop.session idle-delay 0                                      # Disables Idle Activation of screensaver
     echo -e "  ${greenplus} org.gnome.desktop.session idle-delay 0"
    # screensaver lock
    sudo -i -u $finduser gsettings set org.gnome.desktop.screensaver lock-enabled false                            # Disables Locking
     echo -e "  ${greenplus} org.gnome.desktop.screensaver lock-enabled false\n"
    }


disable_power_xfce() {
    if [ $finduser = "root" ]
     then
      echo -e "\n  ${greenplus} XFCE Detected - disabling xfce power management"
      OUTPUT_FILE=/root/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-power-manager.xml
      echo '<?xml version="1.0" encoding="UTF-8"?>' > $OUTPUT_FILE
      echo '' >> $OUTPUT_FILE
      echo '<channel name="xfce4-power-manager" version="1.0">' >> $OUTPUT_FILE
      echo '  <property name="xfce4-power-manager" type="empty">' >> $OUTPUT_FILE
      echo '    <property name="power-button-action" type="empty"/>' >> $OUTPUT_FILE
      echo '    <property name="show-panel-label" type="empty"/>' >> $OUTPUT_FILE
      echo '    <property name="show-tray-icon" type="bool" value="false"/>' >> $OUTPUT_FILE
      echo '    <property name="lock-screen-suspend-hibernate" type="bool" value="false"/>' >> $OUTPUT_FILE
      echo '    <property name="logind-handle-lid-switch" type="bool" value="false"/>' >> $OUTPUT_FILE
      echo '    <property name="blank-on-ac" type="int" value="0"/>' >> $OUTPUT_FILE
      echo '    <property name="dpms-on-ac-sleep" type="uint" value="0"/>' >> $OUTPUT_FILE
      echo '    <property name="dpms-on-ac-off" type="uint" value="0"/>' >> $OUTPUT_FILE
      echo '  <property name="dpms-enabled" type="bool" value="false"/>' >> $OUTPUT_FILE
      echo '  </property>' >> $OUTPUT_FILE
      echo '</channel>' >> $OUTPUT_FILE
      echo -e "${spaces}${greenplus} XFCE power management disabled for user: $finduser"
    else
      echo -e "\n  ${greenplus} XFCE Detected - disabling xfce power management"
      OUTPUT_FILE=/home/$finduser/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-power-manager.xml
      echo '<?xml version="1.0" encoding="UTF-8"?>' > $OUTPUT_FILE
      echo '' >> $OUTPUT_FILE
      echo '<channel name="xfce4-power-manager" version="1.0">' >> $OUTPUT_FILE
      echo '  <property name="xfce4-power-manager" type="empty">' >> $OUTPUT_FILE
      echo '    <property name="power-button-action" type="empty"/>' >> $OUTPUT_FILE
      echo '    <property name="show-panel-label" type="empty"/>' >> $OUTPUT_FILE
      echo '    <property name="show-tray-icon" type="bool" value="false"/>' >> $OUTPUT_FILE
      echo '    <property name="lock-screen-suspend-hibernate" type="bool" value="false"/>' >> $OUTPUT_FILE
      echo '    <property name="logind-handle-lid-switch" type="bool" value="false"/>' >> $OUTPUT_FILE
      echo '    <property name="blank-on-ac" type="int" value="0"/>' >> $OUTPUT_FILE
      echo '    <property name="dpms-on-ac-sleep" type="uint" value="0"/>' >> $OUTPUT_FILE
      echo '    <property name="dpms-on-ac-off" type="uint" value="0"/>' >> $OUTPUT_FILE
      echo '  <property name="dpms-enabled" type="bool" value="false"/>' >> $OUTPUT_FILE
      echo '  </property>' >> $OUTPUT_FILE
      echo '</channel>' >> $OUTPUT_FILE
      chown $finduser:$finduser /home/$finduser/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-power-manager.xml
      echo -e "${spaces}${greenplus} XFCE power management disabled for user: $finduser"
    fi
    }

# disable_power_kde() {
#    # need to work up a kde power management solution before implementing
# }

disable_power_checkde() {
    detect_xfce=$(ps -e | grep -c -E '^.* xfce4-session$')
    detect_gnome=$(ps -e | grep -c -E '^.* gnome-session-*')
    #detect_kde=$(ps -e | grep -c -E '^.* kded4$')
    [ $detect_gnome -ne 0 ] && detected_env="GNOME"
    [ $detect_xfce -ne 0 ] && detected_env="XFCE"
    # [ $detect_kde -ne 0 ] && detected_env="KDE"
    echo -e "\n  ${greenplus} Detected Environment: $detected_env"
    [ $detected_env = "GNOME" ] && disable_power_gnome
    [ $detected_env = "XFCE" ] && disable_power_xfce
    [ $detected_env = "" ] && echo -e "\n  ${redexclaim} Unable to determine desktop environment"
    # [ $detected_env = "KDE" ] && disable_power_kde
    }

silence_pcbeep() {
    echo -e "blacklist pcspkr" > /etc/modprobe.d/nobeep.conf
    echo -e "\n  ${greenplus} Terminal Beep Silenced! /etc/modprobe.d/nobeep.conf \n"
    }


fix_spike() {
    is_spike_hold=$(apt-mark showhold | grep -i -c "spike")

    if [[ $is_spike_hold -eq 1 ]]
      then 
        apt-mark unhold spike
    fi

    is_installed_remove "spike"
   
    APP="wget"
    FUNCTYPE="download spike_2.9-1kali6_${arch}.deb"
    eval wget https://old.kali.org/kali/pool/main/s/spike/spike_2.9-1kali6_$arch.deb -O /tmp/spike_2.9-1kali6_$arch.deb
    EXIT_STATUS="$?"
    check_exit_status ${APP} ${FUNCTYPE} ${EXIT_STATUS}
    clean_vars
    
    APP="dpkg"
    FUNCTYPE="install"
    echo -e "\n  ${greenplus} installing spike 2.9 for $arch ... \n"
    eval dpkg -i /tmp/spike_2.9-1kali6_$arch.deb
    EXIT_STATUS="$?"
    check_exit_status ${APP} ${FUNCTYPE} ${EXIT_STATUS}
    clean_vars

    echo -e "${spaces}${greenplus} spike 2.9 installed \n"
    rm -f /tmp/spike_2.9-1kali6_$arch.deb 
    eval apt-mark hold spike >/dev/null 2>&1
    echo -e "${spaces}${greenplus} apt hold placed on spike package"
    }


fix_liblibc() {
    if [[ "$arch" == "amd64" ]] 
      then 
        if [[ ! -f /usr/lib/x86_64-linux-gnu/liblibc.a ]]
          then
            ln -sf /usr/lib/x86_64-linux-gnu/libc.a /usr/lib/x86_64-linux-gnu/liblibc.a 
            echo -e "\n  ${greenplus} Fixing $arch liblibc.a symlink /usr/lib/x86_64-linux-gnu/liblibc.a"
        fi 
    fi

    if [[ "$arch" == "arm64" ]]
      then 
        if [[ ! -f /usr/lib/aarch64-linux-gnu/liblibc.a ]]
          then 
          ln -sf /usr/lib/aarch64-linux-gnu/libc.a /usr/lib/aarch64-linux-gnu/liblibc.a 
          echo -e "\n  ${greenplus} Fixing $arch liblibc.a symlink.."
        fi
    fi
    }


fix_gowitness() {
    check_gowitness=$(apt-cache policy gowitness |  grep -i -c "100 \/var\/lib\/dpkg\/status")
    if [[ $check_gowitness -eq 0 ]]
      then
        REPO_URL="https://github.com/sensepost/gowitness/tags"
        LATEST_VERSION=$(curl -s "$REPO_URL" | grep -oPm1 '/sensepost/gowitness/releases/tag/\K[\d.]+')
        echo -e "\n  ${greenplus} Installing gowitness $LATEST_VERSION for ${arch} from github"
        
        [ -f /usr/bin/gowitness ] && rm -f /usr/bin/gowitness

        APP="wget"
        FUNCTYPE="download gowitness-${LATEST_VERSION}"
        echo -e "${spaces}${greenplus} Downloading gowitness ${arch} binary...\n"
        eval wget -q https://github.com/sensepost/gowitness/releases/download/${LATEST_VERSION}/gowitness-${LATEST_VERSION}-linux-$arch -O /usr/bin/gowitness
        EXIT_STATUS="$?"
        check_exit_status ${APP} ${FUNCTYPE} ${EXIT_STATUS}
        clean_vars
        chmod +x /usr/bin/gowitness
        rm -f /tmp/releases.gowitness > /dev/null
      else
        echo -e "${spaces}${greenplus} Uninstalling Gowitness"
        is_installed_remove "gowitness"
        fix_gowitness
    fi
    }


fix_root_connectionrefused() {
    echo -e "\n  ${greenplus} Adding root to xhost for $finduser display"
    eval sudo -i -u $finduser xhost +SI:localuser:root >/dev/null 2>&1
    eval xhost +SI:localuser:root >/dev/null 2>&1
    echo -e "${spaces}${greenplus} root added to xhost"
    }


fix_rockyou() {
    ROCKYOU_GZIP="/usr/share/wordlists/rockyou.txt.gz"
    if [ -f ${ROCKYOU_GZIP} ];
      then
        APP="gzip"
        FUNCTYPE="deflate"
        cd /usr/share/wordlists
        echo -e "${spaces}${greenplus} Decompressing ${ROCKYOU_GZIP}"
        gzip -dqf ${ROCKYOU_GZIP}
        EXIT_STATUS="$?"
        check_exit_status ${APP} ${FUNCTYPE} ${EXIT_STATUS}
        clean_vars
      else 
        echo -e "${spaces}${greenminus} rockyou.txt already decompressed, skipping"
    fi 
    }


fix_locate() {
    is_installed "locate"
    }


fix_htop() {
    is_installed "htop"
    }


fix_seclists() {
    is_installed "seclists"
    }


fix_flameshot() {
    is_installed "flameshot"
    }


fix_theharvester() {
    is_installed "theharvester"
    }


install_golang() {
    is_installed "golang"
    }


fix_go_path() {
    echo -e "\n  ${greenplus} Gopath Setup"
    findrealuser=$(logname)

    if [ "$findrealuser" == "root" ]
     then
      check_root_zshrc=$(cat /root/.zshrc | grep -c GOPATH)
      [ -d /$findrealuser/go ] && echo -e "\n  ${greenminus} go directories already exist in /$findrealuser" || echo -e "\n  ${greenplus} creating directories /$findrealuser/go /$findrealuser/go/bin /$findrealuser/go/src"; mkdir -p /$findrealuser/go/{bin,src}
       if [ $check_root_zshrc -ne 0 ]
         then
          echo -e "${spaces}${redminus} GOPATH Variables for $findrealuser already exist in /$findrealuser/.zshrc - Not changing"
         else
          echo -e "${spaces}${greenplus} Adding GOPATH Variables to /root/.zshrc"
          eval echo -e 'export GOPATH=\$HOME/go' >> /root/.zshrc
          eval echo -e 'export PATH=\$PATH:\$GOPATH/bin' >> /root/.zshrc
       fi
      check_root_bashrc=$(cat /root/.bashrc | grep -c GOPATH)
       if [ $check_root_bashrc -ne 0 ]
        then
         echo -e "${spaces}${redminus} GOPATH Variables for $findrealuser already exist in /$findrealuser/.bashrc - Not changing"
        else
         echo -e "${spaces}${greenplus} Adding GOPATH Variables to /root/.bashrc"
         eval echo -e 'export GOPATH=\$HOME/go' >> /root/.bashrc
         eval echo -e 'export PATH=\$PATH:\$GOPATH/bin' >> /root/.bashrc
       fi
     else
      check_user_zshrc=$(cat /home/$findrealuser/.zshrc | grep -c GOPATH)
       [ -d /home/$findrealuser/go ] && echo -e "\n  ${greenminus} go directories already exist in /home/$finduser" || echo -e "\n  ${greenplus} creating directories /home/$findrealuser/go /home/$findrealuser/go/bin /home/$findrealuser/go/src"; mkdir -p /home/$findrealuser/go/{bin,src}; chown -R $findrealuser:$findrealuser /home/$findrealuser/go
       if [ $check_user_zshrc -ne 0 ]
        then
         echo -e "${spaces}${redminus} GOPATH Variables for user $findrealuser already exist in /home/$findrealuser/.zshrc  - Not Changing"
        else
         echo -e "${spaces}${greenplus} Adding GOPATH Variables to /home/$findrealuser/.zshrc"
         eval echo -e 'export GOPATH=\$HOME/go' >> /home/$findrealuser/.zshrc
         eval echo -e 'export PATH=\$PATH:\$GOPATH/bin' >> /home/$findrealuser/.zshrc
       fi
      check_user_bashrc=$(cat /home/$findrealuser/.bashrc | grep -c GOPATH)
       if [ $check_user_bashrc -ne 0 ]
        then
         echo -e "${spaces}${redminus} GOPATH Variables for user $findrealuser already exist in /home/$findrealuser/.bashrc - Not Changing"
        else
         echo -e "${spaces}${greenplus} Adding GOPATH Variables to /home/$findrealuser/.bashrc"
         eval echo -e 'export GOPATH=\$HOME/go' >> /home/$findrealuser/.bashrc
         eval echo -e 'export PATH=\$PATH:\$GOPATH/bin' >> /home/$findrealuser/.bashrc
       fi
    fi
    }


fix_nmap() {
    # clam-av.nse
    echo -e "\n  ${greenplus} Updating clamav-exec.nse"
    rm -f /usr/share/nmap/scripts/clamav-exec.nse
    echo -e "${spaces}${redminus} /usr/share/nmap/scripts/clamav-exec.nse removed "
    eval wget https://raw.githubusercontent.com/nmap/nmap/master/scripts/clamav-exec.nse -O /usr/share/nmap/scripts/clamav-exec.nse $silent
    echo -e "${spaces}${greenplus} /usr/share/nmap/scripts/clamav-exec.nse replaced with working version"
    
    # http-shellshock.nse
    SHELLSHOCK_FIXED_NSE="./addons/fixed-http-shellshock.nse"
    echo -e "\n  ${greenplus} Updating http-shellshock.nse"
    if [ -f ${SHELLSHOCK_FIXED_NSE} ]
    then 
      cp -f ${SHELLSHOCK_FIXED_NSE} /usr/share/nmap/scripts/http-shellshock.nse $silent
    else 
      eval wget https://raw.githubusercontent.com/Dewalt-arch/pimpmykali/master/fixed-http-shellshock.nse -O /usr/share/nmap/scripts/http-shellshock.nse $silent
    fi
    }


fix_smbconf() {
    check_smb_min=$(cat /etc/samba/smb.conf | grep -c -i "client min protocol = LANMAN1")

    if [ $check_smb_min -eq 1 ]
      then
        echo -e "\n  ${greenplus} Checking /etc/samba/smb.conf "
        echo -e "${spaces}${redminus} client min protocol is already set, skipping"
      else
        sed 's/^   client min protocol =.*/client min protocol = LANMAN1/' -i /etc/samba/smb.conf
        echo -e "${spaces}${greenplus} /etc/samba/smb.conf updated"
        echo -e "${spaces}${greenplus} added : client min protocol = LANMAN1"
    fi
    }


fix_grub() {
    echo -e "\n  ${greenplus} Checking /etc/defult/grub" 
    check_grub=$(cat /etc/default/grub | grep -i -c "mitigations=off" )

    if [ $check_grub -eq 1 ]
      then
        echo -e "${spaces}${greenplus} Found mitigations=off, skipping"
      else
        sed 's/GRUB_CMDLINE_LINUX_DEFAULT="quiet"/GRUB_CMDLINE_LINUX_DEFAULT="quiet mitigations=off"/' -i /etc/default/grub
        update-grub
        echo -e "${spaces}${greenplus} Added mitigations=off to GRUB_CMDLINE_LINUX_DEFAULT"
        echo -e "${spaces}${redexclaim} Reboot for changes to take effect \n"
    fi
    }


fix_bad_apt_hash() {
    mkdir -p /etc/gcrypt
    echo "all" > /etc/gcrypt/hwf.deny
    }


install_sublime() {
    # code fix provided by aashiksamuel
    echo -e "\n  ${greenplus} Installing sublime"
    is_installed "gpg apt-transport-https"
    eval wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | gpg --no-default-keyring --keyring ./temp-keyring.gpg --import
    eval gpg --no-default-keyring --keyring ./temp-keyring.gpg --export --output sublime-text.gpg
    eval rm temp-keyring.gpg temp-keyring.gpg~
    eval mkdir -p /usr/local/share/keyrings
    eval mv ./sublime-text.gpg /usr/local/share/keyrings

    eval echo "deb [signed-by=/usr/local/share/keyrings/sublime-text.gpg] https://download.sublimetext.com/ apt/stable/" > /etc/apt/sources.list.d/sublime-text.list
    apt_update
    is_installed "sublime-text"
    }


fix_sources() {
    fix_bad_apt_hash

    check_space=$(cat /etc/apt/sources.list | grep -c "# deb-src http://.*/kali kali-rolling.*")
    check_nospace=$(cat /etc/apt/sources.list | grep -c "#deb-src http://.*/kali kali-rolling.*")
    get_current_mirror=$(cat /etc/apt/sources.list | grep "deb-src http://.*/kali kali-rolling.*" | cut -d "/" -f3)
    
    if [[ $check_space -eq 0 && $check_nospace -eq 0 ]]
      then
        echo -e "\n  ${greenminus} # deb-src or #deb-sec not found - skipping"
        force_apt_update=0
      elif [ $check_space -eq 1 ];
        then
          echo -e "\n  ${greenplus} # deb-src with space found in sources.list uncommenting and enabling deb-src"
          sed 's/\# deb-src http\:\/\/.*\/kali kali-rolling.*/\deb-src http\:\/\/'$get_current_mirror'\/kali kali-rolling main contrib non\-free''/' -i /etc/apt/sources.list
          echo -e "${spaces}${greenplus} new /etc/apt/sources.list written with deb-src enabled"
          force_apt_update=1
      elif [ $check_nospace -eq 1 ]
        then
          echo -e "\n  ${greenplus} #deb-src without space found in sources.list uncommenting and enabling deb-src"
          sed 's/\#deb-src http\:\/\/.*\/kali kali-rolling.*/\deb-src http\:\/\/'$get_current_mirror'\/kali kali-rolling main contrib non\-free''/' -i /etc/apt/sources.list
          echo -e "${spaces}${greenplus} new /etc/apt/sources.list written with deb-src enabled"
          force_apt_update=1
    fi
    sed -i 's/non-free$/non-free non-free-firmware/' /etc/apt/sources.list

    if [[ $force_apt_update -eq 1 ]]
      then
        apt_update
      fi
    }


fix_sead_warning() {
    case $arch in
      amd64)
        echo -e "\n ${greenplus} Architecture is amd64, continuing..."
        ;;
      arm64)
        echo -e "\n ${redexclaim} Unsupported architecture: $arch, exiting"
        echo -e "\n      Please use Impacket v0.12 or newer"
        exit 1
        ;;
    esac

    if [ $SPEEDRUN -eq 1 ]
    then 
        fix_sead_run 
    else 
        echo -e "

 "$bold$redexclaim$red" WARNING "$redexclaim$bold$red"  PIMPMYKALI IMPACKET REMOVAL FUNCTION  "$redexclaim$bold$red" WARNING "$redexclaim$white$norm"

                 *** READ FULLY BEFORE PRESSING ANY KEY ***

   "$red"DISCLAIMER:"$white" Warning: Last Resort Impacket Removal
   This function is intended as a last resort to remove impacket-0.9.19 and install a clean version. 
   
   This function will attempt to remove impacket and related files from common directories, 
   but may not cover every scenario.

   This WILL RECURSIVLY DELETE ANY DIR NAMED impacket* from the following:
    /opt  /usr/bin  /usr/local/lib  /usr/lib  /home/$finduser/.local/bin
    /home/$finduser/.local/lib  /root/.local/lib  /root/.local/bin

   AND ANY related .py and .pyc files from impacket in the following:
    /usr/bin  /local/local/bin  /root/.local/bin  /home/$finduser/.local/bin

   Answering only Y to the following prompt will perform the above actions,
   pressing ANY OTHER KEY WILL EXIT

   "
    read -n1 -p " Press Y to execute or any other key to exit: " fixsead_userinput
    case $fixsead_userinput in
      y|Y) fix_sead_run;;
        *) exit;;
    esac
    fi
    }


fix_sead_run() {
    SEAD=$(find /opt /usr/bin /usr/local/lib /usr/lib /home/$finduser/.local/bin /home/$finduser/.local/lib ~/.local/lib ~/.local/bin -name impacket* 2> /dev/null)
    
    echo -e "\n ${greenplus} Preparing to nuke Impacket... \n"
    
    echo -e "${spaces}${greenplus} function running removing :\n$SEAD\n"
    rm -rf $SEAD
    fix_impacket_array
    install_old_impacket
    }


fix_impacket_array() {
    arr=('addcomputer.py' 'atexec.py' 'dcomexec.py' 'dpapi.py' 'esentutl.py' 'findDelegation.py' 'GetADUsers.py' 'getArch.py' 'GetNPUsers.py'
         'getPac.py' 'getST.py' 'getTGT.py' 'GetUserSPNs.py' 'goldenPac.py' 'karmaSMB.py' 'kintercept.py' 'lookupsid.py' 'mimikatz.py'
         'mqtt_check.py' 'mssqlclient.py' 'mssqlinstance.py' 'netview.py' 'nmapAnswerMachine.py' 'ntfs-read.py' 'ntlmrelayx.py' 'ping6.py'
         'ping.py' 'psexec.py' 'raiseChild.py' 'rdp_check.py' 'registry-read.py' 'reg.py' 'rpcdump.py' 'rpcmap.py' 'sambaPipe.py' 'samrdump.py'
         'secretsdump.py' 'services.py' 'smbclient.py' 'smbexec.py' 'smbrelayx.py' 'smbserver.py' 'sniffer.py' 'sniff.py' 'split.py'
         'ticketConverter.py' 'ticketer.py' 'wmiexec.py' 'wmipersist.py' 'wmiquery.py' 'addcomputer.pyc' 'atexec.pyc' 'dcomexec.pyc' 'dpapi.pyc'
         'esentutl.pyc' 'findDelegation.pyc' 'GetADUsers.pyc' 'getArch.pyc' 'GetNPUsers.pyc' 'getPac.pyc' 'getST.pyc' 'getTGT.pyc'
         'GetUserSPNs.pyc' 'goldenPac.pyc' 'karmaSMB.pyc' 'kintercept.pyc' 'lookupsid.pyc' 'mimikatz.pyc' 'mqtt_check.pyc' 'mssqlclient.pyc'
         'mssqlinstance.pyc' 'netview.pyc' 'nmapAnswerMachine.pyc' 'ntfs-read.pyc' 'ntlmrelayx.pyc' 'ping6.pyc' 'ping.pyc' 'psexec.pyc'
         'raiseChild.pyc' 'rdp_check.pyc' 'registry-read.pyc' 'reg.pyc' 'rpcdump.pyc' 'rpcmap.pyc' 'sambaPipe.pyc' 'samrdump.pyc'
         'secretsdump.pyc' 'services.pyc' 'smbclient.pyc' 'smbexec.pyc' 'smbrelayx.pyc' 'smbserver.pyc' 'sniffer.pyc' 'sniff.pyc' 'split.pyc'
         'ticketConverter.pyc' 'ticketer.pyc' 'wmiexec.pyc' 'wmipersist.pyc' 'wmiquery.pyc' )

     for impacket_file in ${arr[@]}; do
       rm -f /usr/bin/$impacket_file /usr/local/bin/$impacket_file ~/.local/bin/$impacket_file /home/$finduser/.local/bin/$impacket_file
     done
    }


install_old_impacket() {
    install_pip2
    install_pip2_modules
    eval /usr/bin/pip2 uninstall impacket
    fix_impacket_array
    [ -d /opt/impacket-0.9.19 ] && rm -rf /opt/impacket-0.9.19
    eval wget https://github.com/SecureAuthCorp/impacket/releases/download/impacket_0_9_19/impacket-0.9.19.tar.gz -O /tmp/impacket-0.9.19.tar.gz
    eval tar xvfz /tmp/impacket-0.9.19.tar.gz -C /opt
    cd /opt
    chown -R root:root impacket-0.9.19
    cd /opt/impacket-0.9.19
    eval /usr/bin/pip2 install -r requirements.txt
    cd /opt/impacket-0.9.19
    eval /bin/python2.7 ./setup.py install 
    rm -f /tmp/impacket-0.9.19.tar.gz
    eval apt -y reinstall python3-impacket impacket-scripts
    echo -e "\n${spaces}${greenplus} installed: impacket-0.9.19"
    }


make_rootgreatagain() {
    if [[ $ENABLE_ROOT -eq 1 ]]
      then 
        if [[ $SPEEDRUN -eq 1 ]]
          then
          enable_rootlogin 
          else
            echo -e "\n\n KALI-ROOT-LOGIN INSTALLATION: - PAGE 1   "$red"*** READ CAREFULLY! ***"$white" \n"
            echo -e "   Kali 2019.x and prior the default user was root"
            echo -e "   As of Kali 2020.1 and newer this was changed, the default user was changed to be "
            echo -e "   an" $yellow$bold"actual user"$norm$white" on the system and not "$red$bold"root"$norm$white", this user is : kali (by default) "
            echo -e "\n   Press Y - If you wish to re-enable the ability to login as root and be root all the time"
            echo -e "     If you choose Yes - a second screen will prompt you to copy all of /home/$finduser to /root"
            echo -e "     as there is nothing in the /root directory by default"
            echo -e "\n   Press N - The script will skip this section, and not re-enable the login as root function"
            echo -e "\n   "$bold$red"If you are confused or dont understand what"$norm$white
            echo -e "   "$bold$red"this part of the script is doing, press N"$norm$white
            echo -e "\n   Do you want to re-enable the ability to login as root in kali?"
            read -n1 -p "   Please type Y or N : " userinput
            case $userinput in
              y|Y) enable_rootlogin $force;;
              n|N) echo -e "\n\n ${redexclaim} skipping root login setup" ;;
              *) echo -e "\n invalid key try again Y or N"; make_rootgreatagain;;
            esac
        fi
      else 
        echo -e "\n  ${greenminus} Enable root login is ${ENABLE_ROOT} skipping"
    fi
    }


enable_rootlogin() {
    is_installed "kali-root-login"

    echo -e "${spaces}${greenplus} Root login enabled, enter a password for root \n"
    passwd root
    if [ "$?" -ne 0 ]
      then
        echo -e "${spaces}${redexclaim} Passwords did not match - restarting this function"
        enable_rootlogin
      else
        echo -e "${spaces}${greenplus} Password updated"
      fi
    
    echo -e "${spaces}${greenplus} root login enabled"

    if [[ $SPEEDRUN -eq 1 ]]
    then
      ask_homekali_to_root
    else 
      ask_homekali_to_root
    fi 
    }


ask_homekali_to_root() {
    if [[ $SPEEDRUN -eq 1 ]]
      then 
        ask_are_you_sure
      else 
        echo -e "\n KALI-ROOT-LOGIN INSTALLATION: - PAGE 2   "$red"*** READ CAREFULLY! ***"$white" \n"
        echo -e "   This section of the script is only executed if Yes was selected at the enable root login prompt\n"
        echo -e "   If you are planning on operating your kali install as root instead of the user kali, "
        echo -e "   by default there is nothing in /root, This script has the ability to copy everything"
        echo -e "   from /home/$finduser to /root for you. \n"
        echo -e "  $red Warning:$white This copy function $red will overwrite $white anything in /root with the entire contents of /home/kali"
        echo -e "   The copy statement that is going to be performed if you select Y is:\n "
        echo -e "    cp -Rvf /home/$finduser/* /home/$finduser/.* /root"
        echo -e "\n   Would you like to copy everything from /home/$finduser to /root ?"
        echo -e "     Press Y - to copy everything from /home/$finduser to /root"
        echo -e "     Press N - do not copy anything to /root and skip this function\n"
        read -n1 -p "   Please type Y or N : " userinput
        case $userinput in
          y|Y) ask_are_you_sure;;
          n|N) echo -e "\n\n  ${redexclaim} skipping copy of /home/$finduser to /root" ;;
          *) echo -e "\n\n  ${redexclaim} Invalid key try again, Y or N keys only ${redexclaim}"; ask_homekali_to_root;;
        esac
    fi
    }


ask_are_you_sure() {
    if [[ $SPEEDRUN -eq 1 ]]
      then
        perform_copy_to_root
      else 
        echo -e "\n\n  Are you sure you want to copy all of /home/$finduser to /root ?"
        read -n1 -p "  Please type Y or N : " userinput
        case $userinput in
          y|Y) perform_copy_to_root;;
          n|N) echo -e "\n\n  ${redexclaim} skipping copy of /home/$finduser to /root - not copying ";;
          *) echo -e "\n\n  ${redexclaim} Invalid key try again, Y or N keys only ${redexclaim}"; ask_are_you_sure;;
        esac
    fi
    }


perform_copy_to_root() {
    echo -e "\n\n  ${greenplus} Copying everything from /home/$finduser to /root... Please wait..."
   
     if [[ $finduser = "root" ]]
      then
       echo -e "Already root skipping..."
     else
       echo -e "${spaces}${greenplus} Copying /home/$finduser/* to /root"
       eval cp -Rvf /home/$finduser/.* /home/$finduser/* /root >/dev/null 2>&1
       
       echo -e "${spaces}${greenplus} Changing ownership:group of /root to root"
       eval chown -R root:root /root
       
       echo -e "${spaces}${greenplus} Copy from /home/$finduser/* to /root - Complete"
     fi
    }


fix_broken_xfce() {
    echo -e "\n  ${greenplus} Applying broken XFCE Fix  \n "
    is_installed_reinstall "xfce4-settings"
    echo -e "${spaces}${greenplus} Broken XFCE Fix applied: xfce4-settings reinstalled  \n"
    disable_power_xfce
    }


update_linux_headers() {
    list_installed_kernels=$(ls /lib/modules)

    echo -e "\n ${greenplus} Updating linux-headers"
    for each_installed_kernel in $list_installed_kernels
      do
        if apt-cache show linux-headers-${each_installed_kernel} &> /dev/null; 
          then 
            echo -e "${spaces}${greenplus} Kernel ${each_installed_kernel} found, installing linux-headers-${each_installed_kernel}"
            is_installed "linux-headers-${each_installed_kernel}"
          else
            echo > /dev/null 
        fi
    done
	  }


only_upgrade() {
    fix_sources
    echo -e "\n  ${greenplus} Starting Pimpmyupgrade   \n"
    kernel_check=$(ls /lib/modules | sort -n | tail -n 1)
    is_installed "dkms build-essential linux-headers-${kernel_check}"
    apt_upgrade
    update_linux_headers
    virt_what
    check_vm
    }


virt_what() {
    is_installed "virt-what"
    }


check_dmidecode() {
    is_installed "dmidecode" 
    }


vbox_fix_shared_folder_permission_denied() {
    echo -e "\n  ${greenplus} Virtualbox shared folders fix"
    findgroup=$(groups $finduser | grep -i -c "vboxsf")

    if [[ $findgroup = 0 ]]
      then
        eval adduser $finduser vboxsf
        echo -e "${spaces}{$greenplus} ${finduser} added to vboxsf group "
      else
        echo -e "${spaces}${greenminus} ${finduser} user is already a member of vboxsf group\n"
    fi
    }


fix_virtualbox() {
    is_installed_reinstall "virtualbox-dkms virtualbox-guest-x11"
    
    # get detected hostOS version of virtualbox-additions
    check_dmidecode

    VBOX_VER=$(dmidecode | grep -i vboxver | grep -E -o '[[:digit:]\.]+' | tail -n 1)

    echo -e "${spaces}${greenplus} Downloading VBoxGuestAdditions_$VBOX_VER.iso"
    wget 'https://download.virtualbox.org/virtualbox/'$VBOX_VER'/VBoxGuestAdditions_'$VBOX_VER'.iso' -O /tmp/VBoxGuestAdditions_$VBOX_VER.iso
    mkdir /tmp/vboxtmp
    mount -o loop '/tmp/VBoxGuestAdditions_'$VBOX_VER'.iso' /tmp/vboxtmp
    cp -f /tmp/vboxtmp/VBoxLinuxAdditions.run /tmp
    umount /tmp/vboxtmp
    chmod +x /tmp/VBoxLinuxAdditions.run
    /tmp/VBoxLinuxAdditions.run install --force
    /sbin/rcvboxadd quicksetup all

    # get lastest additions
    #mkdir /tmp/vboxtmp
    #wget https://download.virtualbox.org/virtualbox/LATEST.TXT -O /tmp/vbox-latest
    #vboxver=$(cat /tmp/vbox-latest)
    #wget https://download.virtualbox.org/virtualbox/$vboxver/VBoxGuestAdditions_$vboxver.iso -O /usr/share/virtualbox/VBoxGuestAdditions.iso
    #
    #mount /usr/share/virtualbox/VBoxGuestAdditions.iso /tmp/vboxtmp
    #cp -f /tmp/vboxtmp/VBoxLinuxAdditions.run /tmp/VBoxLinuxAdditions.run
    #umount /tmp/vboxtmp
    #rmdir /tmp/vboxtmp
    #chmod +x /tmp/VBoxLinuxAdditions.run
    #/tmp/VBoxLinuxAdditions.run install --force
    #rm -f /tmp/VBoxLinuxAdditions.run
    #/sbin/rcvboxadd quicksetup all
    echo -e "\n  ${greenplus} VBoxGuestAdditions for version $VBOX_VER installed"
    echo -e "\n  ${redstar} A reboot of your system is required"
    }


check_vm() {
    is_installed "linux-headers-$(uname -r)"
    
    echo -e "\n  ${greenplus} Detecting hypervisor"
    vbox_check=$(virt-what | grep -i -c "virtualbox")    # virtualbox check
    vmware_check=$(virt-what | grep -i -c "vmware")      # vmware check (workstation/player/fusion)
    qemu_check=$(virt-what | grep -i -c "qemu\|kvm")     # qemu or kvm check (qemu/utm)
  
    if [ $vbox_check -eq 1 ]
      then
        echo -e "${spaces}${greenplus} *** Virtualbox Detected ***"
        echo -e "${spaces}${greenplus} installing virtualbox-dkms virtualbox-guest-additions-iso virtualbox-guest-x11"
        fix_virtualbox
        vbox_fix_shared_folder_permission_denied
      elif  [ $vmware_check -eq 1 ]
        then
          echo -e "${spaces}${greenplus} *** Vmware Detected ***"
          is_installed_remove fuse
          is_installed_reinstall "open-vm-tools-desktop fuse3"
       elif  [ $qemu_check -eq 1 ]
         then
          echo -e "${spaces}${greenplus} *** Qemu Detected ***"
          is_installed_reinstall "spice-vdagent qemu-guest-agent"
    
      else
        echo -e "\n ${redstar} Hypervisor not detected, Possible bare-metal installation not updating"
    fi
    }


hacking_api_create_cleanupsh() { 
    cleanup_script="cleanup.sh"
    echo -e "\n  ${greenplus} Creating cleanup.sh" 
    # create cleanup.sh - prompts user for a Y or y prompt and provides warning before executing commands
    echo -e "#!/bin/bash" > $cleanup_script
    echo -e "\n" >> $cleanup_script
    echo "cleanup_docker () {" >> $cleanup_script
    echo -e "    sudo docker stop \$(sudo docker ps -aq)" >> $cleanup_script
    echo -e "    sudo docker rm \$(sudo docker ps -aq)" >> $cleanup_script
    echo -e "    sudo docker rm \$(sudo docker images -q)" >> $cleanup_script 
    echo -e "    sudo docker volume rm \$(sudo docker volume ls -q)" >> $cleanup_script 
    echo -e "    sudo docker network rm \$(sudo docker network ls -q)" >> $cleanup_script
    echo "    exit" >> $cleanup_script
    echo "    }" >> $cleanup_script
    echo -e "\n" >> $cleanup_script
    echo "    echo -e \"\n  Warning! This script is about to remove all docker containers and networks!\" " >> $cleanup_script
    echo "    read -n3 -p \"  Press Y or y to proceed any other key to exit : \" userinput " >> $cleanup_script
    echo "    case \$userinput in" >> $cleanup_script
    echo "        y|Y) cleanup_docker ;;" >> $cleanup_script
    echo "          *) exit ;;" >> $cleanup_script
    echo "    esac" >> $cleanup_script
    chmod +x cleanup.sh
    
    startup_script="start-api-hacking.sh"
    echo -e "\n  ${greenplus} Creating start-api-hacking.sh"
    echo -e "#!/bin/bash" > $startup_script
    echo -e "\n" >> $startup_script
    echo -e "cd ~/labs/crAPI/deploy/docker" >> $startup_script 
    echo -e "sudo VERSION=develop docker-compose -f docker-compose.yml pull" >> $startup_script
    echo -e "sudo VERSION=develop docker-compose -f docker-compose.yml --compatibility up -d" >> $startup_script
    chmod +x start-api-hacking.sh
    }


hacking_api_prereq() {
    is_installed "docker.io"
    fix_dockercompose

    echo -e "\n  ${greenplus} Starting docker service and enabling " 
    APP="docker"
    FUNCTYPE="start service"
    systemctl enable docker --now
    EXIT_STATUS="$?"
    check_exit_status ${APP} ${FUNCTYPE} ${EXIT_STATUS}

    # determine arch type and download the respective postman for that arch
    echo -e "\n  ${greenplus} Downloading Postman for $arch"
    if [ $arch == "amd64" ]
      then
        wget https://dl.pstmn.io/download/latest/linux_64 -O /opt/postman.tar.gz
    elif [ $arch == "arm64" ]
      then
        wget https://dl.pstmn.io/download/latest/linux_arm64 -O /opt/postman.tar.gz
    elif [ $arch == "" ]
      then
        echo -e "\n  ${redexclaim} Unable to determine arch type" 
    fi 
    
    #install postman and symlink to /usr/bin/postman to be in $PATH
    echo -e "\n  ${greenplus} Installing Postman"
    cd /opt 
    tar xvfz postman.tar.gz $silent 
    ln -sf /opt/Postman/Postman /usr/bin/postman
    rm /opt/postman.tar.gz

    # user specific setup 
    if [ $finduser == "root" ]
      then 
        if [ ! -d /$finduser/labs ]
          then 
            echo -e "\n  ${greenplus} Creating labs directory /$finduser/labs"
            mkdir /$finduser/labs
        fi 
      
        cd /$finduser/labs
        echo -e "\n  ${greenplus} Installing crAPI to /$finduser/labs/crAPI"
        git clone https://github.com/OWASP/crAPI $silent 
      
        # create cleanup.sh in the crAPI directory
        hacking_api_create_cleanupsh
        cd /$finduser/labs/crAPI/deploy/docker
     else 
        if [ ! -d /home/$finduser/labs ]
          then 
            echo -e "\n  ${greenplus} Creating labs directory /home/$finduser/labs"
            mkdir /home/$finduser/labs
        fi 
      
        cd /home/$finduser/labs
        echo -e "\n  ${greenplus} Installing crAPI to /home/$finduser/labs/crAPI"
        git clone https://github.com/OWASP/crAPI $silent 
      
        # create cleanup.sh in the crAPI directory
        hacking_api_create_cleanupsh 
        chmod +x cleanup.sh
        chown -R $finduser:$finduser /home/$finduser/labs
        cd /home/$finduser/labs/crAPI/deploy/docker
    fi
    
    chmod -R 777 $HOME/peh/labs $HOME/peh/labs/* 
    echo -e "\n  ${greenplus} Please cd $PWD"
    echo -e "       and run the following command : sudo docker-compose up "
    }  


check_nessusd_active() {
    check_nessusd_service=$(sudo systemctl status nessusd | grep -i -c  "active (running)")
    if [[ $check_nessusd_service -ge 1 ]]
     then
      nessusd_service_active=1
      echo -e "\n  ${greenplus} nessusd service is active"
     else
      nessusd_service_active=0
      echo -e "\n  ${redexclaim} nessusd service is not active"
    fi
    }


check_nessus_installed_opt_nessus() {
    if [[ -d /opt/nessus ]]
    then 
     echo -e "\n  ${greenplus} Detected nessus installation at /opt/nessus"
     echo -e "${spaces}${greenplus} Removing all files from /opt/nessus"
     rm -rf /opt/nessus
    else
     echo -e "\n  ${greenplus} Nessus not detected at /opt/nessus"
    fi
    }


check_nessus_installed_dpkg() (
    dpkg_nessus=$(dpkg -l | grep -i -c nessus)
    if [ $dpkg_nessus -ge 1 ]
     then 
      echo -e "\n  ${greenplus} Detected nessus installed via dpkg -l" 
      echo -e "${spaces}${greenplus} Removing Nessus via dpkg -r"
      dpkg -r Nessus &> /dev/null
     else 
      echo -e "\n  ${greenplus} No detectinon of nessus installed via dpkg"
    fi
    )


nuke_nessus() {
    check_nessusd_active
    if [ $nessusd_service_active -ge 1 ]
     then 
      echo -e "\n  ${greenplus} Stopping nessusd service"
      systemctl stop --now nessusd
      check_nessus_installed_dpkg
      check_nessus_installed_opt_nessus
      echo -e "${spaces}${greenplus} Nessus has been removed"
    fi
    }


remove_nessus() {
    check_nessusd_active
    if [[ $nessusd_service_active -ge 1 ]]
     then
      echo -e "\n  Warning! You are about to uninstall and remove Nessus"
      read -n1 -p "  Press Y or y to continue, any other key to exit: " nessus_removeinput
      case $nessus_removeinput in
        y|Y) nuke_nessus;;
          *) echo -e "\n  ${greenplus} Aborting uninstallation of nessus"; exit;;
      esac
     else
      echo -e "\n  ${redexclaim} nessusd service is not running"
    fi
    }


install_nessus() {
    # check if nessus is already installed and build out a remove function
    if [ $arch == "amd64" ]
      then
      nessus_amd64_file=$(curl https://www.tenable.com/downloads/nessus\?loginAttempted\=true | grep -o -m1 -E "Nessus-[0-9]{1,2}.[0-9]{1}.[0-9]{1}-debian10_amd64.deb" | grep -m1 -i ".deb")
      nessus_amd64="https://www.tenable.com/downloads/api/v2/pages/nessus/files/$nessus_amd64_file"
     
      echo -e "\n  ${greenplus} Downloading Nessus for $arch"
      wget -q $nessus_amd64 -O /tmp/nessus_amd64.deb
      echo -e "\n  ${greenplus} Installing Nessus for $arch"
      dpkg -i /tmp/nessus_amd64.deb
      rm -f /tmp/nessus_amd64.deb
      echo -e "\n  ${greenplus} Enabling nessusd service"
      systemctl enable --now nessusd
      check_nessusd_active
    elif [ $arch == "arm64" ]
     then
      nessus_arm64_file=$(curl https://www.tenable.com/downloads/nessus\?loginAttempted\=true | grep -o -m1 -E "Nessus-[0-9]{1,2}.[0-9]{1}.[0-9]{1}-ubuntu[0-9]{1,4}_aarch64.deb" | grep -m1 -i ".deb")
      nessus_arm64="https://www.tenable.com/downloads/api/v2/pages/nessus/files/$nessus_arm64_file"
      
      echo -e "\n  ${greenplus} Downloading Nessus for $arch"
      wget $nessus_arm64 -O /tmp/nessus_arm64.deb
      echo -e "\n  ${greenplus} Installing Nessus for $arch"
      dpkg -i /tmp/nessus_arm64.deb
      rm -f /tmp/nessus_arm64.deb
      echo -e "\n  ${greenplus} Enabling nessusd service" 
      systemctl enable --now nessusd
      check_nessusd_active
    elif [ $arch == "" ]
     then
      echo -e "\n  ${redexclaim} Unable to determine arch type, exiting..." 
      exit
    fi
    }


mapt_prereq() {
    echo -e "\n  ${greenplus} Installing Mobile Application Pentester course requirements"
    is_installed "python${pyver}-venv aapt apktool adb apksigner zipalign wkhtmltopdf default-jdk jadx"
    is_installed "docker.io"
    fix_dockercompose
    eval systemctl enable docker --now
    eval docker pull opensecurity/mobile-security-framework-mobsf:latest
    echo "sudo docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest" > /usr/bin/mobsf-docker
    chmod +x /usr/bin/mobsf-docker 
      # git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF /opt/Mobile-Security-Framework-MobSF
    echo -e "${spaces}${greenplus} Createed MobSF startup script to /usr/bin/mobsf-docker"
    }


pbb_create_cleanupsh() { 
    cleanup_script="cleanup-pbb-labs.sh"
    echo -e "\n  ${greenplus} Creating cleanup_peh_labs.sh" 
    # create cleanup.sh - prompts user for Y or y prompt and provides warning before executing commands
    echo -e "#!/bin/bash" > $cleanup_script
    echo -e "\n" >> $cleanup_script
    echo "cleanup_docker () {" >> $cleanup_script
    echo -e "    sudo docker stop \$(sudo docker ps -aq)" >> $cleanup_script
    echo -e "    sudo docker rm \$(sudo docker ps -aq)" >> $cleanup_script
    echo -e "    sudo docker rm \$(sudo docker images -q)" >> $cleanup_script 
    echo -e "    sudo docker volume rm \$(sudo docker volume ls -q)" >> $cleanup_script 
    echo -e "    sudo docker network rm \$(sudo docker network ls -q)" >> $cleanup_script
    echo "    exit" >> $cleanup_script
    echo "    }" >> $cleanup_script
    echo -e "\n" >> $cleanup_script
    echo "    echo -e \"\n  Warning! This script is about to remove all docker containers and networks!\" " >> $cleanup_script
    echo "    read -n3 -p \"  Press Y or y to proceed any other key to exit : \" userinput " >> $cleanup_script
    echo "    case \$userinput in" >> $cleanup_script
    echo "        y|Y) cleanup_docker ;;" >> $cleanup_script
    echo "          *) exit ;;" >> $cleanup_script
    echo "    esac" >> $cleanup_script
    chmod +x cleanup-pbb-labs.sh

    # create start-pbb-labs.sh
    startup_script="start-pbb-labs.sh"
    echo -e "\n  ${greenplus} Creating start-pbb-labs.sh"
    echo -e "#!/bin/bash" > $startup_script
    echo -e "\n" >> $startup_script
    echo -e "cd ~/pbb/labs/" >> $startup_script
    echo -e "sudo docker-compose down"  >> $startup_script 
    echo -e "sudo systemctl stop mysqld" >> $startup_script 
    echo -e "sudo docker-compose up -d" >> $startup_script
    echo -e "get_lab_status=\$(curl --silent http://localhost/init.php | grep -i \"connection refused\" -c)" >> $startup_script
    echo -e "while [ \$get_lab_status -ge 1 ]" >> $startup_script
    echo -e "do" >> $startup_script
    echo -e "if [[ \$get_lab_status -ge 1 ]]" >> $startup_script
    echo -e " then" >> $startup_script
    echo -e "  sleep 1" >> $startup_script
    echo -e "checkagain=\$(curl --silent http://localhost/init.php | grep -i \"connection refused\" -c)" >> $startup_script
    echo -e "if [[ \$checkagain == 0 ]]" >> $startup_script
    echo -e " then" >> $startup_script
    echo -e "  curl --silent http://localhost/init.php > /dev/null" >> $startup_script
    echo -e " echo \"Databases reset\" ">> $startup_script
    echo -e "     exit" >> $startup_script
    echo -e "    else" >> $startup_script
    echo -e "      echo > /dev/null" >> $startup_script
    echo -e "    fi" >> $startup_script
    echo -e " else" >> $startup_script
    echo -e "  exit" >> $startup_script
    echo -e " fi" >> $startup_script
    echo -e " done" >> $startup_script
    # through here 
    chmod +x start-pbb-labs.sh
    }    


pbb_lab_setup() {
    echo -e "\n  ${greenplus} Installing Practical Bug Bounty course requirements"
    is_installed "docker.io"
    fix_dockercompose
    
    echo -e "${spaces}${greenplus} Starting docker service and enabling " 
    APP="docker"
    FUNCTYPE="start service"
    systemctl enable docker --now
    EXIT_STATUS="$?"
    check_exit_status ${APP} ${FUNCTYPE} ${EXIT_STATUS}
    
    echo -e "${spaces}${greenplus} Downloading pbb-labs.zip " 
    wget https://cdn.fs.teachablecdn.com/iaWfH4NrRp20zLOd3xLr -O /tmp/pbb-labs.zip
    
    if [[ $finduser == "root" ]]
      then 
        #lab setup for root
        echo -e "${spaces}${greenplus} Making peh directory for bugbounty labs /$finduser/pbb"
        mkdir /$finduser/pbb
      
        echo -e "${spaces}${greenplus} Extracting labs to /$finduser/pbb/bugbounty" 
        unzip -o /tmp/pbb-labs.zip -d /$finduser/pbb
     
        echo -e "${spaces}${greenplus} Setting permissions for /$finduser/pbb/bugbounty/labs/uploads"
        chmod 777 /$finduser/pbb/bugbounty/labs/uploads

        echo -e "${spaces}${greenplus} Starting labs docker in daemon mode" 
        cd /$finduser/pbb/bugbounty
        pbb_create_cleanupsh

      if [[ ! -f docker-compose.yml ]]
        then 
          echo -e "${spaces}${redexclaim} docker-compose.yml not found in current directory, aborting "
          exit_screen
        else 
          echo -e "${spaces}${greenplus} docker-compose.yml found, starting labs in daemon mode -d" 
          eval docker-compose up -d 
          get_lab_status=$(curl --silent http://localhost/init.php | grep -c -i "connection refused")
          echo -e "${spaces}${greenminus} Waiting for databases to reset..."
          while [ $get_lab_status -ge 1 ]
            do
            if [[ $get_lab_status -ge 1 ]]
              then
                sleep 1
                checkagain=$(curl --silent http://localhost/init.php | grep -c -i "connection refused")
                if [[ $checkagain == 0 ]]
                  then
                    curl --silent http://localhost/init.php > /dev/null
                    echo -e "${spaces}${greenplus} Database reset"
                    exit
                  else
                    echo > /dev/null
                fi
              else
              exit
            fi
          done
          exit_screen 
      fi 
     else 
      # lab setup for regular user 
      echo -e "${spaces}${greenplus} Making pbb directory for labs /home/$finduser/pbb"
      mkdir /home/$finduser/pbb

      echo -e "${spaces}${greenplus} Extracting labs to /home/$finduser/pbb"
      unzip -o /tmp/pbb-labs.zip -d /home/$finduser/pbb

      # check for /home/$finduser/pbb/bugbounty/labs/uploads
      if [[ -d /home/$finduser/pbb/bugbounty/labs/uploads ]]
        then
          echo -e "${spaces}${greenplus} Setting permissions for /home/$finduser/pbb/labs/uploads"
          chmod 777 /home/$finduser/pbb/bugbounty/labs/uploads
          echo -e "${spaces}${greenplus} Setting ownership to $finduser:$finduser for /home/$finduser/pbb"
          chown -R $finduser:$finduser /home/$finduser/pbb
       else
          echo -e "${spaces}${redexclaim} Unable to find /home/$finduser/pbb/labs/uploads"
      fi

      echo -e "${spaces}${greenplus} Creating cleanup-pbb-labs.sh and start-pbb-labs.sh in /home/$finduser/pbb/bugbounty" 
      cd /home/$finduser/pbb/bugbounty
      pbb_create_cleanupsh

      echo -e "${spaces}${greenplus} Cleaning up temporary files..." 
      rm /tmp/pbb-labs.zip

      echo -e "${spaces}${greenplus} Starting labs docker in daemon mode" 
      cd /home/$finduser/pbb/bugbounty
      if [[ ! -f docker-compose.yml ]]
        then 
          echo -e "${spaces}${redexclaim} docker-compose.yml not found in current directory, aborting "
          exit_screen
       else 
          echo -e "${spaces}${greenplus} docker-compose.yml found, starting labs in daemon mode " 
          eval docker-compose up -d 
          get_lab_status=$(curl --silent http://localhost/init.php | grep -c -i "connection refused")
          echo -e "${spaces}${greenminus} Waiting for databases to reset..."
          while [ $get_lab_status -ge 1 ]
            do
            if [[ $get_lab_status -ge 1 ]]
              then
               sleep 1
               checkagain=$(curl --silent http://localhost/init.php | grep -c -i "connection refused")
                if [[ $checkagain == 0 ]]
                  then
                    curl --silent http://localhost/init.php > /dev/null
                    echo -e "${spaces}${greenplus} Database reset"
                    exit
                  else
                    echo > /dev/null
                fi
            else
              exit
            fi
          done
          exit_screen
      fi
    fi
    }


install_vscode() {
    # install vscode from microsoft
    echo -e "\n  ${greenplus} Installing VSCode"

    is_installed "wget gpg apt_transport_https"

    wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > /tmp/packages.microsoft.gpg
    sudo install -D -o root -g root -m 644 /tmp/packages.microsoft.gpg /etc/apt/keyrings/packages.microsoft.gpg
    echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" | sudo tee /etc/apt/sources.list.d/vscode.list > /dev/null
    rm -f /tmp/packages.microsoft.gpg
    #required-apt-update
    apt_update
    is_installed code
    }


install_vscode_extensions() {
    # install commonly used extensions and themes
    # csharp dev kit, csharp extensions, vscode solutions explorer jupyter polyglot material icon theme
    echo -e "\n  ${greenplus} Installing VSCode Extensions"

    for vscode_extension_id in ms-dotnettools.csdevkit \
    ms-dotnettools.csharp \
    kreativ-software.csharpextensions \
    fernandoescolar.vscode-solution-explorer \
    ms-toolsai.jupyter \
    ms-dotnettools.dotnet-interactive-vscode \
    PKief.material-icon-theme
    do 
      echo -e "${spaces}${greenminus} Uninstalling Extension if exists: $vscode_extension_id" 
      sudo -u $(logname) code --uninstall-extension $vscode_extension_id >/dev/null 2>&1
      echo -e "${spaces}${greenplus} Installing Extension: $vscode_extension_id\n" 
      sudo -u $(logname) code --install-extension $vscode_extension_id >/dev/null 2>&1
    done
    }


install_dotnet() {
    echo -e "\n  ${greenplus} Installing Dotnet: $vscode_extension_id \n" 
    wget https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
    dpkg -i packages-microsoft-prod.deb
    rm -f packages-microsoft-prod.deb
    apt_update
    is_installed "ca-certificates libc6 libgcc-s1 libicu72 libicu-dev liblttng-ust1 libssl3 libstdc++6 libunwind8 zlib1g"
    is_installed "dotnet-sdk-8.0 aspnetcore-runtime-8.0 dotnet-runtime-8.0"
    }


csharp_course_setup() {
    # clean variables
    rc_file=""
    rc_tempfile=""

    USERSHELL=$(echo ${SHELL} | cut -d "/" -f4)

    # check for root or actual user
    if [[ $finduser == "root" ]]; 
          then
            rc_file="/root/.${USERSHELL}rc"
          else
            rc_file="/home/$(logname)/.${USERSHELL}rc"
    fi

    # install vscode
    install_vscode
    # install csharp course extensions
    install_vscode_extensions
    # install dotnet 
    install_dotnet

    # add DOTNET_ROOT and PATH's to ~/.zshrc
    # check for $(logname) if $(logname) == root pathing to ~/.zshrc will change
    if [[ $(cat $rc_file | grep -i -c "export DOTNET_ROOT") -ge 0 ]]; 
    then
      touch /tmp/${USERSHELL}rc.tmp
      rc_tempfile="/tmp/${USERSHELL}rc.tmp"
      dotnet_pattern1="export DOTNET_ROOT.*"
      dotnet_pattern2="export PATH\=\$PATH\:\$DOTNET_ROOT\:\$DOTNET_ROOT/tools.*"
      dotnet_pattern3="# dotnet path statements"
      # check .zshrc for exiting entries, if found, remove them and add specified course material entries
      cat $rc_file | sed s:"^${dotnet_pattern1}":"":g | sed s:"^${dotnet_pattern2}":"":g | sed s:"^${dotnet_pattern3}":"":g | sed '/[^[:space:]]/,$!d' > $rc_tempfile
      echo "" >> $rc_tempfile
      echo "# dotnet path statements" >> $rc_tempfile
      echo "export DOTNET_ROOT=\$HOME/.dotnet" >> $rc_tempfile
      echo "export PATH=\$PATH:\$DOTNET_ROOT:\$DOTNET_ROOT/tools" >> $rc_tempfile
      echo "" >> $rc_tempfile
      cp -f $rc_tempfile $rc_file
      rm -f $rc_tempfile
      chown $(logname):$(logname) $rc_file
      runuser $(logname) $SHELL -c 'subshell=$(echo $SHELL | cut -d "/" -f4); source $HOME/.$subshell"rc"' 
      echo -e "\n  ${greenplus} C# 101 for Hackers setup complete"
      echo -e "${spaces}${greenplus} VSCode Version Installed: $(sudo -u $(logname) code --version | head -n1)" 
      echo -e "${spaces}${greenplus} Dotnet Installed: $(dotnet --version)"
      echo -e "${spaces}${greenplus} AspNetCore version: $(dotnet --list-runtimes | sort -n | grep "AspNetCore" -m 1 | cut -d "[" -f1)"
      echo -e "${spaces}${greenplus} NETCore version: $(dotnet --list-runtimes | sort -n | grep "NETCore" -m 1 | cut -d "[" -f1)"
      echo -e "${spaces}${greenplus} SDK version: $(dotnet --list-sdks | sort -r | head -n1 | cut -d "[" -f1)"
      echo -e "${spaces}${greenplus} Added Dotnet Paths to ${rc_file}"
      echo -e "${spaces}${spaces}export DOTNET_ROOT=\$HOME/.dotnet"
      echo -e "${spaces}${spaces}export PATH=\$PATH:\$DOTNET_ROOT:\$DOTNET_ROOT/tools"
      echo -e "\n  ${redexclaim} Please execute the following command:  source ~/.zshrc "
    fi
    }


hacking_peh_create_cleanupsh() { 
    cleanup_script="cleanup-peh-labs.sh"
    # create cleanup.sh - prompts user for a Y or y prompt and provides warning before executing commands
    echo -e "#!/bin/bash" > $cleanup_script
    echo -e "\n" >> $cleanup_script
    echo "cleanup_docker () {" >> $cleanup_script
    echo -e "    sudo docker stop \$(sudo docker ps -aq)" >> $cleanup_script
    echo -e "    sudo docker rm \$(sudo docker ps -aq)" >> $cleanup_script
    echo -e "    sudo docker rm \$(sudo docker images -q)" >> $cleanup_script 
    echo -e "    sudo docker volume rm \$(sudo docker volume ls -q)" >> $cleanup_script 
    echo -e "    sudo docker network rm \$(sudo docker network ls -q)" >> $cleanup_script
    echo "    exit" >> $cleanup_script
    echo "    }" >> $cleanup_script
    echo -e "\n" >> $cleanup_script
    echo "    echo -e \"\n  Warning! This script is about to remove all docker containers and networks!\" " >> $cleanup_script
    echo "    read -n3 -p \"  Press Y or y to proceed any other key to exit : \" userinput " >> $cleanup_script
    echo "    case \$userinput in" >> $cleanup_script
    echo "        y|Y) cleanup_docker ;;" >> $cleanup_script
    echo "          *) exit ;;" >> $cleanup_script
    echo "    esac" >> $cleanup_script
    chmod +x cleanup-peh-labs.sh
    echo -e "${spaces}${greenplus} cleanup-peh-labs.sh created" 

    # create start-peh-labs.sh
    startup_script="start-peh-labs.sh"
    echo -e "#!/bin/bash" > $startup_script
    echo -e "\n" >> $startup_script
    echo -e "cd ~/peh/labs/" >> $startup_script
    echo -e "sudo docker-compose down"  >> $startup_script 
    echo -e "sudo systemctl stop mysqld" >> $startup_script 
    echo -e "sudo docker-compose up -d" >> $startup_script
    echo -e "get_lab_status=\$(curl --silent http://localhost/init.php | grep -i \"connection refused\" -c)" >> $startup_script
    echo -e "while [ \$get_lab_status -ge 1 ]" >> $startup_script
    echo -e "do" >> $startup_script
    echo -e "if [[ \$get_lab_status -ge 1 ]]" >> $startup_script
    echo -e " then" >> $startup_script
    echo -e "  sleep 1" >> $startup_script
    echo -e "checkagain=\$(curl --silent http://localhost/init.php | grep -i \"connection refused\" -c)" >> $startup_script
    echo -e "if [[ \$checkagain == 0 ]]" >> $startup_script
    echo -e " then" >> $startup_script
    echo -e "  curl --silent http://localhost/init.php > /dev/null" >> $startup_script
    echo -e " echo \"Databases reset\" ">> $startup_script
    echo -e "     exit" >> $startup_script
    echo -e "    else" >> $startup_script
    echo -e "      echo > /dev/null" >> $startup_script
    echo -e "    fi" >> $startup_script
    echo -e " else" >> $startup_script
    echo -e "  exit" >> $startup_script
    echo -e " fi" >> $startup_script
    echo -e " done" >> $startup_script
    chmod +x start-peh-labs.sh
    echo -e "${spaces}${greenplus} start-peh-hacking.sh created"
    }


peh_weblab_setup() {
    echo -e "\n  ${greenplus} Installing PEH Course Web Lab"
    echo -e "${spaces}${greenplus} Installing docker.io and docker-compose"

    fix_dockercompose 
    
    echo -e "${spaces}${greenplus} Starting docker service and enabling " 
    APP="docker"
    FUNCTYPE="start service"
    systemctl enable docker --now
    EXIT_STATUS="$?"
    check_exit_status ${APP} ${FUNCTYPE} ${EXIT_STATUS}
    
    echo -e "${spaces}${greenplus} Downloading peh-web-labs.tar.gz " 
    wget https://cdn.fs.teachablecdn.com/NgPnyKOwSfWYuwnX3Lzb -O /tmp/peh-web-labs.tar.gz
    
    if [[ $finduser == "root" ]]
      then 
        #lab setup for root
        echo -e "${spaces}${greenplus} Making peh directory for labs /$finduser/peh"
        mkdir /$finduser/peh
      
        echo -e "${spaces}${greenplus} Extracting labs to /$finduser/peh" 
        tar xvfz /tmp/peh-web-labs.tar.gz -C /$finduser/peh
     
        echo -e "${spaces}${greenplus} Setting permissions for /$finduser/peh/labs/labs/uploads"
        chmod 777 /$finduser/peh/labs/labs/uploads

        echo -e "${spaces}${greenplus} Setting permissions for /$finduser/peh/labs/capstone/assets"
        chmod 777 /$finduser/peh/labs/capstone/assets

        echo -e "${spaces}${greenplus} Starting labs docker in daemon mode" 
        cd /$finduser/peh/labs 
        hacking_peh_create_cleanupsh

        if [[ ! -f docker-compose.yml ]]
          then 
            echo -e "${spaces}${redexclaim} docker-compose.yml not found in current directory, aborting "
            exit_screen
          else 
            echo -e "${spaces}${greenplus} docker-compose.yml found, starting labs in daemon mode -d" 
            eval docker-compose up -d 
            exit_screen 
        fi 
      else 
        # lab setup for regular user 
        echo -e "${spaces}${greenplus} Making peh directory for labs /home/$finduser/peh"
        mkdir /home/$finduser/peh 
      
        echo -e "${spaces}${greenplus} Extracting labs to /home/$finduser/peh" 
        tar xvfz /tmp/peh-web-labs.tar.gz -C /home/$finduser/peh 
     
        # check for /home/$finduser/peh/labs/labs/uploads
        if [[ -d /home/$finduser/peh/labs/labs/uploads ]]
          then 
            echo -e "${spaces}${greenplus} Setting permissions for /home/$finduser/peh/labs/labs/uploads"
            chmod 777 /home/$finduser/peh/labs/labs/uploads
            echo -e "${spaces}${greenplus} Setting ownership to $finduser:$finduser for /home/$finduser/peh"
            chown -R $finduser:$finduser /home/$finduser/peh 
          else 
            echo -e "${spaces}${redexclaim} Unable to find /home/$finduser/peh/labs/labs/uploads"
        fi 

        # check for /home/$finduser/peh/labs/capstones/assets
        if [[ -d /home/$finduser/peh/labs/capstone/assets ]] 
          then 
            echo -e "${spaces}${greenplus} Setting permissions for /home/$finduser/peh/labs/capstone/assets"
            chmod 777 /home/$finduser/peh/labs/capstone/assets
          else
            echo -e "${spaces}${redexclaim} Unable to locate /home/$finduser/peh/labs/capstone/assets"
            exit_screen
        fi 

        echo -e "${spaces}${greenplus} Creating cleanup-peh-labs.sh and start-peh-labs.sh in /home/$finduser/peh/labs" 
        cd /home/$finduser/peh/labs 
        hacking_peh_create_cleanupsh

        rm -f /tmp/peh-web-labs.tar.gz 

        if [[ ! -f docker-compose.yml ]]
          then 
            echo -e "${spaces}${redexclaim} docker-compose.yml not found in current directory, aborting "
            exit_screen
          else 
            echo -e "${spaces}${greenplus} docker-compose.yml found, starting labs in daemon mode " 
            eval docker-compose up -d 
        fi 
      fi 
    }


fix_ghidra() {
    is_installed "jq curl"
    LATEST_URL="https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest"
    JSON_DATA=$(curl -s "${LATEST_URL}")
    # DOWNLOAD_URL=$(echo "$JSON_DATA" | jq -r '.assets[] | select(.name | test("ghidra_[0-9]+\\.[0-9]+\\.[0-9]+_PUBLIC_[0-9]{8}\\.zip")) | .browser_download_url')
    DOWNLOAD_URL=$(echo "$JSON_DATA" | grep -i "browser_download_url" |  awk {'print $2'} | tr -d \")
    GHIDRA_INSTALL_DIR="/opt/ghidra"
    GHIDRA_TMP_ZIP="/tmp/ghidra.zip"
    GHIDRA_TMP_DIR=$(mktemp -d)
    GHIDRA_SYMLINK="/usr/local/bin/ghidra"
    DESKTOP_FILE="/usr/share/applications/ghidra.desktop"
    EXEC_PATH="${GHIDRA_INSTALL_DIR}/ghidraRun"
    ICON_PATH="${GHIDRA_INSTALL_DIR}/docs/images/GHIDRA_1.png"
    DARK_THEME_URL="https://github.com/zackelia/ghidra-dark-theme"

    echo -e "\n  ${greenplus} Ghidra Setup "
    
    # check for current ghidra installation, uninstall if found
    is_installed_remove "ghidra ghidra-data"
    
    # install dependencies 
    is_installed "openjdk-23-jdk"
    
    [ -f ${GHIDRA_TMP_ZIP} ] && rm -f ${GHIDRA_TMP_ZIP}

    [ -d ${GHIDRA_INSTALL_DIR} ] && rm -rf ${GHIDRA_INSTALL_DIR}
    [ ! -d ${GHIDRA_INSTALL_DIR} ] && mkdir ${GHIDRA_INSTALL_DIR}

    echo -e "${spaces}${greenplus} Downloading Ghidra"
    wget -q "${WGET_STATUS} " "${DOWNLOAD_URL}" -O "${GHIDRA_TMP_ZIP}"
    
    echo -e "${spaces}${greenplus} Unzipping Ghidra to ${GHIDRA_TMP_DIR}"
    unzip -qq -o "${GHIDRA_TMP_ZIP}" -d "${GHIDRA_TMP_DIR}"

    echo -e "${spaces}${greenplus} Moving Ghidra from ${GHIDRA_TMP_DIR} to ${GHIDRA_INSTALL_DIR}"
    mv "${GHIDRA_TMP_DIR}"/ghidra_*/* "${GHIDRA_INSTALL_DIR}"

    # create symbolic link in $PATH
    echo -e "${spaces}${greenplus} Creating Ghidra Symlink ${GHIDRA_SYMLINK}"
    [ -f "${GHIDRA_INSTALL_DIR}"/ghidraRun ] && ln -sf "${GHIDRA_INSTALL_DIR}"/ghidraRun "${GHIDRA_SYMLINK}"
    chmod +x /usr/local/bin/ghidra

    # create .desktop file
    echo -e "${spaces}${greenplus} Creating .desktop file ${DESKTOP_FILE}"

    # .desktop file /usr/share/applications/ghidra.desktop
    echo -e "[Desktop Entry]" > ${DESKTOP_FILE}
    echo -e "Version=1.0" >> ${DESKTOP_FILE}
    echo -e "Name=Ghidra" >> ${DESKTOP_FILE}
    echo -e "Comment=Open-source reverse engineering tool" >> ${DESKTOP_FILE}
    echo -e "Exec=${EXEC_PATH}" >> ${DESKTOP_FILE}
    echo -e "Icon=${ICON_PATH}" >> ${DESKTOP_FILE}
    echo -e "Terminal=false" >> ${DESKTOP_FILE}
    echo -e "Type=Application" >> ${DESKTOP_FILE}
    echo -e "Categories=Development;ReverseEngineering;" >> ${DESKTOP_FILE}

    chmod +x "$DESKTOP_FILE"

    echo -e "${spaces}${greenplus} Ghidra added to the XFCE menu."

    # Ghidra Dark Theme (optional quality of life improvement)
    GHIDRA_DARK_THEME_INSTALL_DIR="/opt/ghidra-dark-theme"
    [ -d ${GHIDRA_DARK_THEME_INSTALL_DIR} ] && rm -rf ${GHIDRA_DARK_THEME_INSTALL_DIR}

    echo -e "${spaces}${greenplus} Cloning Ghidra Dark Theme ${DARK_THEME_URL}"
    echo -e "\n            To install the dark theme, Open Ghidra and Click Edit/Themes/Import"
    echo -e "            browse to ${GHIDRA_DARK_THEME_INSTALL_DIR} double click on the .theme file\n"
  
    # clone ghidra dark-theme
    git clone ${DARK_THEME_URL} ${GHIDRA_DARK_THEME_INSTALL_DIR} > /dev/null 2>&1 
  
    # Cleanup
    echo -e "${spaces}${greenplus} Cleaning up ${GHIDRA_TMP_ZIP}"
    rm -f ${GHIDRA_TMP_ZIP}
    echo -e "${spaces}${greenplus} Cleaning up ${GHIDRA_TMP_DIR}"
    rm -rf ${GHIDRA_TMP_DIR}

    echo -e "${spaces}${greenplus} Ghidra Setup Complete"
    }


iot_course_setup() {
    SASQUATCH_URL="https://github.com/devttys0/sasquatch"
    SASQUATCH_PATCH_URL="https://github.com/devttys0/sasquatch/files/7776843/M1-Kali.patch.txt"
    CLONE_DIR="/opt/sasquatch"
    PATCH_DIR="/opt/sasquatch/patches"
    PATCH_FILE="M1-Kali.patch.txt"
    INSTALLED_BIN="/usr/local/bin/sasquatch"
 
    # rev 1.8.1a IoT Course setup requirements
    echo -e "\n  ${greenplus} IoT and Hardware Hacking Course Setup"

    echo -e "\n${spaces}${greenplus} Installing dependencies sigrok xxd zlib1g-dev liblzma-dev liblzo2-dev"
    
    is_installed "build-essential sigrok xxd zlib1g-dev liblzma-dev liblzo2-dev linux-headers-$(uname -r)"

    echo -e "\n  ${greenplus} Sasquatch Setup"    

    # remove clone dir if it already exists
    [ -d ${CLONE_DIR} ] && rm -rf ${CLONE_DIR}

    # remove installed sasquatch binary if it exists 
    [ -f ${INSTALLED_BIN} ] && rm -f ${INSTALLED_BIN}

    echo -e "\n${spaces}${greenplus} Cloning sasquatch to ${CLONE_DIR} \n"
    cd /opt && git clone ${SASQUATCH_URL}
    
    echo -e "\n${spaces}${greenplus} Downloading sasquatch patch ${PATCH_FILE}"
    wget -qq ${SASQUATCH_PATCH_URL} -O ${PATCH_DIR}/${PATCH_FILE}

    echo -e "\n${spaces}${greenplus} Patching sasquatch with ${PATCH_FILE}" 
    cd ${PATCH_DIR}
    patch patch0.txt M1-Kali.patch.txt  > /dev/null 2>&1 
    APP="sasquatch"
    FUNCTYPE="patch"
    EXIT_STATUS="$?"
    check_exit_status ${APP} ${FUNCTYPE} ${EXIT_STATUS}
    clean_vars

    echo -e "\n${spaces}${greenplus} Building and installing sasquatch to ${INSTALLED_BIN}"
    [ -f ${CLONE_DIR}/build.sh ] && chmod +x ${CLONE_DIR}/build.sh
    cd ${CLONE_DIR}
    yes | ./build.sh  # > /dev/null 2>&1
    APP="sasquatch"
    FUNCTYPE="build"
    EXIT_STATUS="$?"
    check_exit_status ${APP} ${FUNCTYPE} ${EXIT_STATUS}
    clean_vars

    fix_ghidra

    echo -e "${spaces}${greenplus} IoT Course Setup Complete"
    }


#---- begin pimpmykali-mirrors rev 1.3.2 08.20.2021
get_mirrorlist() {
    cleanup
    fix_sources
    echo -e "\n  ${greenplus} Pimpmykali-Mirrors - kali repo mirror speedtest"

    mod_deb=$(cat /etc/apt/sources.list | grep -c "deb http\:\/\/.* kali\-rolling.*")
    mod_debsrc=$(cat /etc/apt/sources.list | grep -c "deb-src http\:\/\/.* kali\-rolling.*")

    if [[ $mod_deb = 1 ]]
      then
        echo -e "${spaces}${greenplus} deb http://*/kali found in /etc/apt/sources.list"
      else
        echo -e "${spaces}${redexclaim} Unable to find deb http://*/kali in /etc/apt/sources.list"
        exit_screen
    fi

    if [[ $mod_debsrc = 1 ]]
      then
        echo -e "${spaces}${greenplus} deb-src http://*/kali found in /etc/apt/sources.list"
      else
        echo -e "${spaces}${redexclaim} Unable to find deb-src in /etc/apt/sources.list"
        exit_screen
    fi

    curl -s http://http.kali.org/README?mirrorlist | grep -i "README" | cut -d ">" -f2 | cut -d "\"" -f2 | grep -i "http://" | \
    sed s:"http\:\/\/http.kali.org\/README.meta4":"":g | sed s:"http\:\/\/http.kali.org\/README.metalink":"":g | sort -u > /tmp/timetest.list
  	}


best_ping() {
    [[ -f /tmp/kali-ping ]] && rm -f /tmp/kali-ping
	  echo -e "\n  ${greenplus} Testing kali mirrors round-trip-time, selecting the top 10"
    mirror=$(cat /tmp/timetest.list | sort -u | sed s:"http\:\/\/":"":g)
    
    for i in $mirror; do
      current_mirror=$(echo $i | cut -d "/" -f1)
      current_file=$(echo $i | cut -d "/" -f2-10)
      avg_rtt_mirror=$(ping -c 3 $current_mirror | grep -i rtt | cut -d "=" -f2 | cut -d "/" -f2)
     
      if [[ $avg_rtt_mirror = "" ]]
        then
          echo -e "${spaces}${redexclaim} Failed to respond: $current_mirror"
        else
          echo -e "${spaces}${greenplus} Testing $current_mirror rtt time: $avg_rtt_mirror"ms" "
          echo "$avg_rtt_mirror:$current_mirror" >> /tmp/kali-ping
      fi
    done

    best_rtt=$(cat /tmp/kali-ping | sed -r '/^\s*$/d' | sort -nr | tail -n1 | cut -d ":" -f1)
    best_rttmirror=$(cat /tmp/kali-ping | sed -r '/^\s*$/d' | sort -nr | tail -n1 | cut -d ":" -f2)
    echo -e "${spaces}${greenplus} Best rtt result : $best_rtt"ms" at $best_rttmirror"
    }


small_speedtest() {
  	echo > /tmp/mirrors_speedtest
    echo -e "\n  ${greenplus} Testing top 10 mirrors - small transfer >1MB, select top 5"
    for i in $(cat /tmp/kali-ping | sed -r '/^\s*$/d' | sort -n | head -n10 | cut -d ":" -f2); do
  	  active_mirror=$(cat /tmp/timetest.list | grep "$i" | grep "README" | sed -r '/^\s*$/d')
  	  active_mirror_display=$(cat /tmp/timetest.list | grep "$i" | grep "README" | cut -d "/" -f3| sed -r '/^\s*$/d')
  	  get_download=$(curl -s "$active_mirror" -w %{speed_download} -o /dev/null)
   	  mb_speed=$(($get_download / 1024 / 1024))
  	  echo "$get_download:$active_mirror:$mb_speed" >> /tmp/mirrors_speedtest
      echo -e "${spaces}${greenplus} $active_mirror_display speed: $get_download b/sec"
  	done
  	}


large_speedtest() {
  	echo > /tmp/mirrors_speedtest
  	echo -e "\n  ${greenplus} Testing top 5 mirrors from small transfer - large transfer (10MB)"
  	for i in $(cat /tmp/kali-ping | sed -r '/^\s*$/d' | sort -n | head -n5 | cut -d ":" -f2); do
  	  active_mirror=$(cat /tmp/timetest.list | grep "$i" | grep "README" | sed s:"README":"dists/kali-rolling/Contents-amd64.gz":g | sed -r '/^\s*$/d')
  	  active_mirror_display=$(cat /tmp/timetest.list | grep "$i" | grep "README" | cut -d "/" -f3| sed -r '/^\s*$/d')
   	  get_download=$(curl --max-time 30 -s -r 0-10485760 "$active_mirror" -w %{speed_download} -o /dev/null)
   	  mb_speed=$(($get_download / 1024 / 1024))
  	  echo "$get_download:$active_mirror:$mb_speed" >> /tmp/mirrors_speedtest
  	  echo -e "${spaces}${greenplus} $active_mirror_display speed: $get_download b/sec ($mb_speed MB/sec)"
  	done
  	}


gen_new_sources() {
  	i=$(cat /tmp/mirrors_speedtest | sort -n | tail -n1 | cut -d "/" -f3)
  	final_mirror=$(cat /tmp/timetest.list | grep "$i" | sed s:"http\:\/\/":"":g | sed s:"/README":"":g )
    # --- relaxed grep and sed, implement at later date 12.11.2021 - should now work with tracelabs osint vm
    newdeb=$(cat /etc/apt/sources.list | grep "deb http\:\/\/.* kali\-rolling.*" | sed s:"deb http\:\/\/.* kali\-rolling.*":"deb http\:\/\/"$final_mirror" kali\-rolling main contrib non\-free":g)
    newdebsrc=$(cat /etc/apt/sources.list | grep "deb-src http\:\/\/.* kali\-rolling.*" | sed s:"deb-src http\:\/\/.* kali\-rolling.*":"deb\-src http\:\/\/"$final_mirror" kali\-rolling main contrib non\-free":g )
    sourcefile=/etc/apt/sources.list
    echo -e "\n  ${greenplus} Based on tests the best selection is: $i "
    echo -e "\n  Preview of the new /etc/apt/sources.list:"
    echo -e "\n  $newdeb\n  $newdebsrc"
    echo -e "\n\n   Save new changes to /etc/apt/sources.list ?"
    read -n1 -p "   Please type Y or N : " userinput
     case $userinput in
       y|Y) echo -e "\n\n  ${greenplus} Saving changes to /etc/apt/sources.list"; cp $sourcefile ${sourcefile}_$(date +%F-%T); \
            sed s:"deb http\:\/\/.* kali\-rolling.*":"deb http\:\/\/"$final_mirror" kali\-rolling main contrib non\-free":g -i $sourcefile; \
            sed s:"deb-src http\:\/\/.* kali\-rolling.*":"deb\-src http\:\/\/"$final_mirror" kali\-rolling main contrib non\-free":g -i $sourcefile; \
            sed 's/non-free$/non-free non-free-firmware/' -i $sourcefile
            echo -e "\n  ${greenplus} Running apt update with mirror $final_mirror selected \n"; apt_update;;
       n|N) echo -e "\n\n  ${redexclaim} Not saving changes";;
         *) echo -e "\n\n  ${redexclaim} Invalid key try again, Y or N only ${redexclaim}"; gen_new_sources;;
     esac
    }


cleanup() {
  	rm -f /tmp/kali-speedtest.found /tmp/kali-speedtest /tmp/timetest.list /tmp/kali-latency /tmp/sources.list /tmp/final.list /tmp/kali-ping /tmp/mirrors_speedtest > /dev/null
    }


fix_keyboard() {
    sudo /bin/bash --rcfile /home/$finduser/.bashrc -ic 'dpkg-reconfigure keyboard-configuration'
    }


fix_timezone() {
    sudo /bin/bash --rcfile /home/$finduser/.bashrc -ic 'dpkg-reconfigure tzdata' 2>/dev/null
    echo -e "\n  ${greenplus} Timezone now set to: $(cat /etc/timezone)"
    }


install_everything() {
    echo -e "\n  ${greenplus} Installing Everything! \n"
    sudo /bin/bash -m --rcfile /home/$finduser/.bashrc -ic 'apt -y install kali-linux-everything' 2> /dev/null
    }


fix_pip2_pip3() {
    # set the pips for python3
    echo -e "\n  ${greenplus} Checking /bin/pip for python3"
    if [[ -f /usr/bin/pip ]]
      then
        pip_check=$(/usr/bin/pip --version | grep -i -c "python 2")
    fi

    if [[ $pipcheck -eq 1 ]]
      then
        is_installed_reinstall "python3-pip"
        ln -sf /usr/bin/pip3 /usr/bin/pip
      else
        echo -e "${spaces}${greenminus} /bin/pip is for python3, skipping"
        pip_check=""
    fi

    echo -e "\n  ${greenplus} Checking /usr/local/bin/pip for python3"
    if [[ -f /usr/local/bin/pip ]] 
      then
        pip_check=$(/usr/local/bin/pip --version | grep -i -c "python 2")
    fi
         
    if [[ $pip_check -eq 1 ]]
      then 
        is_installed_reinstall "python3-pip"
      else
        echo -e "${spaces}${greenminus} /usr/bin/pip is for python3, skipping"
    fi
    }


install_docker() {
    is_installed "docker-cli docker.io"
    }


install_pip2() {
    is_installed_pip2=$(whereis pip2 | cut -d " " -f 2) 
    if [[ $is_installed_pip2 == "/usr/bin/pip2" ]]
    then
      echo -e "\n  ${greenminus} Pip2 for Python2 is installed at ${is_installed_pip2}"
    else 
      PIP2_URL="https://bootstrap.pypa.io/pip/2.7/get-pip.py"
      mkdir /opt/pip2
      cd /opt/pip2
      curl ${PIP2_URL} -o get-pip.py
      /usr/bin/python2 /opt/pip2/get-pip.py
      ln -sf /usr/local/bin/pip2 /usr/bin/pip2
      rm /usr/local/bin/pip
      chmod +x /bin/pip2
      chmod +x /usr/bin/pip2
      chmod +x /usr/local/bin/pip2
    fi
    }


install_pip3_modules() {
    pip3modules=(
      "setuptools"
      "importlib"
      "pyftpdlib"
      "future"
    )

    for pip3module in "${pip3modules[@]}"; do
      is_installed "python3-${pip3module}"
    done
    }


install_pip2_modules() {
    pip2modules=(
      "setuptools"
      "future==0.18"
      "importlib"
      "flask"
      "ldap3==2.9.1"
      "pycryptodomex"
      "xlrd==1.2.0 --upgrade"
      "scapy==2.4.0 --upgrade"
      "colorama"
      "termcolor"
      "service-identity"
      "requests==2.2.1"
      "ldapdomaindump"
    )

    echo -e "\n  ${greenplus} Installing python2 modules"

    for pip2module in "${pip2modules[@]}"; do
      pip2_module_name=$(echo $pip2module | cut -d "=" -f1)
    
      is_pip2_module_installed=$(pip2 list | grep -i -c $pip2_module_name)
      if [[ $is_pip2_module_installed -eq 0 ]]
        then 
          echo -e "${spaces}${greenplus} Installing pip2 module ${pip2module} "
          /usr/bin/pip2 install $pip2module
        else
          echo -e "${spaces}${greenminus} ${pip2module} already installed"
      fi
    done
    }


install_pip3() {
    is_installed "python3-pip"
    }


install_pipx() {
    is_installed "pipx"

    APP="pipx"
    FUNCTYPE="ensurepath"
    sudo -u $(logname) pipx ensurepath
    EXIT_STATUS="$?"
    check_exit_status ${APP} ${FUNCTYPE} ${EXIT_STATUS}
    clean_vars
    }


install_gobuster() {
    is_installed "gobuster"
    }


install_ffuf() {
    is_installed "ffuf"
    }


install_wfuzz() {
    is_installed "wfuzz"
    }


install_hydra() {
    is_installed "hydra"
    }


install_sqlmap() {
    is_installed "sqlmap"
    }


install_enumforlinux() {
    is_installed "enum4linux"
    }


install_enumforlinux_ng() {
    is_installed "enum4linux-ng"
    }


install_plumhound() {
    echo -e "\n  ${greenplus} PlumHound setup"
    is_installed "bloodhound" 

    findrealuser=$(logname) 

    [ -d /opt/PlumHound ] && rm -rf /opt/PlumHound
    PLUMHOUND_URL="https://github.com/PlumHound/PlumHound"
    PLUMHOUND_DIR="/opt/PlumHound"
    git clone ${PLUMHOUND_URL} ${PLUMHOUND_DIR}

    cd $PLUMHOUND_DIR
    echo -e "${spaces}${greenplus} Installing PlumHound" 
    /usr/bin/pip3 install -r requirements.txt --break-system-packages
    chmod +x /opt/PlumHound/PlumHound.py 
  
    echo -e "${spaces}${greenplus} Creating Symlink /usr/local/bin/PlumHound.py" 
    [ -L /usr/local/bin/PlumHound.py ] && rm -f /usr/local/bin/PlumHound.py
    ln -sf /opt/PlumHound/PlumHound.py /usr/local/bin/PlumHound.py

    echo -e "${spaces}${greenplus} Creating symlink /usr/local/bin/plumhound" 
    [ -L /usr/local/bin/plumhound ] && rm -f /usr/local/bin/plumhound
    ln -sf /opt/PlumHound/PlumHound.py /usr/local/bin/plumhound
    }


fix_impacket() {
    is_installed_reinstall "python3-impacket impacket-scripts"
    }


check_installed_linuxheaders() {
    is_installed "linux-headers-$(uname -r)"
    }


check_installed_dkms() {
    is_installed "dkms"
    }


setup_binfmt_misc_winexe() {
    #add wine, regsiter Windows binaries
    dpkg --add-architecture i386 
    apt_update
    is_installed "wine32:i386"
    BINFMT_MISC_PATH="/proc/sys/fs/binfmt_misc"

    if [[ ! -f $BINFMT_MISC_PATH/DOSWin ]]
      then 
        echo -e "${spaces}${greenplus} Adding DOSWin binaries to $BINFMT_MISC_PATH"
        echo ':DOSWin:M::MZ::/usr/bin/wine:' > $BINFMT_MISC_PATH/register
      else
        echo '-1' > $BINFMT_MISC_PATH/DOSWin
        echo ':DOSWin:M::MZ::/usr/bin/wine:' > $BINFMT_MISC_PATH/register
        echo -e "${spaces}${greenminus} DOSWin binaries already added to $BINFMT_MISC_PATH"
    fi
    }


setup_binfmt_mount() {
    # feature request 
    echo -e "\n  ${greenplus} Setup binfmt_misc mount"
    BINFMT_MISC_PATH="/proc/sys/fs/binfmt_misc"

    CHECK_LSMOD=$(lsmod | grep -i -c "binfmt_misc")
    if [[ $CHECK_LSMOD -eq 0 ]]
      then
        echo -e "${spaces}${greenplus} Loading binfmt_misc module"
        modprobe binfmt_misc
      else
        echo -e "${spaces}${greenminus} binfmt_misc module already loaded, skipping"
    fi 

    CHECK_FSTAB=$(cat /etc/fstab | grep -i -c "binfmt_misc")
    if [[ $CHECK_FSTAB -eq 0 ]]
      then
        echo -e "${spaces}${greenplus} Adding binfmt_misc mount to /etc/fstab"
        echo 'binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc defaults 0 0' >> /etc/fstab 
      else
        echo -e "${spaces}${greenminus} binfmt_misc mount already exists in /etc/fstab, skipping"
    fi 
   
    CHECK_MOUNT=$(mount | grep -i -c "/proc/sys/fs/binfmt_misc")
    if [[ $CHECK_MOUNT -eq 0 ]]
      then
        echo -e "${spaces}${greenplus} Mounting binfmt_misc"
        mount binfmt_misc
      else
        echo -e "${spaces}${greenminus} binfmt_misc already mounted, skipping"
      fi 
    }


# ascii art - DONT move
asciiart=$(base64 -d <<< "H4sIAAAAAAAAA31QQQrCQAy89xVz9NR8QHoQH+BVCATBvQmC
CEXI480kXdteTJfdzGQy2S3wi9EM/2MnSDm3oUoMuJlX3hmsMMSjA4uAtUTsSQ9NUkkKVgKKBX
p1lEC0auURW3owsQlTZtf4QtGZgjXYKT4inPtI23oEK7wXlyPnd8arKdKE0EPdUnhIf0v+iE2o
7BgVFVyec3u1OxFw+uRxbvPt8R6+MOpGq5cBAAA="  | gunzip )


confirm_menu_choice() {
    # menu selection confirmation
    if [ "${menuinput}" = "x" ] || [ "${menuinput}" == "X" ]
    then
      exit_screen
    else
      menuinput_to_upper=$(echo ${menuinput} | tr '[:lower:]' '[:upper:]')
      echo -e "\n"
      read -n1 -p "  Menu selection is ${menuinput_to_upper} press Y or N to confirm: " selectinput

      case $selectinput in
        "Y"|"y") echo -e "\n\n  ${greenplus} Executing menu option ${menuinpu_to_upper}";;
        "N"|"n") echo -e "\n\n  ${greenminus} Restarting menu"; return 1;;
              *) echo -e "\n${spaces}${redexclaim} Invalid input, Y, y, N or n only"; confirm_menu_choice $menuinput;;
      esac
    fi
    }


pimpmykali_menu() {
    while true; do
      clear
      echo -e "$asciiart"
      echo -e "\n    Select an option from menu:             Rev: $revision Arch: $arch"
      echo -e "\n Key  Menu Option:                  Description:"
      echo -e " ---  ------------                  ------------"
      echo -e "  1 - Fix Missing                   (pip pip3 golang gedit nmapfix build-essential)"              # fix_missing
      echo -e "  2 - Fix /etc/samba/smb.conf       (set client min/max protocol if not already set)"             # fix_smbconf
      echo -e "  3 - Fix Golang                    (installs golang, adds GOPATH= to .zshrc and .bashrc)"        # install_golang
      echo -e "  4 - Fix Grub                      (adds mitigations=off)"                                       # fix_grub
      echo -e "  5 - Reinstall Impacket            (reinstall impacket from kali repo)"                          # fix_impacket
      echo -e "  6 - Enable Root Login             (installs kali-root-login)"                                   # SPEEDRUN=0; make_rootgreatagain
      echo -e "  7 - Fix Docker-Compose            (installs docker-compose and docker.io)"                      # fix_dockercompose
      echo -e "  8 - Fix nmap scripts              (clamav-exec.nse and http-shellshock.nse)"                    # fix_nmap
      echo -e "  9 - Pimpmyupgrade                 (apt upgrade with vbox/vmware detection)"                     # only_upgrade
      echo -e "                                    (sources.list, linux-headers, vm-video)"                      # only_upgrade extended text
      echo -e "  0 - Fix ONLY 1 thru 8             (runs only 1 thru 8) \n"                                      # fix_all
      echo -e "  "$bold"N - NEW VM SETUP"$reset" - Run this option if this is the first time running pimpmykali\n"
      echo -e "  = - Pimpmykali-Mirrors            (find fastest kali mirror. use the equals symbol = )"          # get_mirrorlist; best_ping; small_speedtest; large_speedtest; gen_new_sources; cleanup;;
      echo -e "  T - Reconfigure Timezone           current timezone  : $(cat /etc/timezone)"                     # reconfig_timekey
      echo -e "  K - Reconfigure Keyboard           current keyb/lang : $(cat /etc/default/keyboard | grep XKBLAYOUT | cut -d "\"" -f2)" # reconfig_keyboard
      echo -e "\n Key  Stand alone functions:        Description:"                                               # 
      echo -e " ---  --COURSES-------------------- ------------"                                                 # 
      echo -e "  A - MAPT Course Setup             (adds requirments for MAPT Course)"                           # mapt_course
      echo -e "  B - Practical Bugbounty Labs      (add requirements for PBB course labs)"                       # pbb_lab_setup
      echo -e "  E - PEH Course WebApp Labs        (add requirements for PEH WebApp Labs and installs) "         # apt_update fix_libwacom peh_weblab_setup
      echo -e "  O - Hacking API Course Setup      (add requirements for Hacking API Course)"                    # hacking_api_prereq
      echo -e "  Y - Andrew B IoT Hardware Hacking (add requirements for IoT Course)"                            # iot_course_setup
      echo -e "  Z - Alex T C# 101 For Hackers     (add requirements for C# 101 course)"                         # csharp_course_setup
      echo -e "\n ---  --UTILS---------------------- ------------"                                               # 
      echo -e "  U - Install Netexec (nxc)         (install netexec)"                                            # fix_netexec
      echo -e "  P - Download Lin/WinPeas          (adds linpeas to /opt/linpeas and winpeas to /opt/winpeas)"   # fix_linwinpeas
      echo -e "  V - Install MS-VSCode             (install microsoft vscode only)"                              # install_vscode
      echo -e "  ! - Nuke Impacket                 (install Impacket 0.9.19)"                                    # fix_sead_warning
      echo -e "  @ - Install Nessus                (install Nessus and start nessusd service)"                   # install_nessus
      echo -e "  $ - Nuke Nessus                   (stop nessusd service and remove nessus)"                     # remove_nessus
      echo -e "  % - CrackMapExec                  (install crackmapexec)\n"                                     # fix_cme
      echo -e "  Please use sudo ./pimpmykali.sh --help for additional installations/fixes\n"
      # menu selection
      read -n1 -p "  Press key for menu item selection or press X to exit: " menuinput

      # menu selection confirmation
      confirm_menu_choice $menuinput
      if [ $? -eq 0 ]; 
        then
          break
      fi
    done 

    if [ $APT_UPDATE_RAN -eq 0 ]
      then 
        apt_update
        export APT_UPDATE_RAN=1
    fi 

    case $menuinput in
        1) SPEEDRUN=0; ENABLE_ROOT=0; fix_missing;;
        2) fix_smbconf;;
        3) install_golang; fix_go_path;;
        4) fix_grub;;
        5) fix_impacket;;
        6) SPEEDRUN=0; ENABLE_ROOT=1; make_rootgreatagain;;
        7) fix_dockercompose;;
        8) fix_nmap ;;
        9) fix_libwacom; only_upgrade;;
        0) SPEEDRUN=0; ENABLE_ROOT=0; fix_all;;
      a|A) mapt_prereq;;
      b|B) pbb_lab_setup;;
#      c|C) ;;
#      d|D) ;;
      e|E) fix_libwacom; peh_weblab_setup;;
#      f|F) ;;
#      g|G) ;;
#      h|H) ;;
#      i|I) ;;
#      j|J) ;;
      k|K) fix_keyboard; echo -e "\n  ${greenplus} Keyboard is currently set to: $(cat /etc/default/keyboard | grep XKBLAYOUT | cut -d "\"" -f2)";;
#      l|L) ;;
#      m|M) ;;
      n|N) fix_all;;
      o|O) hacking_api_prereq;;
      p|P) fix_linwinpeas;; 
#      q|Q) ;;
#      r|R) ;;
#      s|S) ;;
      t|T) fix_timezone;;
      u|U) fix_netexec;;
      v|V) install_vscode;;
#      w|W) ;;
      x|X) echo -e "\n\n Exiting pimpmykali.sh - Happy Hacking! \n" ;;
      y|Y) iot_course_setup;;
      z|Z) csharp_course_setup;;
      "!") install_pip2; install_pip3; fix_pip2_pip3; fix_sead_warning;;
      "=") get_mirrorlist; best_ping; small_speedtest; large_speedtest; gen_new_sources; cleanup;;
      "^") SPEEDRUN=1; ENABLE_ROOT=1; install_everything;;
      "@") install_nessus;;
      "$") remove_nessus;;
      "%") fix_cme;;
        *) pimpmykali_menu;;
    esac
    }


pimpmykali_help() {
    echo -e "\n  Command line args:"
    options=(
    "         --auto  set speedrun var, bypass menu, only prompt is to set root password"
    "   --autonoroot  set speedrun var, bypass menu, bypass enable root login, bypass prompts"
    "          --all  run menu option 0 (fix all) with prompts, bypass enable root login"
    "       --binfmt  enable and mount /proc/sys/fs/binfmt_misc"
    "--binfmt-winexe  enable dos/windows exe in binfmt_misc, installs wine"
    "   --bloodhound  install bloodhound" 
    "   --brokenxfce  apply broken xfce fix"
    "          --cme  install crackmapexec"
    "      --checkvm  detect hypervisor, install guest additions"
    "--dockercompose  install docker compose"
    "    --flameshot  install flameshot"
    "        --gedit  install gedit, apply fix connection refused fix"
    "       --golang  install golang"
    "    --gowitness  install gowitness from github"
    "       --ghidra  install ghidra from github, add dark theme"
    "         --grub  update grub"
    "         --help  this help menu"
    "     --httprobe  run fix_httprobe"
    "     --impacket  install impacket latest"
    " --nukeimpacket  install impacket 0.9.19, leave python3 as default"
    "      --mirrors  run pimpmykali-mirrors speedtest"
    "        --mitm6  reinstall mitm6"
    "      --missing  run menu option 1 (fix missing)"
    "        --neo4j  install neo4j"
    "        --newvm  menu option N new vm setup"
    "         --nmap  run fix nmap"
    "      --netexec  install netexec from github"
    "       --nessus  download, install nessus and start nessusd service"
    "   --nukenessus  stop nessusd service and remove nessus"
    "         --peas  get all the peas (linpeas/winpeas)"
    "    --plumhound  install plumhound"
    "         --root  set speedrun var, enable root login"
    "      --smbconf  run fix smb.conf "
    "     --seclists  install seclists"
    "        --spike  run fix spike"
    "      --sublime  install sublime"
    "       --vscode  install vscode"
    "      --wayback  install waybackrust"
    "      --upgrade  system upgrade, hypervisor detection, install guest additions"
    "\n Python fixes:"
    "         --pip2  install pip2, --pip3 install pip3, --fixpip run fix pip function"
    "         --pipx  install pipx"
    "\n TCM Security course setup:"
    "          --api  Hacking API course setup"
    "       --csharp  C# course setup"
    "          --iot  IoT Hacking course setup"
    "         --mapt  Mobile Application Pentester course setup"
    "          --pbb  Practical Bugbounty course setup"
    "    --pehweblab  PEH course Web Lab setup"
    )

    for option in "${options[@]}"; do
        echo -e "$option"
    done
    exit 0
    }


check_arg() {
    if [ "$1" == "--help" ]
      then
        pimpmykali_help
    elif [ "$1" == "" ]
      then
        pimpmykali_menu
    else
        apt_update
        case $1 in
           --auto) SPEEDRUN=1; ENABLE_ROOT=1 fix_all;;
     --autonoroot) SPEEDRUN=1; ENABLE_ROOT=0 fix_all;;
            --all) SPEEDRUN=0; ENABLE_ROOT=0 fix_all;;
         --binfmt) setup_binfmt_mount;;
  --binfmt-winexe) setup_binfmt_misc_winexe;;
     --bloodhound) fix_bloodhound;;
     --brokenxfce) fix_broken_xfce;;
            --cme) fix_cme;;
        --checkvm) virt_what; check_vm;;
  --dockercompose) fix_dockercompose;;
      --flameshot) fix_flameshot;;
          --gedit) fix_gedit; fix_root_connectionrefused;;
         --golang) install_golang; fix_go_path;;
      --gowitness) fix_chrome; fix_gowitness;;
         --ghidra) fix_ghidra;;
           --grub) fix_grub;;
           --help) pimpmykali_help;;
       --httprobe) fix_httprobe;;
       --impacket) fix_impacket;;
         --nessus) install_nessus;;
     --nukenessus) remove_nessus;;
   --nukeimpacket) SPEEDRUN=1; install_pip2; install_pip3; fix_pip2_pip3; fix_sead_warning;;
        --mirrors) get_mirrorlist; best_ping; small_speedtest; large_speedtest; gen_new_sources; cleanup;;
          --mitm6) is_installed_reinstall "mitm6";;
        --missing) SPEEDRUN=1 ENABLE_ROOT=0; fix_missing;;
          --neo4j) fix_neo4j;;
          --newvm) SPEEDRUN=1; ENABLE_ROOT=0; fix_all;;
           --nmap) fix_nmap;;
        --netexec) fix_netexec;;
           --peas) fix_linwinpeas;;
      --plumhound) install_plumhound;;
           --root) SPEEDRUN=1; ENABLE_ROOT=1 make_rootgreatagain;;
        --smbconf) fix_smbconf;;
       --seclists) fix_seclists;;
        --sublime) install_sublime;;
         --vscode) install_vscode;;
        --upgrade) only_upgrade;;
           --pip2) install_pip2; install_pip2_modules;;
           --pip3) install_pip3; install_pip3_modules;;
         --fixpip) fix_pip2_pip3;;
           --pipx) install_pipx;;
          --spike) fix_spike;;
         --csharp) csharp_course_setup;;
            --pbb) pbb_lab_setup;;
      --pehweblab) fix_libwacom; peh_weblab_setup;;
            --api) hacking_api_prereq;;
            --iot) iot_course_setup;;
        --wayback) fix_waybackurls;;
                *) pimpmykali_help; exit 0;;
        esac
      fi
    }


exit_screen() {
    echo -e "\n"
    eval apt -y --fix-broken install >/dev/null 2>&1
    echo -e "$asciiart"
    echo -e "\n\n    All Done! Happy Hacking! \n"
    findrealuser=$(logname)
    getshell=$(echo $SHELL | cut -d "/" -f4)
    runuser $findrealuser $getshell -c 'subshell=$(echo $SHELL | cut -d "/" -f4); source $HOME/.$subshell"rc"'
    exit
    }


check_for_root
check_distro
check_arg "$1"
exit_screen
