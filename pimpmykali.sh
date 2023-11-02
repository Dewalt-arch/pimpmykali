#!/bin/bash
#
# pimpmykali.sh  Author: Dewalt
# git clone https://github.com/Dewalt-arch/pimpmykali 
# Usage: sudo ./pimpmykali.sh  ( defaults to the menu system )
# command line arguments are valid, only catching 1 arguement
#
# Full Revision history can be found in changelog.txt
# Standard Disclaimer: Author assumes no liability for any damage

# revision var
    revision="1.7.7"  

# unicorn puke:
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

# more unicorn puke...*sigh* added for senpai, taste the rainbow!
# now with 100% more unicorn puke! enjoy a color for no color!!
    color_nocolor='\e[0m'
    color_black='\e[0;30m'
    color_grey='\e[1;30m'
    color_red='\e[0;31m'
    color_light_red='\e[1;31m'
    color_green='\e[0;32m'
    color_light_green='\e[1;32m'
    color_brown='\e[0;33m'
    color_yellow='\e[1;33m'
    color_blue='\e[0;34m'
    color_light_blue='\e[1;34m'
    color_purple='\e[0;35m'
    color_light_purple='\e[1;35m'
    color_cyan='\e[0;36m'
    color_light_cyan='\e[1;36m'
    color_light_grey='\e[0;37m'
    color_white='\e[1;37m'

# nuke impacket function launch_code generator
    launch_codes_alpha=$(echo $((1 + RANDOM % 9999)))
    launch_codes_beta=$(echo $((1 + RANDOM % 9999)))
    launch_codes_charlie=$(echo $((1 + RANDOM % 9999)))

# status indicators
    greenplus='\e[1;33m[++]\e[0m'
    greenminus='\e[1;33m[--]\e[0m'
    redminus='\e[1;31m[--]\e[0m'
    redexclaim='\e[1;31m[!!]\e[0m'
    redstar='\e[1;31m[**]\e[0m'
    blinkexclaim='\e[1;31m[\e[5;31m!!\e[0m\e[1;31m]\e[0m'
    fourblinkexclaim='\e[1;31m[\e[5;31m!!!!\e[0m\e[1;31m]\e[0m'

# variables needed in the script
    # wait_time=10  # 2nd warning screen wait time (disabled)
    force=0
    check=""
    section=""
    type=""
    menu=""
    pipnowarn="--no-python-version-warning"  # turn off all python2.7 deprecation warnings in pip
    export PYTHONWARNINGS="ignore"
    # look at a method to find the current version of nessus should the version number change
    nessusd_service_active=0

# variables moved from local to global
    finduser=$(logname)
    detected_env=""
   
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

# for vbox_fix_shared_folder_permission_denied
    findgroup=$(groups $finduser | grep -i -c "vboxsf")

# Logging
    LOG_FILE=pimpmykali.log
    exec > >(tee ${LOG_FILE}) 2>&1

# silent mode
    silent=''                  # uncomment to see all output
    # silent='>/dev/null 2>&1' # uncomment to hide all output10
    export DEBIAN_FRONTEND=noninteractive
    export PYTHONWARNINGS=ignore

# 02.02.21 - rev 1.1.8 - fix_xfce_root fix_xfce_user fix_xfcepower external configuration file
    raw_xfce="https://raw.githubusercontent.com/Dewalt-arch/pimpmyi3-config/main/xfce4/xfce4-power-manager.xml"

check_distro() {
    distro=$(uname -a | grep -i -c "kali") # distro check
    if [ $distro -ne 1 ]
     then echo -e "\n $blinkexclaim Kali Linux Not Detected - WSL/WSL2/Anything else is unsupported $blinkexclaim \n"; exit
    fi

    # check for tracelabs osint vm, if found exit
    findhostname=$(hostname)
    findrelease=$(cat /etc/os-release | grep -i -c -m1 "2022.1")
    if [[ "$finduser" == "osint" ]] && [[ "$findhostname" == "osint" ]] && [[ $findrelease -ge 1 ]]
     then 
      echo -e "\n  $redexclaim Tracelabs Osint VM Detected, exiting"
      exit
    fi 
    }

check_for_root() {
    if [ "$EUID" -ne 0 ]
      then echo -e "\n\n Script must be run with sudo ./pimpmykali.sh or as root \n"
      exit
    else
      # 02.19.21 - Kali 2021.1 + MSF 6.0.30-DEV Released
      # Remove any prior hold on metasploit-framework at startup
      eval apt-mark unhold metasploit-framework >/dev/null 2>&1
    fi
    }

fix_section() {
    if [ $check -ne 1 ]
     then
      # sanity check : force=0 check=0 or force=1 check=0
      echo -e "\n  $greenplus install : $section"
      eval apt -o Dpkg::Progress-Fancy="1" -y install $section $silent
     elif [ $force = 1 ]
      then
       # sanity check : force=1 check=1
       echo -e "\n  $redstar reinstall : $section"
       eval apt -o Dpkg::Progress-Fancy="1" -y reinstall $section $silent
     else
       # sanity check : force=0  check=1
       echo -e "\n  $greenminus $section already installed"
       echo -e "       use --force to reinstall"
    fi
    check=""
    type=""
    section=""
    }

apt_update() {
    echo -e "\n  $greenplus running: apt update \n"
    eval apt -y update -o Dpkg::Progress-Fancy="1"
    }

apt_upgrade() {
    echo -e "\n  $greenplus running: apt upgrade \n"
    eval apt -y upgrade -o Dpkg::Progress-Fancy="1"
    }

apt_autoremove() {
    echo -e "\n  $greenplus running: apt autoremove \n"
    eval apt -y autoremove -o Dpkg::Progress-Fancy="1"
    }

apt_update_complete() {
    echo -e "\n  $greenplus apt update - complete"
    }

apt_upgrade_complete() {
    echo -e "\n  $greenplus apt upgrade - complete"
    }

apt_autoremove_complete() {
    echo -e "\n  $greenplus apt autoremove - complete"
    }

apt_fixbroken() {
    apt -y --fix-broken install 
}    

apt_fixbroken_complete() {
    echo -e "\n  $greenplus apt -y --fix-broken install  - complete"
}

fix_missing() {
    fix_kali_lightdm_theme_and_background
    fix_sources
    fix_hushlogin         # 06.18.2021 - added fix for .hushlogin file
    apt_update && apt_update_complete
    fix_libwacom
    apt_autoremove && apt_autoremove_complete
    eval apt -y remove kali-undercover $silent
    # 02.01.2020 - Added cifs-utils and libguestfs-tools as they are require for priv escalation
    # 10.05.2021 - Added dbus-x11 as it has become a common problem for those wanting to use gedit
    # 01.15.2023 - Added libu2f-udev and moved virt-what to an earlier section of the script
    eval apt -o Dpkg::Progress-Fancy="1" -y install libu2f-udev virt-what neo4j dkms build-essential autogen automake python-setuptools python3-setuptools python3-distutils python$pyver-dev libguestfs-tools cifs-utils dbus-x11 $silent
    # check_python         # 07.02.21 - check_python check if python is symlinked to python2 if not, make it point to python2
    python-pip-curl
    python3_pip $force
    fix_gedit   $force    # restored to its former glory
    fix_root_connectionrefused
    fix_htop    $force
    fix_golang  $force
    fix_nmap
    fix_rockyou
    fix_theharvester      # 02.02.2021 - added theharvester to fix_missing
    silence_pcbeep        # 02.02.2021 - turn off terminal pc beep
    disable_power_checkde # 06.18.2021 - disable gnome or xfce power management based on desktop environment detection
    fix_python_requests
    fix_pipxlrd           # 12.29.2020 added xlrd==1.2.0 for windows-exploit-suggester.py requirement
    fix_spike
    fix_set
    fix_pyftpdlib         # 09.01.21 - added pyftpdlib for python2
    fix_amass             # 09.02.21 - added amass precompiled binary
    fix_httprobe          # 01.04.22 - added httprobe precompiled binary
    fix_assetfinder       # 03.17.22 - added assetfinder precompiled binary
    check_chrome
    fix_gowitness         # 01.27.2021 added due to 404 errors with go get -u github.com/sensepost/gowitness
    fix_mitm6             # 05.09.2022 - added mitm6 to fix missing
    fix_linwinpeas
    fix_neo4j
    fix_bloodhound
    fix_proxychains
    fix_sshuttle
    fix_chisel
    fix_cme               # 08.03.2023 - added new CME6.x 
    fix_ssh_widecompat
    #fix_waybackurls      # has issues not implemented yet 
    }

fix_all() {
    fix_missing   $force
    apt_autoremove && apt_autoremove_complete 
    apt_fixbroken && apt_fixbroken_complete 
    make_rootgreatagain $force
    seclists
    fix_flameshot $force
    fix_grub
    fix_smbconf
    fix_impacket # - restored after changes made in 1.6.9
    # ID10T REMINDER: DONT CALL THESE HERE THEY ARE IN FIX_MISSING!
    # python-pip-curl python3_pip fix_golang fix_nmap
    # fix_upgrade is not a part of fix_missing and only
    # called as sub-function call of fix_all or fix_upgrade itself
    }

fix_kali_lightdm_theme_and_background () {
    # set kali lightdm login theme from Kali-Light to Kali-Dark
    sed s:"Kali-Light":"Kali-Dark":g -i /etc/lightdm/lightdm-gtk-greeter.conf
    # dark to light theme

    # set kali login-theme to Kali-Light from Dark theme
    # sed s:"Kali-Dark":"Kali-Light":g -i /etc/lightdm/lightdm.conf

    # set kali background to solid black color
    # sed s:"background = /usr/share/desktop-base/kali-theme/login/background":"background = #000000":g
    }

fix_libwacom() {
    eval apt -y install libwacom-common
    # fix for missing libwacom9 requires libwacom-common
    }

install_rustup() {
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -sSf | sh -s -- -y
    sudo -i -u $finduser curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -sSf | sh -s -- -y
    
    }

install_cargo() {
    sudo apt -y install cargo libssl-dev
    }

fix_waybackurls() {
    echo -e "\n  $greenplus Installing WaybackUrls \n"
    [ -f $HOME/.cargo/env ] && source $HOME/.cargo/env
    whichrust=$(which rustc)
    whichcargo=$(which cargo)
    echo -e "\n  $greenplus Checking for rustc and cargo"
    if [ "$whichrust" == "$HOME/.cargo/bin/rustc" ]
     then
      echo > /dev/null 
     else
      echo -e "\n  $redexclaim cannot find rustc, installing rustup"
      export RUSTUP_INIT_SKIP_PATH_CHECK=yes
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -sSf | sh -s -- -y
      source $HOME/.cargo/env
      echo "its in $HOME/.cargo/env"
      fix_waybackurls
    fi
    
    [ -f $HOME/.cargo/env ] && source $HOME/.cargo/env
    if [ "$whichcargo" == "$HOME/.cargo/bin/cargo" ]
     then
      rm -rf /opt/WaybackRust
      git clone https://github.com/Neolex-Security/WaybackRust /opt/WaybackRust
      cd /opt/WaybackRust
      [ -f $HOME/.cargo/env ] && source $HOME/.cargo/env; cargo build --release
    else 
      echo -e "\n  $redexclaim cannot find cargo... installing cargo"
      sudo apt -y install cargo libssl-dev
      echo -e "\n  $greenplus restarting fix_waybackurls function"
      exit 0
      fix_waybackurls
    fi

    if [[ -f /opt/WaybackRust/target/release/waybackrust ]]
     then
      echo -e "\n  $greenplus symlinking waybackrust to /usr/bin/waybackurls"
      ln -sf /opt/WaybackRust/target/release/waybackrust /usr/bin/waybackurls
      echo -e "\n  $greenplus Installation complete"
    else
      echo -e "\n  $redexclaim cant find waybackrust"
    fi
    }

fix_neo4j() {
    echo -e "\n  $greenplus Installing Neo4j"
    eval apt -y install neo4j
    }

fix_bloodhound() {
    echo -e "\n  $greenplus Installing Bloodhound"
    eval apt -y install bloodhound
    }

fix_proxychains() {
    echo -e "\n  $greenplus Installing proxychains"
    eval apt -y install proxychains
    }        

fix_sshuttle() {
    echo -e "\n  $greenplus Installing sshuttle"
    eval apt -y install sshuttle
    }    

fix_chisel() {
    echo -e "\n  $greenplus Installing chisel" 
    eval apt -y install chisel 
    }

fix_ssh_widecompat() { 
    echo -e "\n  $greenplus Setting SSH for wide compatibility"
    eval cp -f /usr/share/kali-defaults/etc/ssh/ssh_config.d/kali-wide-compat.conf /etc/ssh/ssh_config.d/kali-wide-compat.conf
    echo -e "\n  $greenplus Restarting SSH service for wide compatibility"
    eval systemctl restart ssh
    }        

fix_cme_symlinks() { 
    # needs to be a better way than doing this manually for each one
    # create a few symlinks to make life easier 

    findrealuser=$(logname) 
    getshell=$(echo $SHELL | cut -d "/" -f4)

    cmebin_path="$HOME/.local/pipx/venvs/crackmapexec/bin/"
    localbin_path="$HOME/.local/bin/"

    cme_symlink_array=( 'addcomputer.py' 'antdsparse' 'apython' 'ardpscan' 'asmbcertreq' 'asmbclient' 'asmbgetfile' 'asmbscanner' 'asmbshareenum'
    'asn1tools' 'asysocksbrute' 'asysocksportscan' 'asysocksproxy' 'asysockssec' 'asysockstunnel' 'atexec.py' 'awinreg' 'bloodhound-python' 'dcomexec.py'
    'dpapi.py' 'dploot' 'esentutl.py' 'exchanger.py' 'findDelegation.py' 'GetADUsers.py' 'getArch.py' 'Get-GPPPassword.py' 'getLAPSv2Password.py' 
    'GetNPUsers.py' 'getPac.py' 'getST.py' 'getTGT.py' 'GetUserSPNs.py' 'goldenPac.py' 'karmaSMB.py' 'keylistattack.py' 'kintercept.py' 'ldapdomaindump' 
    'ldd2bloodhound' 'ldd2pretty' 'lookupsid.py' 'lsassy' 'machine_role.py' 'masky' 'mimikatz.py' 'minidump' 'minikerberos-ccache2kirbi' 'minikerberos-ccacheedit'
    'minikerberos-ccacheroast' 'minikerberos-cve202233647' 'minikerberos-cve202233679' 'minikerberos-getNTPKInit' 'minikerberos-getS4U2proxy'
    'minikerberos-getS4U2self' 'minikerberos-getTGS' 'minikerberos-getTGT' 'minikerberos-kerb23hashdecrypt' 'minikerberos-kerberoast' 'minikerberos-kirbi2ccache'
    'mqtt_check.py' 'msldap' 'mssqlclient.py' 'mssqlinstance.py' 'netaddr' 'netview.py' 'nmapAnswerMachine.py' 'normalizer' 'ntfs-read.py'
    'ping6.py' 'ping.py' 'psexec.py' 'pypykatz' 'pywerview' 'raiseChild.py' 'rbcd.py' 'rdp_check.py' 'registry-read.py' 'reg.py'
    'rpcdump.py' 'rpcmap.py' 'sambaPipe.py' 'samrdump.py' 'secretsdump.py' 'services.py' 'smbclient.py' 'smbexec.py' 'smbpasswd.py' 'smbrelayx.py'
    'smbserver.py' 'sniffer.py' 'sniff.py' 'split.py' 'ticketConverter.py' 'ticketer.py' 'tstool.py' 'wmiexec.py' 'wmipersist.py' 'wmiquery.py')
     for cme_symlink_array_file in ${cme_symlink_array[@]}; do
     echo $cme_symlink_array_file > /tmp/cmesymlink.tmp
     # sanity check 
     # runuser $findrealuser $getshell -c 'echo -e "\n $HOME/.local/pipx/venvs/crackmapexec/bin/$(cat /tmp/cmesymlink.tmp) $HOME/.local/bin/$(cat /tmp/cmesymlink.tmp)"'
     echo -e "\n  $greenplus Creating symlink for user $findrealuser to ~/.local/bin/$cme_symlink_array_file  " 
     runuser $findrealuser $getshell -c 'symlink_file=$(cat /tmp/cmesymlink.tmp); ln -sf $HOME/.local/pipx/venvs/crackmapexec/bin/$symlink_file $HOME/.local/bin/$symlink_file'
     done
     # cleanup 
     rm -f /tmp/cmesymlink.tmp
    }

fix_cme() {
    findrealuser=$(logname) 
    echo -e "\n  $greenplus Installing cme (crackmapexec)" 
    echo -e "\n  $greenplus Checking for existing crackmapexec installation..."  
    
    checkforcme=$(apt list crackmapexec | grep -i -c "installed")
    
    if [[ $checkforcme -ge 1 ]]; 
     then
      echo -e "\n  $greenplus Existing installation found! - Removing"
      sudo apt -y remove crackmapexec
    fi 

    # root installation 
    if [[ $findrealuser == "root" ]];
     then
       echo -e "\n  Starting $findrealuser user installation"
       # pipx installer changed as of revision 1.7.4h 
       eval apt -y install pipx python3-venv  
       # python3 -m pip install pipx --user

       # git clone https://github.com/mpgn/CrackMapExec /opt/CrackMapExec
       git clone https://github.com/Porchetta-Industries/CrackMapExec /opt/CrackMapExec
       cd /opt/CrackMapExec
       pipx install . --force

       getshell=$(echo $SHELL | cut -d "/" -f4)
       check_for_local_bin_path=$(cat "$HOME/.$getshell"rc | grep -i "PATH=" | grep -i "\$HOME\/\.local\/bin" -c)

       if [[ $check_for_local_bin_path -eq 0 ]];
        then
         echo "export PATH=\$HOME/.local/bin:\$PATH" >> $HOME/.$getshell"rc"
        else 
         echo "\n  $redexclaim Path already exists for user $findrealuser "
       fi
       fix_cme_symlinks 
      fi

     # user installation 
     if [[ $findrealuser != "root" ]];
      then
        echo -e "\n  Starting $findrealuser user installation\n"
        # pipx installer changed as of revision 1.7.4h 
        # sudo -i -u $findrealuser sh -c 'python3 -m pip install pipx --user'
        eval apt -y install pipx python3-venv 
     
        [ -d /opt/CrackMapExec ] && rm -rf /opt/CrackMapExec
        git clone https://github.com/Porchetta-Industries/CrackMapExec /opt/CrackMapExec
        sudo -i -u $findrealuser sh -c 'cd /opt/CrackMapExec; pipx install . --force'
     
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
        fix_cme_symlinks 
      fi    
     }    

fix_linwinpeas() {
    # get all the peas!!!
    current_build=$(curl -s https://github.com/carlospolop/PEASS-ng/releases | grep -i "refs/heads/master" -m 1 | awk '{ print $5 }' | cut -d "<" -f1)
    releases_url="https://github.com/carlospolop/PEASS-ng/releases/download/$current_build"
	  dest_linpeas="/opt/linpeas"
	  dest_winpeas="/opt/winpeas"
    
    # linpeas to /opt/linpeas
	  echo -e "\n $greenplus Downloading all the linpeas from build $current_build"
    [ ! -d $dest_linpeas ] && mkdir $dest_linpeas || echo > /dev/null 
    
    linpeas_arr=('linpeas.sh' 'linpeas_darwin_amd64' 'linpeas_darwin_arm64' 'linpeas_fat.sh' 'linpeas_linux_386' 'linpeas_linux_amd64' 'linpeas_linux_arm')
     for linpeas_file in ${linpeas_arr[@]}; do
       echo -e "  $greenplus Downloading $linpeas_file to $dest_linpeas/$linpeas_file"
       wget -q $releases_url/$linpeas_file -O $dest_linpeas/$linpeas_file
       chmod +x $dest_linpeas/$linpeas_file 
     done

    # winpeas to /opt/winpeas
	  echo -e "\n $greenplus Downloading all the winpeas from build $current_build"
    [ ! -d $dest_winpeas ] && mkdir $dest_winpeas || echo > /dev/null 
    
    winpeas_arr=('winPEAS.bat' 'winPEASany.exe' 'winPEASany_ofs.exe' 'winPEASx64_ofs.exe' 'winPEASx86.exe' 'winPEASx86_ofs.exe')
     for winpeas_file in ${winpeas_arr[@]}; do
       echo -e "  $greenplus Downloading $winpeas_file to $dest_winpeas/$winpeas_file"
       # revision 1.7.4 static wget of the April 2023 release of Winpeas
       # due to github issue https://github.com/carlospolop/PEASS-ng/issues/359 
       wget -q https://github.com/carlospolop/PEASS-ng/releases/tag/20230419-b6aac9cb/$winpeas_file -O $dest_winpeas/$winpeas_file 
       # original code to be re-enabled once the winpeas group releases a fixed self-contained version
       # wget -q $releases_url/$winpeas_file -O $dest_winpeas/$winpeas_file
       chmod +x $dest_winpeas/$winpeas_file 
     done
    }


fix_assetfinder() {
    echo -e "\n  $greenplus Installing Assetfinder precompiled binary for $arch ... "
    [[ -f /usr/bin/assetfinder ]] && rm -f /usr/bin/assetfinder || echo > /dev/null
    eval apt -y reinstall assetfinder
    }

fix_httprobe() { # 01.04.22 - added httprobe precompiled binary to fix_missing
    if [ -f /usr/bin/httprobe ];
      then
        echo -e "\n  $greenminus skipping httprobe... already installed"
      else
        echo -e "\n  $greenplus installing httprobe"
        eval apt -y install httprobe
        echo -e "\n  $greenplus installed httprobe"
    fi
    }

fix_amass() {
    echo -e "\n  $greenplus installing amass for $arch "
    # 01.15.2023 rev 1.6.0 - Function updated for $arch detection amd64 or arm64 
    echo apt -y install amass 
    echo -e "\n  $greenplus amass installed"
    }

fix_pyftpdlib() {
    echo -e "\n  $greenplus installing pyftpdlib"
    eval pip install pyftpdlib
    echo -e "\n  $greenplus pyftpdlib installed"
    }

# 04.06.21 - rev 1.2.2 - add google-chrome due to gowitness dependancy
check_chrome(){
    [[ -f "/usr/bin/google-chrome" ]] && echo -e "\n  $greenminus google-chrome already installed - skipping  \n" || fix_chrome;
    }

# 04.06.21 - rev 1.2.2 - add google-chrome due to gowitness dependancy
fix_chrome() {
    if [[ "$arch" == "arm64" ]];
     then 
      echo -e "\n $redexclaim Google-Chrome is not available for this platform $arch -- skipping"
    elif [[ "$arch" == "amd64" ]];
     then 
      # need if statement here if arm64 , chrome does not exist in kali linux on arm64 as of yet
      echo -e "\n  $greenplus Gowitness dependancy fix: Downloading - google-chrome for $arch \n"
      eval wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb -O /tmp/google-chrome-stable_current_amd64.deb
      echo -e "\n  $greenplus Gowitness dependancy fix: Installing - google-chrome for $arch \n"
      eval apt -y install libu2f-udev
      eval dpkg -i /tmp/google-chrome-stable_current_amd64.deb
      rm -f /tmp/google-chrome-stable_current_amd64.deb
      # --- old code to be removed --- 
      # --- added as of revision 1.6.9a - changed installation source to kali repo 
      # --- disabled as a 1.7.1 google-chrome-stable no longer in the repo!! 
      # eval apt -y install google-chrome-stable
    fi 
    }

# 06.18.2021 - fix_hushlogin rev 1.2.9
fix_hushlogin() {
    echo -e "\n  $greenplus Checking for .hushlogin"
    if [ $finduser = "root" ]
     then
      if [ -f /root/.hushlogin ]
       then
        echo -e "\n  $greenminus /$finduser/.hushlogin exists - skipping"
      else
        echo -e "\n   $greenplus Creating file /$finduser/.hushlogin"
        touch /$finduser/.hughlogin
      fi
    else
      if [ -f /home/$finduser/.hushlogin ]
       then
        echo -e "\n  $greenminus /home/$finduser/.hushlogin exists - skipping"
      else
        echo -e "\n  $greenplus Creating file /home/$finduser/.hushlogin"
        touch /home/$finduser/.hushlogin
      fi
    fi
    }

# 06.18.2021 - disable_power_gnome rev 1.2.9
disable_power_gnome() {
    # CODE CONTRIBUTION : pswalia2u - https://github.com/pswalia2u
    fix_hushlogin
    echo -e "\n  $greenplus Gnome detected - Disabling Power Savings"
    # ac power
    sudo -i -u $finduser gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-type nothing      # Disables automatic suspend on charging)
     echo -e "  $greenplus org.gnome.settings-daemon.plugins.power sleep-inactive-ac-type nothing"
    sudo -i -u $finduser gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-timeout 0         # Disables Inactive AC Timeout
     echo -e "  $greenplus org.gnome.settings-daemon.plugins.power sleep-inactive-ac-timeout 0"
    # battery power
    sudo -i -u $finduser gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-battery-type nothing # Disables automatic suspend on battery)
     echo -e "  $greenplus org.gnome.settings-daemon.plugins.power sleep-inactive-battery-type nothing"
    sudo -i -u $finduser gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-battery-timeout 0    # Disables Inactive Battery Timeout
     echo -e "  $greenplus org.gnome.settings-daemon.plugins.power sleep-inactive-battery-timeout 0"
    # power button
    sudo -i -u $finduser gsettings set org.gnome.settings-daemon.plugins.power power-button-action nothing         # Power button does nothing
     echo -e "  $greenplus org.gnome.settings-daemon.plugins.power power-button-action nothing"
    # idle brightness
    sudo -i -u $finduser gsettings set org.gnome.settings-daemon.plugins.power idle-brightness 0                   # Disables Idle Brightness
     echo -e "  $greenplus org.gnome.settings-daemon.plugins.power idle-brightness 0"
    # screensaver activation
    sudo -i -u $finduser gsettings set org.gnome.desktop.session idle-delay 0                                      # Disables Idle Activation of screensaver
     echo -e "  $greenplus org.gnome.desktop.session idle-delay 0"
    # screensaver lock
    sudo -i -u $finduser gsettings set org.gnome.desktop.screensaver lock-enabled false                            # Disables Locking
     echo -e "  $greenplus org.gnome.desktop.screensaver lock-enabled false\n"
    }

# 06.18.2021 - disable_power_xfce rev 1.2.9 replaces fix_xfce_power fix_xfce_user and fix_xfce_root functions
disable_power_xfce() {
    if [ $finduser = "root" ]
     then
      echo -e "\n  $greenplus XFCE Detected - disabling xfce power management \n"
      eval wget $raw_xfce -O /root/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-power-manager.xml
      echo -e "\n  $greenplus XFCE power management disabled for user: $finduser \n"
    else
      echo -e "\n  $greenplus XFCE Detected - disabling xfce power management \n"
      eval wget $raw_xfce -O /home/$finduser/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-power-manager.xml
      echo -e "\n  $greenplus XFCE power management disabled for user: $finduser \n"
    fi
    }

# disable_power_kde() {
#    # need to work up a kde power management solution before implementing
# }

# 06.18.2021 - disable_power_checkde rev 1.2.9
disable_power_checkde() {
    detect_xfce=$(ps -e | grep -c -E '^.* xfce4-session$')
    detect_gnome=$(ps -e | grep -c -E '^.* gnome-session-*')
    #detect_kde=$(ps -e | grep -c -E '^.* kded4$')
    [ $detect_gnome -ne 0 ] && detected_env="GNOME"
    [ $detect_xfce -ne 0 ] && detected_env="XFCE"
    # need to work up a kde power management solution before implementing
    # [ $detect_kde -ne 0 ] && detected_env="KDE"
    echo -e "\n  $greenplus Detected Environment: $detected_env"
    [ $detected_env = "GNOME" ] && disable_power_gnome
    [ $detected_env = "XFCE" ] && disable_power_xfce
    [ $detected_env = "" ] && echo -e "\n  $redexclaim Unable to determine desktop environment"
    # [ $detected_env = "KDE" ] && disable_power_kde
    }

# 02.02.21 - rev 1.1.8 - Turn off / Silence PCSPKR beep
silence_pcbeep() {
    echo -e "blacklist pcspkr" > /etc/modprobe.d/nobeep.conf
    echo -e "\n  $greenplus Terminal Beep Silenced! /etc/modprobe.d/nobeep.conf \n"
    }

fix_pipxlrd() {
    eval pip install xlrd==1.2.0 --upgrade
    eval pip3 install scapy==2.4.4 --upgrade
    # eval pip3 install xlrd --upgrade
    echo -e "\n  $greenplus python module : xlrd installed \n"
    }

# Thinking about this before implementation
# 07.02.21 - check_python check if python is symlinked to python2 if not, make it point to python2
# fix_python_version() {
#    # check if python is python2
#    # Meh.. rethink this...
#    is_python2=$(ls -la /bin/python | grep -i -c "python2")
#    # check if python is python3
#    is_python3=$(ls -la /bin/python | grep -i -c "python3")
#
#    if [ $is_python2 = 1 ]
#     then
#      echo -e "\n  $greenplus python is python2 - skipping "
#     else
#      if [ $is_python3 = 1 ]
#       then
#        echo -e "\n  $redminus python is python3 ... installing python-is-python2 \n\n"
#        eval apt -y install python-is-python2
#        echo -e "\n  $greenplus python is now python2 "
#       else
#        echo -e "\n  $redexclaim Unable to determine python value"
#      fi
#    fi
#    }

python-pip-curl() {
  # Adding in some checks
  # python3_version="$(python3 --version 2>&1 | awk '{print $2}')"
  # py3_major=$(echo "$python3_version" | cut -d'.' -f1)
  # py3_minor=$(echo "$python3_version" | cut -d'.' -f2)
  #
  # python_version="$(python --version 2>&1 | awk '{print $2}')"
  # py_major=$(echo "$python_version" | cut -d'.' -f1)
  # py_minor=$(echo "$python_version" | cut -d'.' -f2)
  #
  # pip_is_for_python_version="$(pip --version 2>&1 | awk '{print $6}' | tr -d ")")" #needs to be modified
  # pip_major=$(echo "$pip_is_for_python_version" | cut -d'.' -f1)
  # pip_minor=$(echo "$pip_is_for_python_version" | cut -d'.' -f2)
  #
  # pip3_is_for_python_version="$(pip3 --version 2>&1 | awk '{print $6}' | tr -d ")" )"
  # pip3_major=$(echo "$pip3_is_for_python_version" | cut -d'.' -f1)
  # pip3_minor=$(echo "$pip3_is_for_python_version" | cut -d'.' -f2)
  #
  # echo " Python3 is : $python3_version $py3_major $py3_minor "
  # echo " Python2 is : $python_version $py_major $py_minor "
  # echo " Pip is for : $pip_is_for_python_version $pip_major $pip_minor"
  # echo "Pip3 is for : $pip3_is_for_python_version $pip3_major $pip3_minor"
    check_pip=$(whereis pip | grep -i -c "/usr/local/bin/pip2.7")
    if [ $check_pip -ne 1 ]
     then
      echo -e "\n  $greenplus installing pip"
      # 01.26.2021 - get-pip.py throwing an error, commented out and pointed wget directly to the python2.7 get-pip.py
      eval curl https://raw.githubusercontent.com/pypa/get-pip/3843bff3a0a61da5b63ea0b7d34794c5c51a2f11/2.7/get-pip.py -o /tmp/get-pip.py $silent
      # make a python-is-python2 function out of this...
      echo -e "\n  $greenplus Symlinking /bin/python2.7 to /bin/python\n"
      [[ -f /bin/python2.7 ]] && ln -sf /bin/python2.7 /bin/python
      # ------- buildout this function at a later date
      eval python /tmp/get-pip.py $silent
      rm -f /tmp/get-pip.py
      eval pip --no-python-version-warning install setuptools
      # python2-pip installer is now removing /usr/bin/pip3 - new "feature" I guess... 09.01.2021
      [[ ! -f /usr/bin/pip3 ]] && echo -e "\n  $greenplus installing python3-pip"; apt -y reinstall python3-pip || echo -e "\n  $greenplus python3-pip exists in /usr/bin/pip3"
      echo -e "\n  $greenplus python-pip installed"
    else
      echo -e "\n  $greenminus python-pip already installed"
    fi
    }

 # section= must be exact name of package in kali repo
 # check= custom check for that particular item
 # type= set in fix_section based on eval of $check and $force
 # force= to override force / set force var
 # fix_section $section $check $force

# 01.26.2021 - rev 1.1.5 - Current version of spike throws undefined symbol error, revert to old version
# 01.15.2023 - rev 1.6.0 - Updated to use $arch variable for amd64 or arm64
fix_spike() {
    echo -e "\n  $greenplus Fix SPIKE "
    echo -e "\n  $greenplus removing SPIKE..."
    eval apt -y --allow-change-held-packages remove spike
    # curl --progress-bar
    eval wget https://old.kali.org/kali/pool/main/s/spike/spike_2.9-1kali6_$arch.deb -O /tmp/spike_2.9-1kali6_$arch.deb
    echo -e "\n  $greenplus installing spike 2.9 for $arch ... \n"
    eval dpkg -i /tmp/spike_2.9-1kali6_$arch.deb
    echo -e "\n  $greenplus spike 2.9 installed \n"
    rm -f /tmp/spike_2.9-1kali6_$arch.deb 
    echo -e "\n  $greenplus setting apt hold on spike package"
    eval apt-mark hold spike
    echo -e "\n  $greenplus apt hold placed on spike package"
    }

fix_liblibc() {
    # amd64 / x86_64
    if [[ "$arch" == "amd64" ]] 
     then 
      if [[ ! -f /usr/lib/x86_64-linux-gnu/liblibc.a ]]
       then
        ln -sf /usr/lib/x86_64-linux-gnu/libc.a /usr/lib/x86_64-linux-gnu/liblibc.a 
        echo -e "\n  $greenplus Fixing $arch liblibc.a symlink /usr/lib/x86_64-linux-gnu/liblibc.a"
       fi 
    fi

    # arm64 
    if [[ "$arch" == "arm64" ]]
     then 
      if [[ ! -f /usr/lib/aarch64-linux-gnu/liblibc.a ]]
       then 
        ln -sf /usr/lib/aarch64-linux-gnu/libc.a /usr/lib/aarch64-linux-gnu/liblibc.a 
        echo -e "\n  $greenplus Fixing $arch liblibc.a symlink.."
      fi
    fi 
}

fix_mitm6() {
    [[ -d /opt/mitm6 ]] && rm -rf /opt/mitm6 || git clone https://github.com/dirkjanm/mitm6 /opt/mitm6
    git clone https://github.com/dirkjanm/mitm6 /opt/mitm6
    cd /opt/mitm6
    pip3 install typing twisted --break-system-packages
    pip3 install -r requirements.txt --break-system-packages
    python3 setup.py install 
    fix_liblibc
    echo -e "\n  $greenplus MITM6 installed.. "
    }

fix_gowitness() {
    echo -e "\n  $greenplus Installing gowitness prebuilt binary...\n"
    rm -f /tmp/releases.gowitness > /dev/null
    check_chrome
    rm -f /usr/bin/gowitness > /dev/null 
    # 01.15.2023 rev 1.6.0 updated with $arch variable for amd64 or arm64 detected by pimpmykali  
    eval wget https://github.com/sensepost/gowitness/releases/download/2.4.1/gowitness-2.4.1-linux-$arch -O /usr/bin/gowitness
    chmod +x /usr/bin/gowitness
    rm -f /tmp/releases.gowitness > /dev/null
    }

fix_root_connectionrefused() {
    # fix root gedit connection refused
    echo -e "\n  $greenplus Adding root to xhost for $finduser display: xhost +SI:localuser:root \n"
    # 07.02.21 - may need to consider using the sudo -i -u $finduser here
    eval sudo -i -u $finduser xhost +SI:localuser:root
    eval xhost +SI:localuser:root
    echo -e "\n  $greenplus root added to xhost"
    }

fix_gedit() {
    section="gedit"
    check=$(whereis gedit | grep -i -c "gedit: /usr/bin/gedit")
    fix_section $section $check $force
    fix_root_connectionrefused
    }

fix_set() {
    # move these to their individual respecitive functions at a later date - 04.11.2021 rev 1.2.4
    eval apt -y install libssl-dev set gcc-mingw-w64-x86-64-win32
    }

fix_rockyou() {
    cd /usr/share/wordlists
    gzip -dqf /usr/share/wordlists/rockyou.txt.gz
    echo -e "\n  $greenplus gunzip /usr/share/wordlists/rockyou.txt.gz\n"
    }

locate() {
    section="locate"
    check=$(whereis locate | grep -i -c "locate: /usr/bin/locate")
    fix_section $section $check $force
    }

fix_htop() {
    section="htop"
    check=$(whereis htop | grep -i -c "htop: /usr/bin/htop")
    fix_section $section $check $force
    }

python3_pip() {
    # section="python3-pip"
    # check=$(python3 -m pip --version | grep -i -c "/usr/lib/python3/dist-packages/pip")
    # force=1
    # fix_section $section $check $force
    eval apt -y reinstall python3-pip
    }

seclists() {
    #section="seclists"
    # Function changed 01.15.2023 rev 1.6.0 many users were thinking the script was "stuck" with no info being displayed
    if [[ -d /usr/share/seclists ]];
     then
      echo -e "\n $greenplus /usr/share/seclists  already exists -- skipping"
     else
      echo -e "\n $greenplus Download Seclists to /tmp/SecLists.zip"
      eval wget https://github.com/danielmiessler/SecLists/archive/master.zip -O /tmp/SecList.zip
      echo -e "\n $greenplus Extracing /tmp/Seclists.zip to /usr/share/seclists"
      unzip -o /tmp/SecList.zip -d /usr/share/seclists
      rm -f /tmp/SecList.zip
      echo -e "\n $greenplus Seclists complete" 
    fi
    }

fix_nmap() {
    rm -f /usr/share/nmap/scripts/clamav-exec.nse
    echo -e "\n  $redminus /usr/share/nmap/scripts/clamav-exec.nse removed "
    eval wget https://raw.githubusercontent.com/nmap/nmap/master/scripts/clamav-exec.nse -O /usr/share/nmap/scripts/clamav-exec.nse $silent
    eval wget https://raw.githubusercontent.com/Dewalt-arch/pimpmykali/master/fixed-http-shellshock.nse -O /usr/share/nmap/scripts/http-shellshock.nse $silent
    echo -e "\n  $greenplus /usr/share/nmap/scripts/clamav-exec.nse replaced with working version "
    }

fix_flameshot() {
    section="flameshot"
    check=$(whereis flameshot | grep -i -c "/usr/bin/flameshot")
    fix_section $section $check $force
    }

# 02.02.21 - rev 1.1.8 - install theharvester
fix_theharvester() {
    section="theharvester"
    check=$(whereis theharvester | grep -i -c "/usr/bin/theharvester")
    fix_section $section $check $force
    }

fix_golang() {
    section="golang"  #check this golang or golang-go?
    check=$(whereis go  | grep -i -c "/usr/bin/go")
    fix_section $section $check $force
    fix_go_path
    }

fix_go_path() {
    # added gonski fix - 01.21.22 rev 1.4.2
    # --- This needs to be moved to a Global from a local as it is reused at line 1165 ---
    # Why am I not using $finduser here?
    check_for_displayzero=$(who | grep -c "(\:0)")
    if [ $check_for_displayzero == 1 ]
     then
      findrealuser=$(who | grep "(\:0)" | awk '{print $1}')
      echo -e "\n  $greenplus getting user from display 0 (:0) : $findrealuser"
    else
      findrealuser=$(who | grep "tty[0-9]" | sort -n | head -n1 | awk '{print $1}')
      echo -e "\n  $greenplus display0 not found getting user from tty : $findrealuser"
    fi
     # above is the Gonski Fix, Gonski was getting 'kali kali' in $findrealuser the original "who | awk '{print $1}'" statement
     # with a kali user on tty7 (:0) and then kali pts/1, as pimpmykali.sh is being run with sudo and was producing this fault
     # this will resolve the issue either logged into x11 on display 0 or just in a terminal on a tty
     # --- Move the above to a global from a local as it is reused on line 1165 ----
    if [ $findrealuser == "root" ]
     then
      check_root_zshrc=$(cat /root/.zshrc | grep -c GOPATH)
      [ -d /$findrealuser/go ] && echo -e "\n  $greenminus go directories already exist in /$findrealuser" || echo -e "\n  $greenplus creating directories /$findrealuser/go /$findrealuser/go/bin /$findrealuser/go/src"; mkdir -p /$findrealuser/go/{bin,src}
       if [ $check_root_zshrc -ne 0 ]
         then
          echo -e "\n  $redminus GOPATH Variables for $findrealuser already exist in /$findrealuser/.zshrc - Not changing"
         else
          echo -e "\n  $greenplus Adding GOPATH Variables to /root/.zshrc"
          eval echo -e 'export GOPATH=\$HOME/go' >> /root/.zshrc
          eval echo -e 'export PATH=\$PATH:\$GOPATH/bin' >> /root/.zshrc
       fi
      check_root_bashrc=$(cat /root/.bashrc | grep -c GOPATH)
       if [ $check_root_bashrc -ne 0 ]
        then
         echo -e "\n  $redminus GOPATH Variables for $findrealuser already exist in /$findrealuser/.bashrc - Not changing"
        else
         echo -e "\n  $greenplus Adding GOPATH Variables to /root/.bashrc"
         eval echo -e 'export GOPATH=\$HOME/go' >> /root/.bashrc
         eval echo -e 'export PATH=\$PATH:\$GOPATH/bin' >> /root/.bashrc
       fi
     else
      check_user_zshrc=$(cat /home/$findrealuser/.zshrc | grep -c GOPATH)
       [ -d /home/$findrealuser/go ] && echo -e "\n  $greenminus go directories already exist in /home/$finduser" || echo -e "\n  $greenplus creating directories /home/$findrealuser/go /home/$findrealuser/go/bin /home/$findrealuser/go/src"; mkdir -p /home/$findrealuser/go/{bin,src}; chown -R $findrealuser:$findrealuser /home/$findrealuser/go
       if [ $check_user_zshrc -ne 0 ]
        then
         echo -e "\n  $redminus GOPATH Variables for user $findrealuser already exist in /home/$findrealuser/.zshrc  - Not Changing"
        else
         echo -e "\n  $greenplus Adding GOPATH Variables to /home/$findrealuser/.zshrc"
         eval echo -e 'export GOPATH=\$HOME/go' >> /home/$findrealuser/.zshrc
         eval echo -e 'export PATH=\$PATH:\$GOPATH/bin' >> /home/$findrealuser/.zshrc
       fi
      check_user_bashrc=$(cat /home/$findrealuser/.bashrc | grep -c GOPATH)
       if [ $check_user_bashrc -ne 0 ]
        then
         echo -e "\n  $redminus GOPATH Variables for user $findrealuser already exist in /home/$findrealuser/.bashrc - Not Changing"
        else
         echo -e "\n  $greenplus Adding GOPATH Variables to /home/$findrealuser/.bashrc"
         eval echo -e 'export GOPATH=\$HOME/go' >> /home/$findrealuser/.bashrc
         eval echo -e 'export PATH=\$PATH:\$GOPATH/bin' >> /home/$findrealuser/.bashrc
       fi
    fi
    }

fix_smbconf() {
    check_min=$(cat /etc/samba/smb.conf | grep -c -i "client min protocol")
    check_max=$(cat /etc/samba/smb.conf | grep -c -i "client max protocol")
    if [ $check_min -ne 0 ] || [ $check_max -ne 0 ]
     then
      echo -e "\n  $green /etc/samba/smb.conf "
      echo -e "\n  $redminus client min protocol is already set not changing\n  $redminus client max protocol is already set not changing"
    else
      sed 's/\[global\]/\[global\]\n   client min protocol = CORE\n   client max protocol = SMB3\n''/' -i /etc/samba/smb.conf
      echo -e "\n  $greenplus /etc/samba/smb.conf updated"
      echo -e "\n  $greenplus added : client min protocol = CORE\n  $greenplus added : client max protocol = SMB3"
    fi
    }

fix_grub() {
    check_grub=$(cat /etc/default/grub | grep -i -c "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"" )
    if [ $check_grub -ne 1 ]
     then
      echo -e "\n  $redexclaim Error: /etc/default/grub is not the default config - not changing"
    else
      sed 's/GRUB_CMDLINE_LINUX_DEFAULT="quiet"/GRUB_CMDLINE_LINUX_DEFAULT="quiet mitigations=off"/' -i /etc/default/grub
      update-grub
      echo -e "\n  $greenplus Added mitigations=off to GRUB_CMDLINE_LINUX_DEFAULT"
      echo -e "\n  $redexclaim Reboot for changes to take effect \n"
    fi
    }

fix_python_requests() {
    #eval git clone https://github.com/psf/requests /opt/requests
    #cd /opt/requests
    eval pip install colorama termcolor service_identity requests==2.2.1
    echo -e "\n  $greenplus installed python2 module : colorama"
    #eval pip install .
    echo -e "\n  $greenplus installed python2 module : requests"
    }

fix_bad_apt_hash() {
    mkdir -p /etc/gcrypt
    echo "all" > /etc/gcrypt/hwf.deny
    }

# Update this function with the new fork as atom was deprecated
# install_atom () {
#    if [ -f /usr/bin/atom ]
#     then
#      echo -e "\n  $greenminus atom already installed - skipping"
#    else
#      apt_update  && apt_update_complete
#      echo -e "\n  $greenplus downloading atom"
#      eval wget https://atom.io/download/deb -O /tmp/atom.deb $silent
#      echo -e "\n  $greenplus installing atom"
#      eval dpkg -i /tmp/atom.deb $silent
#      eval rm -f /tmp/atom.deb $silent
#      eval apt -y --fix-broken install $silent
#    fi
#    }

install_sublime() {
    echo -e "\n  $greenplus installing sublime text editor"
    # code fix provided by aashiksamuel
    eval wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | gpg --no-default-keyring --keyring ./temp-keyring.gpg --import
    eval gpg --no-default-keyring --keyring ./temp-keyring.gpg --export --output sublime-text.gpg
    eval rm temp-keyring.gpg temp-keyring.gpg~
    eval mkdir -p /usr/local/share/keyrings
    eval mv ./sublime-text.gpg /usr/local/share/keyrings
    eval apt-get install apt-transport-https
    eval echo "deb [signed-by=/usr/local/share/keyrings/sublime-text.gpg] https://download.sublimetext.com/ apt/stable/" > /etc/apt/sources.list.d/sublime-text.list
    apt_update && apt_update_complete
    eval apt -y install sublime-text
    }

# 06.01.21 - Function rewrite code-oss was added to Kali 2021.2 repo
install_vscode() {
    if [[ -f /usr/bin/code ]]; then
      echo -e "\n  $greenminus  vscode already installed - skipping"
    else
    	echo -e "\n  $greenplus installing vscode"
      apt_update && apt_update_complete && apt -y install code-oss
      echo -e "\n  $greenplus  vscode - installed "
    fi
    }

# 04.06.2021 fix_sources rev 1.2.2 / rev 1.3.2 updated to add wildcards
fix_sources() {
    fix_bad_apt_hash
    # relaxed grep
    check_space=$(cat /etc/apt/sources.list | grep -c "# deb-src http://.*/kali kali-rolling.*")
    check_nospace=$(cat /etc/apt/sources.list | grep -c "#deb-src http://.*/kali kali-rolling.*")
    get_current_mirror=$(cat /etc/apt/sources.list | grep "deb-src http://.*/kali kali-rolling.*" | cut -d "/" -f3)
    if [[ $check_space = 0 && $check_nospace = 0 ]]; then
    	echo -e "\n  $greenminus # deb-src or #deb-sec not found - skipping"
    elif [ $check_space = 1 ]; then
      echo -e "\n  $greenplus # deb-src with space found in sources.list uncommenting and enabling deb-src"
      # relaxed sed
      sed 's/\# deb-src http\:\/\/.*\/kali kali-rolling.*/\deb-src http\:\/\/'$get_current_mirror'\/kali kali-rolling main contrib non\-free''/' -i /etc/apt/sources.list
      echo -e "\n  $greenplus new /etc/apt/sources.list written with deb-src enabled"
    elif [ $check_nospace = 1 ]; then
      echo -e "\n  $greenplus #deb-src without space found in sources.list uncommenting and enabling deb-src"
      # relaxed sed
      sed 's/\#deb-src http\:\/\/.*\/kali kali-rolling.*/\deb-src http\:\/\/'$get_current_mirror'\/kali kali-rolling main contrib non\-free''/' -i /etc/apt/sources.list
      echo -e "\n  $greenplus new /etc/apt/sources.list written with deb-src enabled"
    fi
    }

run_update() {
    fix_sources
    echo -e "\n  $greenplus starting: pimpmyupgrade   \n"
    apt_update && apt_update_complete
    kernel_check=$(ls /lib/modules | sort -n | tail -n 1)
    echo -e "\n  $greenplus installing dkms build-essential linux-headers-$kernel_check \n"
    eval apt -y install dkms build-essential linux-headers-amd64 $silent
    }

make_rootgreatagain() {
    echo -e "\n\n KALI-ROOT-LOGIN INSTALLATION: - PAGE 1   "$red"*** READ CAREFULLY! ***"$white" \n"
    echo -e "   On Kali 2019.x and prior the default user was root"
    echo -e "   On Kali 2020.1 and newer this was changed, the default user was changed to be "
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
        n|N) echo -e "\n\n $redexclaim skipping root login setup" ;;
        *) echo -e "\n invalid key try again Y or N"; make_rootgreatagain;;
    esac
    }

enable_rootlogin() {
    section="kali-root-login"
    check=$(whereis kali-root-login | grep -i -c "kali-root-login: /usr/share/kali-root-login")
    fix_section $section $check $force
    echo -e "\n\nEnabling Root Login Give root a password"
    passwd root
    if [ "$?" -ne 0 ]
     then
      echo -e "\n  $redexclaim - Passwords did not match - restarting this function"
      enable_rootlogin
    else
      echo -e "\n  $greenplus - Password updated"
    fi
    echo -e "\n  $greenplus root login enabled \n"
    ask_homekali_to_root
    }

# 01.02.2021 - rev 1.1.2 begin - new screens for copying from /home/kali to /root, no detection, all based on used input
ask_homekali_to_root() {
    echo -e "\n\n KALI-ROOT-LOGIN INSTALLATION: - PAGE 2   "$red"*** READ CAREFULLY! ***"$white" \n"
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
        n|N) echo -e "\n\n  $redexclaim skipping copy of /home/$finduser to /root" ;;
        *) echo -e "\n\n  $redexclaim Invalid key try again, Y or N keys only $redexclaim"; ask_homekali_to_root;;
      esac
    }

# 01.03.2021 - rev 1.1.3 begin - added are you sure prompt
ask_are_you_sure() {
    echo -e "\n\n   Are you sure you want to copy all of /home/$finduser to /root ?"
    read -n1 -p "   Please type Y or N : " userinput
     case $userinput in
       y|Y) perform_copy_to_root;;
       n|N) echo -e "\n\n  $redexclaim skipping copy of /home/$finduser to /root - not copying ";;
         *) echo -e "\n\n  $redexclaim Invalid key try again, Y or N keys only $redexclaim"; ask_are_you_sure;;
     esac
    }

# 01.02.2021 - rev 1.1.2 - copy to /root warning screens and function
perform_copy_to_root() {
    echo -e "\n\n  $greenplus Copying everything from /home/$finduser to /root... Please wait..."
    # add call to check_helpers here before doing the copy from /home/kali to /root
     if [[ $finduser = "root" ]]
      then
       echo -e "Your already root!"
     else
       # [[ ! -d /root/Desktop ]] && cp -RVf /home/$findrealuser/kali/Desktop /root/Desktop
       echo -e "\n\n cp -Rvf /home/$finduser/.* /home/$finduser/* \n\n"
       eval cp -Rvf /home/$finduser/.* /home/$finduser/* /root >/dev/null 2>&1
       eval chown -R root:root /root
       echo -e "\n  $greenplus Everything from /home/$finduser has been copied to /root"
     fi
    }

# check_helpers() {
  # check /home/kali/.config/xfce4/helpers.rc for default settings of WebBrowser TerminalEmulator FileManager
  # may need this in the copy to root function above , code is commented out and only a place holder currently
  # if /root/.config/xfce4/helpers.rc AND /home/kali/.config/xfce4/helpers.rc does not exist create a new file for /root/.config/xfce4/helpers.rc
#    if [ -f /home/kali/.config/xfce4/helpers.rc ]
#     then
#      check_browser=$(cat /home/kali/.config/xfce4/helpers.rc | grep -c "WebBrowser")
#      if [ $check_browser = 1 ]
#       then
#        check_which_browser=$(cat /home/kali/.config/xfce4/helpers.rc | grep "WebBrowser" | cut -d "=" -f2)
#        echo "WebBrowser is set and default browser is $check_which_browser"
#      else
#        echo "Browser is not set"
#      fi
#
#      check_terminal=$(cat /home/kali/.config/xfce4/helpers.rc | grep -c "TerminalEmulator")
#      if [ $check_terminal = 1 ]
#       then
#        check_which_terminal=$(cat /home/kali/.config/xfce4/helpers.rc | grep  "TerminalEmulator" | cut -d "=" -f2)
#        echo "TerminalEmulator is set and default terminal is $check_which_terminal"
#       else
#        echo "Default TerminalEmulator is not set"
#      fi
#
#      check_filemanager=$(cat /home/kali/.config/xfce4/helpers.rc | grep -c "FileManager")
#      if [ $check_filemanager = 1 ]
#       then
#        check_which_filemanager=$(cat /home/kali/.config/xfce4/helpers.rc | grep "FileManager" | cut -d "=" -f2)
#        echo "FileManager is set and default file manager is $check_which_filemanager"
#       else
#        echo "Default FileManager is not set"
#      fi
#     else
#      echo "/home/kali/.config/xfce4/helpers.rc does not exist - do something about it"
#    fi
#   }


fix_sead_warning() {
    clear
 # fugly - really need to clean this up, it works but its just a nightmare to look at
 echo -e "

 "$bold$redexclaim$red" WARNING "$redexclaim$bold$red"  PIMPMYKALI IMPACKET REMOVAL FUNCTION  "$redexclaim$bold$red" WARNING "$redexclaim$white$norm"

                 *** READ FULLY BEFORE PRESSING ANY KEY ***

   "$red"DISCLAIMER:"$white" This is a last resort effort to remove impacket from the system
   and install a clean working install of impacket-0.9.19 and should be only
   used as such. This is for only if you screwed up your impacket as bad as
   Bobloblaw (Blob) did!! (thank you blob! you are the wind beneath my impacket
   removal scripts!)

   This function of pimpmykali is reserved for the most severe cases of broken
   impacket installs, multiple impacket installs, etc, and will attempt to
   clean the system of impacket and any related files that may be preventing
   a clean and working install of impacket-0.9.19

   It is not possible to forsee every possible scenario but this makes a best
   attempt of the most common dirs and files to clean your system to remove
   anything impacket related only from the areas listed below.

   This WILL RECURSIVLY DELETE ANY DIR NAMED impacket* from the following:
    /opt  /usr/bin  /usr/local/lib  /usr/lib  /home/$finduser/.local/bin
    /home/$finduser/.local/lib  /root/.local/lib  /root/.local/bin

   AND ANY related .py and .pyc files from impacket in the following:
    /usr/bin  /local/local/bin  /root/.local/bin  /home/$finduser/.local/bin

   After this function completes the following will be run automatically
    sudo ./pimpmykali.sh --impacket

   Answering only Y to the following prompt will preform the above actions,
   pressing ANY OTHER KEY WILL EXIT

   "
    read -n1 -p " Press Y to execute or any other key to exit: " fixsead_userinput
    case $fixsead_userinput in
        y|Y) fix_sead_run ;;
        *) exit ;;
    esac
    }

fix_sead_run() {
    apt_update && apt_update_complete
    python-pip-curl
    python3_pip
    eval pip  uninstall impacket -y $silent
    eval pip3 uninstall impacket -y --break-system-packages $silent 
    SEAD=$(find /opt /usr/bin /usr/local/lib /usr/lib /home/$finduser/.local/bin /home/$finduser/.local/lib ~/.local/lib ~/.local/bin -name impacket* 2> /dev/null)
    # Last Chance Launch Sequence ** WARNING SCREEN ** and 10 second time out
    # may consider removing this.... 2nd warning screen
    #    clear
    #    echo -e "  If you've made it this far you're having a really bad day with impacket... "
    echo -e "  Enjoy the last chance launch sequence!\n"
    echo -e "  Preparing to nuke Impacket... \n"
    echo -e "  $green[....]$white acquiring targets \n"
    echo -e "  $green[$red+$green..$red+$green]$white targets selected\n$SEAD \n"
    echo -e "  $green[-$red++$green-]$white targets locked \n"
    echo -e "  $green[++++]$white systems ready \n"
    echo -e "  $green[<$red@@$green>]$white taking aim \n"
    echo -e "  $green[$red####$green]$white requesting NukeImpacket launch codes \n"
    echo -e "  $green[$red$launch_codes_alpha-$launch_codes_beta-$launch_codes_charlie$green]$white launch code confirmed"
    #    echo -e "  Are you sure you meant to run this script?\n"
    #    temp_cnt=${wait_time}
    #     while [[ ${temp_cnt} -gt 0 ]];
    #       do
    #         printf "\r  You have %2d second(s) remaining to hit Ctrl+C to cancel this operation!" ${temp_cnt}
    #         sleep 1
    #         ((temp_cnt--))
    #      done
    #    echo -e "\n\n  No user input detected... Executing!!"
    echo -e "\n  $fourblinkexclaim *** FIRE!! *** $fourblinkexclaim\n"
    echo -e "  $redstar function running removing :\n$SEAD\n"
    rm -rf $SEAD
    fix_impacket_array
    fix_impacket
    exit_screen
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

fix_impacket() {
    python-pip-curl
    python3_pip
    eval pip uninstall impacket -y $silent
    eval pip3 uninstall impacket --break-system-packages -y $silent
    fix_impacket_array
    eval wget https://github.com/SecureAuthCorp/impacket/releases/download/impacket_0_9_19/impacket-0.9.19.tar.gz -O /tmp/impacket-0.9.19.tar.gz $silent
    eval tar xfz /tmp/impacket-0.9.19.tar.gz -C /opt $silent
    cd /opt
    chown -R root:root impacket-0.9.19
    chmod -R 755 impacket-0.9.19
    cd /opt/impacket-0.9.19
    eval pip install -r requirements.txt
    eval /bin/python2.7 ./setup.py install 
    sudo -i -u $findrealuser pip install ldap3==2.5.1
    pip install ldap3==2.5.1
    rm -f /tmp/impacket-0.9.19.tar.gz
    eval apt -y reinstall python3-impacket impacket-scripts $silent
    #sudo -i -u $finduser python3 -m pip install impacket --user --upgrade --break-system-packages
    echo -e "\n  $greenplus installed: impacket-0.9.19 python-pip wheel impacket flask pyasn1"
    echo -e "\n  $greenplus installed: lsassy pycryptodomes pyOpenSSL ldap3 ldapdomaindump"
    echo -e "\n  $greenplus installed: python3-pip python3-impacket impacket-scripts"
    }

fix_broken_xfce() {
    echo -e "\n  $greenplus Applying broken XFCE Fix  \n "
    eval apt -y reinstall xfce4-settings
    echo -e "\n  $greenplus Broken XFCE Fix applied: xfce4-settings reinstalled  \n"
    fix_xfcepower
    }

only_upgrade() {
    fix_sources
    echo -e "\n  $greenplus starting pimpmyupgrade   \n"
    apt_update && apt_update_complete && apt_upgrade && apt_upgrade_complete
    run_update
    virt_what
    check_vm
    }

fix_upgrade() {
    fix_sources
    apt_update && apt_update_complete
    run_update
    apt_upgrade && apt_upgrade_complete
    virt_what
    check_vm
    }

bpt() {
    rm -rf /opt/the-essentials
    git clone https://github.com/blindpentester/the-essentials /opt/the-essentials
    cd /opt/the-essentials
    sh -c '/opt/the-essentials/the_essentials.sh --skip'
    exit_screen
    }

# Upgraded virt-what function - 04.07.2021 rev 1.2.2
# 01.15.2023 - Virt-What installed much earlier in the script, function is now redundant
virt_what() {
    [ -f "/usr/sbin/virt-what" ] && virtwhat=1 || virtwhat=0

    if [ $virtwhat = 1 ]
     then
       echo -e "\n  $greenminus virt-what already installed - skipping \n"
    else
       echo -e "\n  $greenplus installing virt-what \n"
       eval apt -y install virt-what $silent
    fi
    }

vbox_fix_shared_folder_permission_denied() {
    if [ $findgroup = 1 ]
     then
      echo -e "\n  $greenminus : user is already a member of vboxsf group\n"
    else
      eval adduser $finduser vboxsf
      echo -e "\n  $greenplus fix applied : virtualbox permission denied on shared folder"
      echo -e "       user added to vboxsf group "
    fi
    }

fix_virtualbox() {
    ## added for revision 0.5i ##
    eval mkdir /tmp/vboxtmp
    eval apt -y reinstall virtualbox-dkms virtualbox-guest-x11 $silent
    # virtualbox-guest-additions-iso virtualbox-guest-x11 $silent
    # virtualbox-guest-additions-iso leaving so it gets installed and we dont have to create a bunch of dirs
    # may not need the following once the kali repo is updatedf
    # may keep this function as is, so it is always getting the most updated version from Oracle not the Kali Repo
    # which seems to lag behind
    #
    # Side Step the Kali Repo as it is the wrong version not current
    # This will always pull the latest version from download.virtualbox.org/virtualbox/LATEST
     # check version
     eval wget https://download.virtualbox.org/virtualbox/LATEST.TXT -O /tmp/vbox-latest
     vboxver=$(cat /tmp/vbox-latest)
     # get new iso and place over old one in /usr/share/virtualbox
     eval wget https://download.virtualbox.org/virtualbox/$vboxver/VBoxGuestAdditions_$vboxver.iso -O /usr/share/virtualbox/VBoxGuestAdditions.iso
     # end of sidestep
    eval mount /usr/share/virtualbox/VBoxGuestAdditions.iso /tmp/vboxtmp
    eval cp -f /tmp/vboxtmp/VBoxLinuxAdditions.run /tmp/VBoxLinuxAdditions.run
    eval umount /tmp/vboxtmp
    eval rmdir /tmp/vboxtmp
    eval chmod +x /tmp/VBoxLinuxAdditions.run
    eval /tmp/VBoxLinuxAdditions.run install --force
    eval rm -f /tmp/VBoxLinuxAdditions.run
    eval /sbin/rcvboxadd quicksetup all
    echo -e "\n  $redstar A reboot of your system is required"
    }

check_vm() {
    echo -e "\n  $greenplus detecting hypervisor type \n"
    vbox_check=$(virt-what | grep -i -c "virtualbox")    # virtualbox check
    vmware_check=$(virt-what | grep -i -c "vmware")      # vmware check - vmware check works on Mac VMWare Fusion
    qemu_check=$(virt-what | grep -i -c "qemu\|kvm")     # m4ul3r Qemu/libvirt check
    if [ $vbox_check = 1 ]
      then
        echo -e "\n  $greenplus *** VIRTUALBOX DETECTED *** \n"
        echo -e "\n  $greenplus installing virtualbox-dkms virtualbox-guest-additions-iso virtualbox-guest-x11"
           # call fix_virtualbox function
           # Additional Fixes for virtualbox
           #----------------------- additional virtualbox fixes
             fix_virtualbox
             vbox_fix_shared_folder_permission_denied
           #----------------------- end of virtualbox additional fixes
           # exit_screen
      elif  [ $vmware_check = 1 ]
        then
          echo -e "\n  $greenplus *** VMWARE DETECTED *** \n"
          echo -e "\n  $greenplus installing open-vm-tools-desktop fuse"
          eval apt -y remove fuse
          eval apt -y reinstall open-vm-tools-desktop fuse3 $silent
          # echo -e "\n  $greenplus restarting vmware tools"
          # eval restart-vm-tools
          # Additional Fixes for Vmware
          #----------------------- additional vmware fixes
          #
          #----------------------- end of vmware additional fixes
          # exit_screen
       elif  [ $qemu_check = 1 ]
         then
          echo -e "\n  $greenplus *** QEMU/LIBVIRT DETECTED *** \n"
          eval apt -y reinstall spice-vdagent qemu-guest-agent
          # xserver-xorg-video-qxl - rev 1.5.4 no longer in the kali repo
          echo -e "\n  $greenplus installing xserver-xorg-video-qxl spice-vdagent"
      else
        echo -e "\n $redstar Hypervisor not detected, Possible bare-metal installation not updating"
    fi
    }

hacking_api_create_cleanupsh() { 
    cleanup_script="cleanup.sh"
    echo -e "\n  $greenplus Creating cleanup.sh" 
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
    echo -e "\n  $greenplus Creating start-api-hacking.sh"
    echo -e "#!/bin/bash" > $startup_script
    echo -e "\n" >> $startup_script
    echo -e "cd ~/labs/crAPI/deploy/docker" >> $startup_script 
    echo -e "sudo VERSION=develop docker-compose -f docker-compose.yml pull" >> $startup_script
    echo -e "sudo VERSION=develop docker-compose -f docker-compose.yml --compatibility up -d" >> $startup_script
    chmod +x start-api-hacking.sh
    }    
    
# code commented out for now, debtaing the idea of a postman desktop icon 
# would require it to be placed in either /$finduser/Desktop (root)  or  /home/$finduser/Desktop (normal user)
# create_postman_desktopicon() {
#    echo "[Desktop Entry]" > Postman.desktop
#    echo "Version=1.0" >> Postman.desktop
#    echo "Type=Application" >> Postman.desktop
#    echo "Name=Postman" >> Postman.desktop
#    echo "Comment=Postman" >> Postman.desktop
#    echo "Exec=/usr/bin/postman" >> Postman.desktop
#    echo "Icon=postman" >> Postman.desktop
#    echo "Path=" >> Postman.desktop
#    echo "Terminal=false" >> Postman.desktop
#    echo "StartupNotify=false" >> Postman.desktop
#    }

hacking_api_prereq() {
    # additions to PMK 1.6.6 - Practical API Hacking course setup 
    # common setup
    echo -e "\n  $greenplus Running apt update" 
    eval apt update $silent
    echo -e "\n  $greenplus Installing docker.io docker-compose"
    eval apt -y install docker.io docker-compose $silent 
    echo -e "\n  $greenplus Enabling docker services (systemctl enable docker)"
    systemctl enable docker 
    # determine arch type and download the respective postman for that arch
    if [ $arch == "amd64" ]
     then 
      echo -e "\n  $greenplus Downloading Postman for $arch"
      wget https://dl.pstmn.io/download/latest/linux_64 -O /opt/postman.tar.gz
    elif [ $arch == "arm64" ]
     then
      wget https://dl.pstmn.io/download/latest/linux_arm64 -O /opt/postman.tar.gz
    elif [ $arch == "" ]
     then
      echo -e "\n  $redexclaim Unable to determine arch type, exiting..." 
      exit 
    fi 
    #install postman and symlink to /usr/bin/postman to be in $PATH
    echo -e "\n  $greenplus Installing Postman"
    cd /opt 
    tar xvfz postman.tar.gz $silent 
    ln -sf /opt/Postman/Postman /usr/bin/postman
    rm /opt/postman.tar.gz
    # user specific setup 
    if [ $finduser == "root" ]
     then 
      if [ ! -d /$finduser/labs ]
       then 
        echo -e "\n  $greenplus Creating labs directory /$finduser/labs"
        mkdir /$finduser/labs
      fi 
      cd /$finduser/labs
      echo -e "\n  $greenplus Installing crAPI to /$finduser/labs/crAPI"
      git clone https://github.com/OWASP/crAPI $silent 
      # create cleanup.sh in the crAPI directory
      hacking_api_create_cleanupsh
       cd /$finduser/labs/crAPI/deploy/docker
     else 
      if [ ! -d /home/$finduser/labs ]
       then 
       echo -e "\n  $greenplus Creating labs directory /home/$finduser/labs"
       mkdir /home/$finduser/labs
      fi 
      cd /home/$finduser/labs
      echo -e "\n  $greenplus Installing crAPI to /home/$finduser/labs/crAPI"
      git clone https://github.com/OWASP/crAPI $silent 
      # create cleanup.sh in the crAPI directory
      hacking_api_create_cleanupsh 
      chmod +x cleanup.sh
      chown -R $finduser:$finduser /home/$finduser/labs
      cd /home/$finduser/labs/crAPI/deploy/docker
    fi
    chmod -R 777 $HOME/peh/labs $HOME/peh/labs/* 
    echo -e "\n  $greenplus Please cd $PWD"
    echo -e "       and run the following command : sudo docker-compose up "
    }  

check_nessusd_active() {
    check_nessusd_service=$(sudo systemctl status nessusd | grep -i -c  "active (running)")
    if [[ $check_nessusd_service -ge 1 ]]
     then
      nessusd_service_active=1
      echo -e "\n  $greenplus nessusd service is active"
     else
      nessusd_service_active=0
      echo -e "\n  $redexclaim nessusd service is not active"
    fi
    }

check_nessus_installed_opt_nessus() {
    if [[ -d /opt/nessus ]]
    then 
     echo -e "\n  $greenplus Detected nessus installation at /opt/nessus"
     echo -e "\n  $greenplus Removing all files from /opt/nessus"
     rm -rf /opt/nessus
    else
     echo -e "\n  $greenplus Nessus not detected at /opt/nessus"
    fi 
    }

check_nessus_installed_dpkg() (
    dpkg_nessus=$(dpkg -l | grep -i -c nessus)
    if [ $dpkg_nessus -ge 1 ]
     then 
      echo -e "\n  $greenplus Detected nessus installed via dpkg -l" 
      echo -e "\n  $greenplus Removing Nessus via dpkg -r"
      dpkg -r Nessus
     else 
      echo -e "\n  $greenplus No detectinon of nessus installed via dpkg"
    fi
    )

nuke_nessus() {
    check_nessusd_active
    if [ $nessusd_service_active -ge 1 ]
     then 
      echo -e "\n  $greenplus Stopping nessusd service"
      systemctl stop --now nessusd
      check_nessus_installed_dpkg
      check_nessus_installed_opt_nessus
      echo -e "\n  $greenplus Nessus has been removed"
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
          *) echo -e "\n  $greenplus Aborting uninstallation of nessus"; exit;;
      esac
     else
      echo -e "\n  $redexclaim nessusd service is not running"
    fi
    }

install_nessus() {
    # code to check if nessus is already installed and build out a remove function
    if [ $arch == "amd64" ]
      then
      nessus_amd64_file=$(curl https://www.tenable.com/downloads/nessus\?loginAttempted\=true | grep -o -m1 -E "Nessus-[0-9]{1,2}.[0-9]{1}.[0-9]{1}-debian10_amd64.deb" | grep -m1 -i ".deb")
      nessus_amd64="https://www.tenable.com/downloads/api/v2/pages/nessus/files/$nessus_amd64_file"
     
      echo -e "\n  $greenplus Downloading Nessus for $arch"
      wget -q $nessus_amd64 -O /tmp/nessus_amd64.deb
      echo -e "\n  $greenplus Installing Nessus for $arch"
      dpkg -i /tmp/nessus_amd64.deb
      rm -f /tmp/nessus_amd64.deb
      echo -e "\n  $greenplus Enabling nessusd service"
      systemctl enable --now nessusd
      check_nessusd_active
    elif [ $arch == "arm64" ]
     then
      nessus_arm64_file=$(curl https://www.tenable.com/downloads/nessus\?loginAttempted\=true | grep -o -m1 -E "Nessus-[0-9]{1,2}.[0-9]{1}.[0-9]{1}-ubuntu[0-9]{1,4}_aarch64.deb" | grep -m1 -i ".deb")
      nessus_arm64="https://www.tenable.com/downloads/api/v2/pages/nessus/files/$nessus_arm64_file"
      
      echo -e "\n  $greenplus Downloading Nessus for $arch"
      wget $nessus_arm64 -O /tmp/nessus_arm64.deb
      echo -e "\n  $greenplus Installing Nessus for $arch"
      dpkg -i /tmp/nessus_arm64.deb
      rm -f /tmp/nessus_arm64.deb
      echo -e "\n  $greenplus Enabling nessusd service" 
      systemctl enable --now nessusd
      check_nessusd_active
    elif [ $arch == "" ]
     then
      echo -e "\n  $redexclaim Unable to determine arch type, exiting..." 
      exit
    fi
    }

mapt_prereq() {
    # would like to do a check of python2 pip python3 and pip3 instead of just re-running python-pip-curl and python3_pip functions
    # modifiy the python-pip-curl function and the python3_pip functions instead
    python-pip-curl
    python3_pip
    apt_update
    echo -e "\n  $greenplus Installing tools for MAPT Course Requirements"
    echo -e "  $greenplus python$pyver-venv aapt apktool adb apksigner zipalign wkhtmltopdf default-jdk jadx"
    apt -y install python$pyver-venv aapt apktool adb apksigner zipalign wkhtmltopdf default-jdk jadx
    echo -e "\n  $greenplus git cloning mobsf to /opt"
    eval apt -y install docker.io docker-compose
    eval systemctl enable docker
    eval docker pull opensecurity/mobile-security-framework-mobsf:latest
    echo "sudo docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest" > /usr/bin/mobsf-docker
    chmod +x /usr/bin/mobsf-docker 
      # git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF /opt/Mobile-Security-Framework-MobSF
    echo -e "\n  $greenplus Installing MobSF startup script to /usr/bin/mobsf-docker"
      # scripts are not executable upon git clone of mobsf
      # sudo chmod +x /opt/Mobile-Security-Framework-MobSF/*.sh
      # cd /opt/Mobile-Security-Framework-MobSF/
      # /opt/Mobile-Security-Framework-MobSF/setup.sh

    # --- ANDROID STUDIO ONLY ---
    # echo -e "\n  $greenplus Installing Android Studio requirements"
    # dpkg --add-architecture i386
    # apt_update
    # apt -y install libc6:i386 libncurses5:i386 libstdc++6:i386 lib32z1 libbz2-1.0:i386
    # echo -e "\n  $greenplus Downloading Android Studio"
    # wget https://redirector.gvt1.com/edgedl/android/studio/ide-zips/2020.3.1.26/android-studio-2020.3.1.26-linux.tar.gz -O /tmp/android-studio-2020.3.1.26-linux.tar.gz
    # echo -e "\n  $greenplus Extracting Android Studio to /opt/android-studio"
    # tar xvfz /tmp/android-studio-2020.3.1.26-linux.tar.gz -C /opt
    # echo -e "\n  $greenplus Making scripts executable in /opt/android-studio/bin"
    # chmod +x /opt/android-studio/bin/*.sh
    # rm -f /tmp/android-studio-2020.3.1.26-linux.tar.gz
    # --- ANDROID STUDIO ONLY ---
    }

# ppa_prereq() {
#    # PMK 1.4.1 - Practical Phising Assesment Course Prereq - 01.05.22
#    echo -e "\n  $greenplus Installing PPA Course Prerequisites... \n"
#    sudo apt -y install whois bind9-dnsutils
#    echo -e "\n  $greenplus Git Cloning Spoofpoint to /opt/spoofpoint \n"
#    [[ -d /opt/spoofpoint ]] && rm -rf /opt/spoofpoint
#    git clone https://github.com/grahamhelton/spoofpoint /opt/spoofpoint
#    echo -e "\n  $greenplus Creating Symlink /usr/bin/spoofpoint \n"
#    ln -sf /opt/spoofpoint/spoofpoint /usr/bin/spoofpoint
#    }

# start new modifications for pbb course

pbb_create_cleanupsh() { 
    cleanup_script="cleanup-pbb-labs.sh"
    echo -e "\n  $greenplus Creating cleanup_peh_labs.sh" 
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
    chmod +x cleanup-pbb-labs.sh

    # create start-pbb-labs.sh
    startup_script="start-pbb-labs.sh"
    echo -e "\n  $greenplus Creating start-pbb-labs.sh"
    echo -e "#!/bin/bash" > $startup_script
    echo -e "\n" >> $startup_script
    echo -e "cd ~/pbb/labs/" >> $startup_script
    echo -e "sudo docker-compose down"  >> $startup_script 
    echo -e "sudo systemctl stop mysqld" >> $startup_script 
    echo -e "sudo docker-compose up -d" >> $startup_script
    echo -e "get_lab_status=\$(curl --silent http://localhost/init.php | grep -i \"connection refused\" -c)" >> $startup_script
    # may not be necessary
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

pbb_create_cleanupsh() { 
    cleanup_script="cleanup-pbb-labs.sh"
    echo -e "\n  $greenplus Creating cleanup_peh_labs.sh" 
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
    chmod +x cleanup-pbb-labs.sh

    # create start-pbb-labs.sh
    startup_script="start-pbb-labs.sh"
    echo -e "\n  $greenplus Creating start-pbb-labs.sh"
    echo -e "#!/bin/bash" > $startup_script
    echo -e "\n" >> $startup_script
    echo -e "cd ~/pbb/bugbounty" >> $startup_script
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
    chmod +x start-pbb-labs.sh
    }

pbb_lab_setup() {
    echo -e "\n  $greenplus Installing docker.io and docker-compose"
    eval apt -y install docker.io docker-compose
    
    echo -e "\n  $greenplus Starting docker service and enabling " 
    eval systemctl enable docker --now
    
    echo -e "\n  $greenplus Downloading pbb-labs.zip " 
    wget https://cdn.fs.teachablecdn.com/iaWfH4NrRp20zLOd3xLr -O /tmp/pbb-labs.zip
    
    if [[ $finduser == "root" ]]
     then 
      #lab setup for root
      echo -e "\n  $greenplus Making peh directory for bugbounty labs /$finduser/pbb"
      mkdir /$finduser/pbb
      
      echo -e "\n  $greenplus Extracting labs to /$finduser/pbb/bugbounty" 
      unzip -o /tmp/pbb-labs.zip -d /$finduser/pbb
     
      echo -e "\n  $greenplus Setting permissions for /$finduser/pbb/bugbounty/labs/uploads"
      chmod 777 /$finduser/pbb/bugbounty/labs/uploads

      echo -e "\n  $greenplus Starting labs docker in daemon mode" 
      cd /$finduser/pbb/bugbounty
      pbb_create_cleanupsh

      if [[ ! -f docker-compose.yml ]]
       then 
        echo -e "\n  $redexclaim docker-compose.yml not found in current directory, aborting "
        exit_screen
       else 
        echo -e "\n  $greenplus docker-compose.yml found, starting labs in daemon mode -d" 
        eval docker-compose up -d 
        get_lab_status=$(curl --silent http://localhost/init.php | grep -c -i "connection refused")
        echo -e "\n  $greenminus Waiting for databases to reset..."
          while [ $get_lab_status -ge 1 ]
            do
            if [[ $get_lab_status -ge 1 ]]
              then
               sleep 1
              checkagain=$(curl --silent http://localhost/init.php | grep -c -i "connection refused")
                if [[ $checkagain == 0 ]]
                  then
                    curl --silent http://localhost/init.php > /dev/null
                    echo -e "\n  $greenplus Database reset"
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
      echo -e "\n  $greenplus Making pbb directory for labs /home/$finduser/pbb"
      mkdir /home/$finduser/pbb

      echo -e "\n  $greenplus Extracting labs to /home/$finduser/pbb"
      unzip -o /tmp/pbb-labs.zip -d /home/$finduser/pbb

      # check for /home/$finduser/pbb/bugbounty/labs/uploads
      if [[ -d /home/$finduser/pbb/bugbounty/labs/uploads ]]
       then
        echo -e "\n  $greenplus Setting permissions for /home/$finduser/pbb/labs/uploads"
        chmod 777 /home/$finduser/pbb/bugbounty/labs/uploads
        echo -e "\n  $greenplus Setting ownership to $finduser:$finduser for /home/$finduser/pbb"
        chown -R $finduser:$finduser /home/$finduser/pbb
       else
        echo -e "\n  $redexclaim Unable to find /home/$finduser/pbb/labs/uploads"
      fi


      echo -e "\n  $greenplus Creating cleanup-pbb-labs.sh and start-pbb-labs.sh in /home/$finduser/pbb/bugbounty" 
      cd /home/$finduser/pbb/bugbounty
      pbb_create_cleanupsh

      echo -e "\n  $greenplus Cleaning up temporary files..." 
      rm /tmp/pbb-labs.zip

      echo -e "\n  $greenplus Starting labs docker in daemon mode" 
      cd /home/$finduser/pbb/bugbounty
      if [[ ! -f docker-compose.yml ]]
       then 
        echo -e "\n  $redexclaim docker-compose.yml not found in current directory, aborting "
        exit_screen
       else 
        echo -e "\n  $greenplus docker-compose.yml found, starting labs in daemon mode " 
        eval docker-compose up -d 
        get_lab_status=$(curl --silent http://localhost/init.php | grep -c -i "connection refused")
        echo -e "\n  $greenminus Waiting for databases to reset..."
          while [ $get_lab_status -ge 1 ]
            do
            if [[ $get_lab_status -ge 1 ]]
              then
               sleep 1
              checkagain=$(curl --silent http://localhost/init.php | grep -c -i "connection refused")
                if [[ $checkagain == 0 ]]
                  then
                    curl --silent http://localhost/init.php > /dev/null
                    echo -e "\n  $greenplus Database reset"
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
# New modifications end here

hacking_peh_create_cleanupsh() { 
    cleanup_script="cleanup-peh-labs.sh"
    echo -e "\n  $greenplus Creating cleanup-peh-labs.sh" 
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

    # create start-peh-labs.sh
    startup_script="start-peh-labs.sh"
    echo -e "\n  $greenplus Creating start-peh-hacking.sh"
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
    }    

peh_weblab_setup() {
    echo -e "\n  $greenplus Installing docker.io and docker-compose"
    eval apt -y install docker.io docker-compose
    
    echo -e "\n  $greenplus Starting docker service and enabling " 
    eval systemctl enable docker --now
    
    echo -e "\n  $greenplus Downloading peh-web-labs.tar.gz " 
    wget https://cdn.fs.teachablecdn.com/NgPnyKOwSfWYuwnX3Lzb -O /tmp/peh-web-labs.tar.gz
    
    if [[ $finduser == "root" ]]
     then 
      #lab setup for root
      echo -e "\n  $greenplus Making peh directory for labs /$finduser/peh"
      mkdir /$finduser/peh
      
      echo -e "\n  $greenplus Extracting labs to /$finduser/peh" 
      tar xvfz /tmp/peh-web-labs.tar.gz -C /$finduser/peh
     
      echo -e "\n  $greenplus Setting permissions for /$finduser/peh/labs/labs/uploads"
      chmod 777 /$finduser/peh/labs/labs/uploads

      echo -e "\n  $greenplus Setting permissions for /$finduser/peh/labs/capstone/assets"
      chmod 777 /$finduser/peh/labs/capstone/assets

      echo -e "\n  $greenplus Starting labs docker in daemon mode" 
      cd /$finduser/peh/labs 
      hacking_peh_create_cleanupsh

      if [[ ! -f docker-compose.yml ]]
       then 
        echo -e "\n  $redexclaim docker-compose.yml not found in current directory, aborting "
        exit_screen
       else 
        echo -e "\n  $greenplus docker-compose.yml found, starting labs in daemon mode -d" 
        eval docker-compose up -d 
        exit_screen 
      fi 

     else 
      # lab setup for regular user 
      echo -e "\n  $greenplus Making peh directory for labs /home/$finduser/peh"
      mkdir /home/$finduser/peh 
      
      echo -e "\n  $greenplus Extracting labs to /home/$finduser/peh" 
      tar xvfz /tmp/peh-web-labs.tar.gz -C /home/$finduser/peh 
     
      # check for /home/$finduser/peh/labs/labs/uploads
      if [[ -d /home/$finduser/peh/labs/labs/uploads ]]
       then 
        echo -e "\n  $greenplus Setting permissions for /home/$finduser/peh/labs/labs/uploads"
        chmod 777 /home/$finduser/peh/labs/labs/uploads
        echo -e "\n  $greenplus Setting ownership to $finduser:$finduser for /home/$finduser/peh"
        chown -R $finduser:$finduser /home/$finduser/peh 
       else 
        echo -e "\n  $redexclaim Unable to find /home/$finduser/peh/labs/labs/uploads"
      fi 

      # check for /home/$finduser/peh/labs/capstones/assets
      if [[ -d /home/$finduser/peh/labs/capstone/assets ]] 
       then 
        echo -e "\n  $greenplus Setting permissions for /home/$finduser/peh/labs/capstone/assets"
        chmod 777 /home/$finduser/peh/labs/capstone/assets
       else
        echo -e "\n  $redexclaim Unable to locate /home/$finduser/peh/labs/capstone/assets"
        exit_screen
      fi 

      echo -e "\n  $greenplus Creating cleanup-peh-labs.sh and start-peh-labs.sh in /home/$finduser/peh/labs" 
      cd /home/$finduser/peh/labs 
      hacking_peh_create_cleanupsh

      echo -e "\n  $greenplus Cleaning up temporary files..." 
      rm /tmp/peh-web-labs.tar.gz 

      echo -e "\n  $greenplus Starting labs docker in daemon mode" 
      
      if [[ ! -f docker-compose.yml ]]
       then 
        echo -e "\n  $redexclaim docker-compose.yml not found in current directory, aborting "
        exit_screen
       else 
        echo -e "\n  $greenplus docker-compose.yml found, starting labs in daemon mode " 
        eval docker-compose up -d 
      fi 
    fi 
    }

mayor_mpp() {
    # additions to PMK 1.3.0 - Mayor MPP Course additions
    fix_sources
    apt_update  && apt_update_complete
    apt_upgrade && apt_upgrade_complete
    apt_autoremove && apt_autoremove_complete
    echo -e "\n  $greenplus installing apt-transport-https dnsutils dotnet-sdk-3.1"
    apt -y install apt-transport-https dnsutils dotnet-sdk-3.1
    # download directly to /tmp and install
    echo -e "\n  $greenplus installing packages-microsoft-prod.deb"
    eval wget https://packages.microsoft.com/config/ubuntu/21.04/packages-microsoft-prod.deb -O /tmp/packages-microsoft-prod.deb
    dpkg -i /tmp/packages-microsoft-prod.deb
    rm -f /tmp/packages-microsoft-prod.deb
    # git clone Covenant to /opt
    # add check and prompt if /opt/Covenant already exists, what to do with it
    echo -e "\n  $greenplus installing covenant to /opt/Covenant"
    [ -d /opt/Covenant ] && rm -rf /opt/Covenant; git clone --recurse-submodules https://github.com/ZeroPointSecurity/Covenant.git /opt/Covenant || git clone --recurse-submodules https://github.com/ZeroPointSecurity/Covenant.git
    # create /usr/local/bin/startcovenant.sh
    echo -e "\n  $greenplus creating /usr/local/bin/startcovenant.sh"
    echo '#!/bin/bash' > /usr/local/bin/startcovenant.sh
    echo 'kill_covenant=$(pgrep -f "sudo dotnet run --project /opt/Covenant/Covenant")' >> /usr/local/bin/startcovenant.sh
    echo 'kill_covenant_debug=$(pgrep -f "/opt/Covenant/Covenant/bin/Debug/netcoreapp3.1/Covenant")' >> /usr/local/bin/startcovenant.sh
    echo 'if [[ $kill_covenant -ne 0 || $kill_covenant_debug -ne 0 ]]; then' >> /usr/local/bin/startcovenant.sh
    echo '  sudo kill $kill_covenant $kill_covenant_debug' >> /usr/local/bin/startcovenant.sh
    echo '  sudo dotnet run --project /opt/Covenant/Covenant' >> /usr/local/bin/startcovenant.sh
    echo 'else' >> /usr/local/bin/startcovenant.sh
    echo '  sudo dotnet run --project /opt/Covenant/Covenant' >> /usr/local/bin/startcovenant.sh
    echo 'fi' >> /usr/local/bin/startcovenant.sh
    # change mode of script to +x
    echo -e "\n  $greenplus making executable /usr/local/bin/startcovenant.sh"
    chmod +x /usr/local/bin/startcovenant.sh
    # symlink /usr/local/bin/startcovenant.sh to /usr/local/bin/startcovenant
    echo -e "\n  $greenplus symlinking /usr/local/bin/startcovenant.sh to /usr/local/bin/covenant"
    ln -sf /usr/local/bin/startcovenant.sh /usr/local/bin/covenant

    #make desktop icon
    findrealuser=$(who | awk '{print $1}')
    if [[ $findrealuser == "root" ]];
      then
        echo -e "\n  $greenplus creating desktop icon /root/Desktop/Start Covenent"
        echo '[Desktop Entry]' > /root/Desktop/"Start Covenant.desktop"
        echo 'Version=1.0' >> /root/Desktop/"Start Covenant.desktop"
        echo 'Type=Application' >> /root/Desktop/"Start Covenant.desktop"
        echo 'Name=Start Covenant' >> /root/Desktop/"Start Covenant.desktop"
        echo 'Comment=Start Covenant' >> /root/Desktop/"Start Covenant.desktop"
        echo 'Exec=/usr/local/bin/covenant' >> /root/Desktop/"Start Covenant.desktop"
        echo 'Icon=cpu' >> /root/Desktop/"Start Covenant.desktop"
        echo 'Path=' >> /root/Desktop/"Start Covenant.desktop"
        echo 'Terminal=true' >> /root/Desktop/"Start Covenant.desktop"
        echo 'StartupNotify=false' >> /root/Desktop/"Start Covenant.desktop"
        chown $finduser:$finduser /$finduser/Desktop/"Start Covenant.desktop"
        chmod +x /$finduser/Desktop/"Start Covenant.desktop"
      else
        echo -e "\n  $greenplus creating desktop icon /home/$finduser/Start Covenent"
        echo '[Desktop Entry]' > /home/$finduser/Desktop/"Start Covenant.desktop"
        echo 'Version=1.0' >> /home/$finduser/Desktop/"Start Covenant.desktop"
        echo 'Type=Application' >> /home/$finduser/Desktop/"Start Covenant.desktop"
        echo 'Name=Start Covenant' >> /home/$finduser/Desktop/"Start Covenant.desktop"
        echo 'Comment=Start Covenant' >> /home/$finduser/Desktop/"Start Covenant.desktop"
        echo 'Exec=/usr/local/bin/covenant' >> /home/$finduser/Desktop/"Start Covenant.desktop"
        echo 'Icon=cpu' >> /home/$finduser/Desktop/"Start Covenant.desktop"
        echo 'Path=' >> /home/$finduser/Desktop/"Start Covenant.desktop"
        echo 'Terminal=true' >> /home/$finduser/Desktop/"Start Covenant.desktop"
        echo 'StartupNotify=false' >> /home/$finduser/Desktop/"Start Covenant.desktop"
        chown $finduser:$finduser /home/$finduser/Desktop/"Start Covenant.desktop"
        chmod +x /home/$finduser/Desktop/"Start Covenant.desktop"
      fi
    }

#---- begin pimpmykali-mirrors rev 1.3.2 08.20.2021 ----
get_mirrorlist() {
  	cleanup
    fix_sources
    echo -e "\n  $greenplus Pimpmykali-Mirrors - kali repo mirror speedtest"
    # relaxed grep should now work with tracelabs osint vm - 12.11.2021
    mod_deb=$(cat /etc/apt/sources.list | grep -c "deb http\:\/\/.* kali\-rolling.*")
    mod_debsrc=$(cat /etc/apt/sources.list | grep -c "deb-src http\:\/\/.* kali\-rolling.*")
    
  	if [[ $mod_deb = 1 ]]
  	 then
       echo -e "\n  $greenplus deb http://*/kali found in /etc/apt/sources.list"
     else
      echo -e "\n  $redexclaim Unable to find deb http://*/kali in /etc/apt/sources.list"
      exit_screen
    fi
    if [[ $mod_debsrc = 1 ]]
     then
      echo -e "\n  $greenplus deb-src http://*/kali found in /etc/apt/sources.list"
    else
      echo -e "\n  $redexclaim Unable to find deb-src in /etc/apt/sources.list"
      exit_screen
    fi
    
    curl -s http://http.kali.org/README.mirrorlist | grep -i "README" | cut -d ">" -f2 | cut -d "\"" -f2 | grep -i "http://" | \
    sed s:"http\:\/\/http.kali.org\/README.meta4":"":g | sed s:"http\:\/\/http.kali.org\/README.metalink":"":g | sort -u > /tmp/timetest.list
  	}

best_ping() {
    [[ -f /tmp/kali-ping ]] && rm -f /tmp/kali-ping
	  echo -e "\n  $greenplus Testing kali mirrors round-trip-time, selecting the top 10"
    mirror=$(cat /tmp/timetest.list | sort -u | sed s:"http\:\/\/":"":g)
     for i in $mirror; do
       current_mirror=$(echo $i | cut -d "/" -f1)
       current_file=$(echo $i | cut -d "/" -f2-10)
       avg_rtt_mirror=$(ping -c 3 $current_mirror | grep -i rtt | cut -d "=" -f2 | cut -d "/" -f2)
    	  if [[ $avg_rtt_mirror = "" ]]
         then
          echo -e "    $redexclaim Failed to respond: $current_mirror"
         else
          echo -e "    $greenplus Testing $current_mirror rtt time: $avg_rtt_mirror"ms" "
          echo "$avg_rtt_mirror:$current_mirror" >> /tmp/kali-ping
        fi
     done
     best_rtt=$(cat /tmp/kali-ping | sed -r '/^\s*$/d' | sort -nr | tail -n1 | cut -d ":" -f1)
     best_rttmirror=$(cat /tmp/kali-ping | sed -r '/^\s*$/d' | sort -nr | tail -n1 | cut -d ":" -f2)
     #echo -e "  $greenplus Best rtt result : $best_rtt"ms" at $best_rttmirror"
    }

small_speedtest() {
  	echo > /tmp/mirrors_speedtest
    echo -e "\n  $greenplus Testing top 10 mirrors - small transfer >1MB, select top 5"
    for i in $(cat /tmp/kali-ping | sed -r '/^\s*$/d' | sort -n | head -n10 | cut -d ":" -f2); do
  	  active_mirror=$(cat /tmp/timetest.list | grep "$i" | grep "README" | sed -r '/^\s*$/d')
  	  active_mirror_display=$(cat /tmp/timetest.list | grep "$i" | grep "README" | cut -d "/" -f3| sed -r '/^\s*$/d')
  	  get_download=$(curl -s "$active_mirror" --w %{speed_download} -o /dev/null)
   	  mb_speed=$(($get_download / 1024 / 1024))
  	  echo "$get_download:$active_mirror:$mb_speed" >> /tmp/mirrors_speedtest
      echo -e "    $greenplus $active_mirror_display speed: $get_download b/sec"
  	done
  	}

large_speedtest() {
  	echo > /tmp/mirrors_speedtest
  	echo -e "\n  $greenplus Testing top 5 mirrors from small transfer - large transfer (10MB)"
  	for i in $(cat /tmp/kali-ping | sed -r '/^\s*$/d' | sort -n | head -n5 | cut -d ":" -f2); do
  	  active_mirror=$(cat /tmp/timetest.list | grep "$i" | grep "README" | sed s:"README":"dists/kali-rolling/Contents-amd64.gz":g | sed -r '/^\s*$/d')
  	  active_mirror_display=$(cat /tmp/timetest.list | grep "$i" | grep "README" | cut -d "/" -f3| sed -r '/^\s*$/d')
   	  get_download=$(curl --max-time 30 -s -r 0-10485760 "$active_mirror" --w %{speed_download} -o /dev/null)
   	  mb_speed=$(($get_download / 1024 / 1024))
  	  echo "$get_download:$active_mirror:$mb_speed" >> /tmp/mirrors_speedtest
  	  echo -e "    $greenplus $active_mirror_display speed: $get_download b/sec ($mb_speed MB/sec)"
  	done
  	}

gen_new_sources() {
  	i=$(cat /tmp/mirrors_speedtest | sort -n | tail -n1 | cut -d "/" -f3)
  	final_mirror=$(cat /tmp/timetest.list | grep "$i" | sed s:"http\:\/\/":"":g | sed s:"/README":"":g )
    # --- relaxed grep and sed, implement at later date 12.11.2021 - should now work with tracelabs osint vm
    newdeb=$(cat /etc/apt/sources.list | grep "deb http\:\/\/.* kali\-rolling.*" | sed s:"deb http\:\/\/.* kali\-rolling.*":"deb http\:\/\/"$final_mirror" kali\-rolling main contrib non\-free":g)
    newdebsrc=$(cat /etc/apt/sources.list | grep "deb-src http\:\/\/.* kali\-rolling.*" | sed s:"deb-src http\:\/\/.* kali\-rolling.*":"deb\-src http\:\/\/"$final_mirror" kali\-rolling main contrib non\-free":g )
    sourcefile=/etc/apt/sources.list
    echo -e "\n  $greenplus Based on tests the best selection is: $i "
    echo -e "\n  Preview of the new /etc/apt/sources.list:"
    echo -e "\n  $newdeb\n  $newdebsrc"
    echo -e "\n\n   Save new changes to /etc/apt/sources.list ?"
    read -n1 -p "   Please type Y or N : " userinput
     case $userinput in
       y|Y) echo -e "\n\n  $greenplus Saving changes to /etc/apt/sources.list"; cp $sourcefile ${sourcefile}_$(date +%F-%T); \
       sed s:"deb http\:\/\/.* kali\-rolling.*":"deb http\:\/\/"$final_mirror" kali\-rolling main contrib non\-free":g -i $sourcefile; \
       sed s:"deb-src http\:\/\/.* kali\-rolling.*":"deb\-src http\:\/\/"$final_mirror" kali\-rolling main contrib non\-free":g -i $sourcefile; \
       echo -e "\n  $greenplus Running apt update with mirror $final_mirror selected \n";  apt update;;
       n|N) echo -e "\n\n  $redexclaim Not saving changes";;
         *) echo -e "\n\n  $redexclaim Invalid key try again, Y or N keys only $redexclaim"; gen_new_sources;;
     esac
    }

cleanup() {
  	rm -f /tmp/kali-speedtest.found /tmp/kali-speedtest /tmp/timetest.list /tmp/kali-latency /tmp/sources.list /tmp/final.list /tmp/kali-ping /tmp/mirrors_speedtest > /dev/null
    }
    # function call list : get_mirrorlist; best_ping; small_speedtest; large_speedtest; gen_new_sources; cleanup;;
    #---- end pimpmykali-mirrors rev 1.3.2 08.20.2021 ----

# fix_ssh function - set ssh client to wide compatibility mode legacy ciphers - 08.04.2022 rev 1.5.7
#fix_ssh() {
#  echo -e "\n  $greenplus Fix SSH set ssh to wide compatibility"
#  outputfile="/etc/ssh/ssh_config.d/kali-wide-compat.conf"
#  if [[ -f $outputfile ]]
#  then
#    echo -e "\n  $redexclaim File already exists, not updating..."
#  else
#    echo -e "Host *" > $outputfile
#    echo -e "  Ciphers +3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc" >> $outputfile
#    echo -e "  KexAlgorithms +diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1,diffie-hellman-group14-sha1" >> $outputfile
#    echo -e "  HostKeyAlgorithms +ssh-rsa,ssh-rsa-cert-v01@openssh.com,ssh-dss,ssh-dss-cert-v01@openssh.com" >> $outputfile
#    echo -e "  PubkeyAcceptedAlgorithms +ssh-rsa,ssh-rsa-cert-v01@openssh.com,ssh-dss,ssh-dss-cert-v01@openssh.com" >> $outputfile
#    echo -e "  LocalCommand /bin/echo \"Warning: SSH client configured for wide compatibility by kali-tweaks.\"" >> $outputfile
#    echo -e "  PermitLocalCommand yes" >> $outputfile
#    echo -e "\n  $greenplus File : /etc/ssh/ssh_config.d/kali-wide-compat.conf - created"
#    echo -e "\n  $greenplus Restarting SSH Service..."
#    systemctl restart ssh
#    echo -e "\n  $greenplus Fix SSH - Complete"
#  fi
#  }


fix_keyboard() {
  sudo /bin/bash --rcfile /home/$finduser/.bashrc -ic 'dpkg-reconfigure keyboard-configuration'
  }
  
fix_timezone() {
  sudo /bin/bash --rcfile /home/$finduser/.bashrc -ic 'dpkg-reconfigure tzdata' 2>/dev/null
  echo -e "\n  $greenplus Timezone now set to: $(cat /etc/timezone)"
  }

install_everything() {
  echo -e "\n  $greenplus Installing Everything! \n"
  #eval sudo apt -y install kali-linux-everything
  sudo /bin/bash -m --rcfile /home/$finduser/.bashrc -ic 'apt -y install kali-linux-everything' 2> /dev/null
  }

# ascii art - DONT move
asciiart=$(base64 -d <<< "H4sIAAAAAAAAA31QQQrCQAy89xVz9NR8QHoQH+BVCATBvQmC
CEXI480kXdteTJfdzGQy2S3wi9EM/2MnSDm3oUoMuJlX3hmsMMSjA4uAtUTsSQ9NUkkKVgKKBX
p1lEC0auURW3owsQlTZtf4QtGZgjXYKT4inPtI23oEK7wXlyPnd8arKdKE0EPdUnhIf0v+iE2o
7BgVFVyec3u1OxFw+uRxbvPt8R6+MOpGq5cBAAA="  | gunzip )

pimpmykali_menu() {
    # DATE=$(date +%x); TIME=$(date +%X)
    clear
    echo -e "$asciiart"
    echo -e "\n    Select an option from menu:             Rev: $revision Arch: $arch"
#    echo -e "\n     *** APT UPGRADE WILL ONLY BE CALLED FROM MENU OPTION 9 ***"
#    echo -e "\n  Menu Options:"                                                                    # function call list
    echo -e "\n Key  Menu Option:             Description:"
    echo -e " ---  ------------             ------------"
    echo -e "  1 - Fix Missing              (pip pip3 golang gedit nmapfix build-essential)"        # fix_missing
    echo -e "  2 - Fix /etc/samba/smb.conf  (adds the 2 missing lines)"                             # fix_smbconf
    echo -e "  3 - Fix Golang               (installs golang, adds GOPATH= to .zshrc and .bashrc)"  # fix_golang
    echo -e "  4 - Fix Grub                 (adds mitigations=off)"                                 # fix_grub
    echo -e "  5 - Fix Impacket             (installs impacket 0.9.19)"                             # fix_impacket
    echo -e "  6 - Enable Root Login        (installs kali-root-login)"                             # make_rootgreatagain
    #echo -e "  7 - Install Waybackrust      (waybackrust installed, symlinked to waybackurls)"      # fix_waybackurls
    echo -e "  8 - Fix nmap scripts         (clamav-exec.nse and http-shellshock.nse)"              # fix_nmap
    echo -e "  9 - Pimpmyupgrade            (apt upgrade with vbox/vmware detection)"               # only_upgrade
    echo -e "                               (sources.list, linux-headers, vm-video)"                # -
    echo -e "  0 - Fix ONLY 1 thru 8        (runs only 1 thru 8) \n"                                # fix_all
    echo -e "  "$bold"N - NEW VM SETUP"$reset" - Run this option if this is the first time running pimpmykali\n"
    echo -e "  = - Pimpmykali-Mirrors       (find fastest kali mirror. use the equals symbol = )"   # get_mirrorlist; best_ping; small_speedtest; large_speedtest; gen_new_sources; cleanup;;
    echo -e "  T - Reconfigure Timezone      current timezone  : $(cat /etc/timezone)"              # reconfig_timekey
    echo -e "  K - Reconfigure Keyboard      current keyb/lang : $(cat /etc/default/keyboard | grep XKBLAYOUT | cut -d "\"" -f2)\n" # reconfig_keyboard
    echo -e " Key  Stand alone functions:   Description:"                                           # optional line
    echo -e " ---  ----------------------   ------------"                                           # optional line
    echo -e "  B - Practical Bugbounty Labs (add requirements for PBB course labs)"                 # pbb_lab_setup
    echo -e "  E - PEH Course WebApp Labs   (add requirements for PEH WebApp Labs and installs) "   # apt_update fix_libwacom only_upgrade peh_weblab_setup
    echo -e "  O - Hacking API Course Setup (add requirements for Hacking API Course)"              # hacking_api_prereq was fix_ssh
    echo -e "  M - Mayors MPP Course Setup  (adds requirments for Mayors MPP Course)"               # mayor_mpp
    echo -e "  A - MAPT Course Setup        (adds requirments for MAPT Course)"                     # mapt_course
    echo -e "  P - Download Lin/WinPeas     (adds linpeas to /opt/linpeas and winpeas to /opt/winpeas)" # fix_linwinpeas
  #  echo -e "  B - BPT - TheEssentials      (BlindPentesters TheEssentials aprox 8GB of tools)"     # bpt function
    echo -e "  I - Install MITM6            (install mitm6 from github)"                            # fix_mitm6
    echo -e "  C - Missing Google-Chrome    (install google-chrome only)"                           # check_chrome / fix_chrome
    echo -e "  S - Fix Spike                (remove spike and install spike v2.9)"                  # fix_spike
    echo -e "  F - Broken XFCE Icons fix    (stand-alone function: only applies broken xfce fix)"   # fix_broken_xfce
    echo -e "  G - Fix Gedit Conn Refused   (fixes gedit as root connection refused)"               # fix_root_connectionrefused
    echo -e "  H - Fix httprobe missing     (fixes httprobe missing only)"                          # fix_httprobe
    echo -e "  L - Install Sublime Editor   (install the sublime text editor)"                      # install_sublime
    echo -e "  W - Gowitness Precompiled    (download and install gowitness)"                       # fix_gowitness
    echo -e "  V - Install MS-Vscode        (install microsoft vscode only)"                        # install_vscode
    echo -e "  ! - Nuke Impacket            (Type the ! character for this menu item)"              # fix_sead_warning
    echo -e "  @ - Install Nessus           (Type the @ character for this menu item)"              # install_nessus
    echo -e "  $ - Nuke Nessus              (Type the $ character for this menu item)"              # remove_nessus
    echo -e "  % - CrackMapExec 6.x.x pipx  (Type the % character for this menu item)\n"            #fix_cme
    read -n1 -p "  Press key for menu item selection or press X to exit: " menuinput

    case $menuinput in
        1) fix_missing;;
        2) fix_smbconf;;
        3) fix_golang;;
        4) fix_grub;;
        5) fix_impacket;;
        6) make_rootgreatagain;;
       # 7) fix_waybackurls;;
        8) fix_nmap ;;
        9) apt_update; fix_libwacom; only_upgrade;;
        0) fix_all; run_update; virt_what; check_vm;;
        !) forced=1; fix_sead_warning;;
      a|A) mapt_prereq;;
      b|B) pbb_lab_setup;;
      c|C) check_chrome;;
      e|E) apt_update; fix_libwacom; peh_weblab_setup;; # only_upgrade;
      f|F) fix_broken_xfce;;
      g|G) fix_root_connectionrefused ;;
      h|H) fix_httprobe;;
      i|I) fix_mitm6;;
      k|K) fix_keyboard; echo -e "\n  $greenplus Keyboard is currently set to: $(cat /etc/default/keyboard | grep XKBLAYOUT | cut -d "\"" -f2)";;
      l|L) install_sublime;;
      m|M) mayor_mpp;;
      n|N) fix_all; fix_upgrade;;
      o|O) hacking_api_prereq;; # was fix_ssh
      p|P) fix_linwinpeas;; 
      s|S) fix_spike;;
      t|T) fix_timezone;;
      v|V) install_vscode;;
      w|W) fix_gowitness;;
      "=") get_mirrorlist; best_ping; small_speedtest; large_speedtest; gen_new_sources; cleanup;;
      x|X) echo -e "\n\n Exiting pimpmykali.sh - Happy Hacking! \n" ;;
        ^) install_everything;;
        @) install_nessus;;
        $) remove_nessus;;
        %) fix_cme;;
        *) pimpmykali_menu ;;
    esac
    }

pimpmykali_help() {
    # do not edit this echo statement, spacing has been fixed and is correct for display in the terminal
    echo -e "\n valid command line arguements are : \n \n --all        run all operations \n"\
            "--smb        only run smb.conf fix \n --go         only fix/install golang"\
            "\n --impacket   only fix/install impacket \n --grub       only add mitigations=off"\
            "\n --root       only enable root login \n --missing    install all common missing packages" \
            "\n --menu       its the menu \n --atom       only install atom\n --flameshot  only fix/install flameshot" \
            "\n --borked     only to be used as last resort to remove-reinstall impacket" \
            "\n --upgrade    fix apt upgrade with detection for virtualbox or vmware\n --help       your looking at it"
    exit
    }

check_arg() {
    if [ "$1" == "" ]
      then pimpmykali_menu
     else
      case $1 in
      --menu) pimpmykali_menu                  ;;
       --all) fix_all                          ;;
       --smb) fix_smbconf                      ;;
        --go) fix_golang                       ;;
  #--impacket) fix_impacket                     ;;
      --grub) fix_grub                         ;;
      --root) make_rootgreatagain              ;;
   --missing) fix_missing                      ;;
      --help) pimpmykali_help                  ;;
 --flameshot) fix_flameshot                    ;;
     --force) force=1; fix_all $force          ;;
    --borked) force=1; fix_sead_warning $force ;;
      --nmap) fix_nmap                         ;;
       --bpt) bpt                              ;;
    --vscode) install_vscode                   ;;
      --subl) install_sublime                  ;;
#      --atom) install_atom                     ;;
   --upgrade) only_upgrade                     ;;
   --mirrors) get_mirrorlist; best_ping; small_speedtest; large_speedtest; gen_new_sources; cleanup;;
# --harvester) fix_theharvester                ;;
      *) pimpmykali_help ; exit 0              ;;
    esac
    fi
    }

exit_screen() {
    eval apt -y --fix-broken install >/dev/null 2>&1
    echo -e "$asciiart"
    echo -e "\n\n    All Done! Happy Hacking! \n"
    exit
    }

check_for_root
check_distro
check_arg "$1"
exit_screen

