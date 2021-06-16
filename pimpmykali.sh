#!/bin/bash
#
# pimpmykali.sh  Author: Dewalt
# git clone https://github.com/Dewalt-arch/pimpmykali
# Usage: sudo ./pimpmykali.sh  ( defaults to the menu system )
# command line arguments are valid, only catching 1 arguement
#
# Full Revision history can be found in README.md
# Standard Disclaimer: Author assumes no liability for any damage

# revision var
    revision="1.2.8"

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

# variables moved from local to global
    finduser=$(logname)

# for vbox_fix_shared_folder_permission_denied
    findgroup=$(groups $finduser | grep -i -c "vboxsf")

#    Logging
#    LOG_FILE=/tmp/pimpmykali.log
#    exec > >(tee ${LOG_FILE}) 2>&1

# silent mode
    silent=''                  # uncomment to see all output
    # silent='>/dev/null 2>&1' # uncomment to hide all output10

# 02.02.21 - rev 1.1.8 - fix_xfce_root fix_xfce_user fix_xfcepower external configuration file
    raw_xfce="https://raw.githubusercontent.com/Dewalt-arch/pimpmyi3-config/main/xfce4/xfce4-power-manager.xml"

check_distro() {
    distro=$(uname -a | grep -i -c "kali") # distro check
    if [ $distro -ne 1 ]
     then echo -e "\n $blinkexclaim Kali Linux Not Detected - WSL/WSL2/Anything else is unsupported $blinkexclaim \n"; exit
    fi
    }

# May change check_distro
#    check_distro() {
#        # distro=$(uname -a | grep -i -c "kali") # distro check
#        # may change the distro check
#
#        if [ -f /etc/os-release ]
#        then
#         distro=$(cat /etc/os-release | grep -c "kali")
#         if [ $distro = 0 ]
#           then echo -e "\n $blinkexclaim Kali Linux Not Detected - WSL/WSL2/Anything else is unsupported $blinkexclaim \n"; exit
#         else
#           echo "System is Kali Linux - Proceeding..."
#         fi
#        else
#         echo "Unable to determine distro - /etc/os-release does not exist"
#       fi


check_for_root () {
    if [ "$EUID" -ne 0 ]
      then echo -e "\n\n Script must be run with sudo ./pimpmykali.sh or as root \n"
      exit
    else
      # 02.19.21 - Kali 2021.1 + MSF 6.0.30-DEV Released
      # Remove any prior hold on metasploit-framework at startup
      eval apt-mark unhold metasploit-framework >/dev/null 2>&1
    fi
    }

fix_section () {
    if [ $check -ne 1 ]
     then
      # sanity check : force=0 check=0 or force=1 check=0
      echo -e "\n  $greenplus install : $section"
      eval apt -y install $section $silent
     elif [ $force = 1 ]
      then
       # sanity check : force=1 check=1
       echo -e "\n  $redstar reinstall : $section"
       eval apt -y reinstall $section $silent
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
    eval apt -y update
    }

apt_upgrade() {
    echo -e "\n  $greenplus running: apt upgrade \n"
    eval apt -y upgrade
    }

apt_autoremove() {
    echo -e "\n  $greenplus running: apt autoremove \n"
    eval apt -y autoremove
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

fix_missing () {
    fix_sources
    apt_update && apt_update_complete
    apt_autoremove && apt_autoremove_complete
    eval apt -y remove kali-undercover $silent
    # 02.01.2020 - Added cifs-utils and libguestfs-tools as they are require for priv escalation
    eval apt -y install dkms build-essential autogen automake python3-setuptools python3-distutils python3.9-dev libguestfs-tools cifs-utils $silent
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
    fix_xfcepower         # 02.02.2021 - disable xfce power management for user and root
    fix_python_requests
    fix_pipxlrd           # 12.29.2020 added xlrd==1.2.0 for windows-exploit-suggester.py requirement
    fix_spike
    fix_set
    check_chrome
    fix_gowitness       # 01.27.2021 added due to 404 errors with go get -u github.com/sensepost/gowitness
    }

fix_all () {
    fix_missing   $force
    make_rootgreatagain $force
    seclists      $force
    install_atom
    fix_flameshot $force
    fix_grub
    fix_smbconf
    fix_impacket
    # ID10T REMINDER: DONT CALL THESE HERE THEY ARE IN FIX_MISSING!
    # python-pip-curl python3_pip fix_golang fix_nmap
    # fix_upgrade is not a part of fix_missing and only
    # called as sub-function call of fix_all or fix_upgrade itself
    }

# lightdm theme change to light or dark mode maybe
# cat /etc/lightdm/lightdm-gtk-greeter.conf | sed 's/Kali-Light/Kali-Dark''/'
# cat /etc/lightdm/lightdm-gtk-greeter.conf | sed 's/Kali-Dark/Kali-Light''/'
# add optional ugly-background fix?

# 04.06.21 - rev 1.2.2 - add google-chrome due to gowitness dependancy
check_chrome(){
    [[ -f "/usr/bin/google-chrome" ]] && echo -e "\n  $greenminus google-chrome already installed - skipping  \n" || fix_chrome;
    }

fix_chrome() {
    echo -e "\n  $greenplus Gowitness dependancy fix: Downloading - google-chrome \n"
    eval wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb -O /tmp/google-chrome-stable_current_amd64.deb
    echo -e "\n  $greenplus Gowitness dependancy fix: Installing - google-chrome \n"
    eval dpkg -i /tmp/google-chrome-stable_current_amd64.deb
    rm -f /tmp/google-chrome-stable_current_amd64.deb
    }

# 02.02.21 - rev 1.1.8 - Turn off XFCE Power Management for user
fix_xfce_root() {
    eval wget $raw_xfce -O /root/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-power-manager.xml
    echo -e "\n  $greenplus turned off xfce power management root \n"
  	}

# 02.02.21 - rev 1.1.8 - Turn off XFCE Power Management for $finduser
fix_xfce_user() {
    eval wget $raw_xfce -O /home/$finduser/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-power-manager.xml
    echo -e "\n  $greenplus turned off xfce power management for $finduser \n"
	  }

# 02.02.21 - rev 1.1.8 - Turn off XFCE Power - detection statements
fix_xfcepower () {
    [[ -f "/home/$finduser/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-power-manager.xml" ]] && fix_xfce_user || echo -e "\n  $greenminus xfce power management file not found"
    [[ -f "/root/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-power-manager.xml" ]] && fix_xfce_root || echo -e "\n  $greenminus xfce power management file not found"
  	}

# 02.02.21 - rev 1.1.8 - Turn off / Silence PCSPKR beep
silence_pcbeep () {
    echo -e "blacklist pcspkr" > /etc/modprobe.d/nobeep.conf
    echo -e "\n  $greenplus Terminal Beep Silenced! /etc/modprobe.d/nobeep.conf \n"
    }

fix_pipxlrd () {
    eval pip install xlrd==1.2.0 --upgrade
    # eval pip3 install xlrd --upgrade
    echo -e "\n  $greenplus python module : xlrd installed \n"
    }

python-pip-curl () {
    check_pip=$(whereis pip | grep -i -c "/usr/local/bin/pip2.7")
    if [ $check_pip -ne 1 ]
     then
      echo -e "\n  $greenplus installing pip"
      # 01.26.2021 - get-pip.py throwing an error, commented out and pointed wget directly to the python2.7 get-pip.py
      eval curl https://raw.githubusercontent.com/pypa/get-pip/3843bff3a0a61da5b63ea0b7d34794c5c51a2f11/2.7/get-pip.py -o /tmp/get-pip.py $silent
      eval python /tmp/get-pip.py $silent
      rm -f /tmp/get-pip.py
      eval pip install setuptools
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
fix_spike () {
    echo -e "\n  $greenplus Fix SPIKE "
    echo -e "\n  $greenplus removing SPIKE...\n"
    eval apt -y --allow-change-held-packages remove spike
    wget http://old.kali.org/kali/pool/main/s/spike/spike_2.9-1kali6_amd64.deb -O /tmp/spike_2.9-1kali6_amd64.deb
    echo -e "\n  $greenplus installing spike 2.9... \n"
    eval dpkg -i /tmp/spike_2.9-1kali6_amd64.deb
    echo -e "\n  $greenplus spike 2.9 installed \n"
    rm -f /tmp/spike_2.9-1kali6_amd64.deb
    echo -e "\n  $greenplus setting apt hold on spike package"
    eval apt-mark hold spike
    echo -e "\n  $greenplus apt hold placed on spike package"
    }

fix_gowitness () {
   echo -e "\n  $greenplus Installing gowitness prebuilt binary...\n"
   rm -f /tmp/releases.gowitness > /dev/null
   check_chrome
   wget https://github.com/sensepost/gowitness/releases -O /tmp/releases.gowitness
   current_build=$(cat /tmp/releases.gowitness | grep -i "<a href=\"/sensepost/gowitness/releases/download/"  | grep -i -m1 linux | cut -d "\"" -f2)
   wget https://github.com$current_build -O /usr/bin/gowitness
   chmod +x /usr/bin/gowitness
   rm -f /tmp/releases.gowitness > /dev/null
   }

fix_root_connectionrefused () {
    # fix root gedit connection refused
    echo -e "\n  $greenplus Adding root to xhost : xhost +SI:localuser:root \n"
    eval xhost +SI:localuser:root
    echo -e "\n  $greenplus root added to xhost"
    }

fix_gedit () {
    section="gedit"
    check=$(whereis gedit | grep -i -c "gedit: /usr/bin/gedit")
    fix_section $section $check $force
    }

fix_set() {
    # move these to their individual respecitive functions at a later date - 04.11.2021 rev 1.2.4
    eval apt -y install libssl-dev set gcc-mingw-w64-x86-64-win32
    }

fix_rockyou () {
    cd /usr/share/wordlists
    gzip -dq /usr/share/wordlists/rockyou.txt.gz
    echo -e "\n  $greenplus gunzip /usr/share/wordlists/rockyou.txt.gz\n"
    }

locate () {
    section="locate"
    check=$(whereis locate | grep -i -c "locate: /usr/bin/locate")
    fix_section $section $check $force
    }

fix_htop () {
    section="htop"
    check=$(whereis htop | grep -i -c "htop: /usr/bin/htop")
    fix_section $section $check $force
    }

python3_pip () {
    section="python3-pip"
    check=$(python3 -m pip --version | grep -i -c "/usr/lib/python3/dist-packages/pip")
    fix_section $section $check $force
    }

seclists () {
    section="seclists"
    check=$(whereis seclists | grep -i -c "seclists: /usr/bin/seclists /usr/share/seclists")
    fix_section $section $check $force
    }

fix_nmap () {
    rm -f /usr/share/nmap/scripts/clamav-exec.nse
    echo -e "\n  $redminus /usr/share/nmap/scripts/clamav-exec.nse removed "
    eval wget https://raw.githubusercontent.com/nmap/nmap/master/scripts/clamav-exec.nse -O /usr/share/nmap/scripts/clamav-exec.nse $silent
    eval wget https://raw.githubusercontent.com/onomastus/pentest-tools/master/fixed-http-shellshock.nse -O /usr/share/nmap/scripts/http-shellshock.nse $silent
    echo -e "\n  $greenplus /usr/share/nmap/scripts/clamav-exec.nse replaced with working version "
    }

fix_flameshot () {
    section="flameshot"
    check=$(whereis flameshot | grep -i -c "/usr/bin/flameshot")
    fix_section $section $check $force
    }

# 02.02.21 - rev 1.1.8 - install theharvester
fix_theharvester () {
    section="theharvester"
    check=$(whereis theharvester | grep -i -c "/usr/bin/theharvester")
    fix_section $section $check $force
    }

fix_golang () {
    section="golang"
    check=$(whereis go  | grep -i -c "/usr/bin/go")
    fix_section $section $check $force
    fix_go_path
    }

fix_go_path() {
    findrealuser=$(who | awk '{print $1}')
    if [ $findrealuser == "root" ]
     then
      check_root_zshrc=$(cat /root/.zshrc | grep -c GOPATH)
       if [ $check_root_zshrc -ne 0 ]
         then
          echo -e "\n  $redminus GOPATH Variables for $findrealuser already exist in /root/.zshrc - Not changing"
         else
          echo -e "\n  $greenplus Adding GOPATH Variables to /root/.zshrc"
          eval echo -e 'export GOPATH=\$HOME/go' >> /root/.zshrc
          eval echo -e 'export PATH=\$PATH:\$GOPATH/bin' >> /root/.zshrc
       fi
      check_root_bashrc=$(cat /root/.bashrc | grep -c GOPATH)
       if [ $check_root_bashrc -ne 0 ]
        then
         echo -e "\n  $redminus GOPATH Variables for $findrealuser already exist in /root/.bashrc - Not changing"
        else
         echo -e "\n  $greenplus Adding GOPATH Variables to /root/.bashrc"
         eval echo -e 'export GOPATH=\$HOME/go' >> /root/.bashrc
         eval echo -e 'export PATH=\$PATH:\$GOPATH/bin' >> /root/.bashrc
       fi
     else
      check_user_zshrc=$(cat /home/$findrealuser/.zshrc | grep -c GOPATH)
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

fix_smbconf () {
    check_min=$(cat /etc/samba/smb.conf | grep -c -i "client min protocol")
    check_max=$(cat /etc/samba/smb.conf | grep -c -i "client max protocol")
    if [ $check_min -ne 0 ] || [ $check_max -ne 0 ]
      then
        echo -e "\n  $green /etc/samba/smb.conf "
        echo -e "\n  $redminus client min protocol is already set not changing\n  $redminus client max protocol is already set not changing"
      else
        cat /etc/samba/smb.conf | sed 's/\[global\]/\[global\]\n   client min protocol = CORE\n   client max protocol = SMB3\n''/' > /tmp/fix_smbconf.tmp
        cat /tmp/fix_smbconf.tmp > /etc/samba/smb.conf
        rm -f /tmp/fix_smbconf.tmp
        echo -e "\n  $greenplus /etc/samba/smb.conf updated"
        echo -e "\n  $greenplus added : client min protocol = CORE\n  $greenplus added : client max protocol = SMB3"
    fi
    }

fix_grub () {
    check_grub=$(cat /etc/default/grub | grep -i -c "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"" )
    if [ $check_grub -ne 1 ]
      then
        echo -e "\n  $redexclaim Error: /etc/default/grub is not the default config - not changing"
      else
        cat /etc/default/grub | sed 's/GRUB_CMDLINE_LINUX_DEFAULT="quiet"/GRUB_CMDLINE_LINUX_DEFAULT="quiet mitigations=off"/' > /tmp/fix_grub.tmp
        cat /tmp/fix_grub.tmp > /etc/default/grub
        rm -f /tmp/fix_grub.tmp
        update-grub
        echo -e "\n  $greenplus Added mitigations=off to GRUB_CMDLINE_LINUX_DEFAULT"
	      echo -e "\n  $redexclaim Reboot for changes to take effect \n"
    fi
    }

fix_python_requests () {
    eval git clone https://github.com/psf/requests /opt/requests
    cd /opt/requests
    eval pip install colorama
    eval pip install .
    echo -e "\n  $greenplus installed python2 module : requests"
    echo -e "\n  $greenplus installed python2 module : colorama"
    }

fix_bad_apt_hash () {
    mkdir -p /etc/gcrypt
    echo "all" > /etc/gcrypt/hwf.deny
    }

install_atom () {
    if [ -f /usr/bin/atom ]
     then
       echo -e "\n  $greenminus atom already installed - skipping"
    else
      apt_update  && apt_update_complete
      echo -e "\n  $greenplus installing atom"
      eval wget -qO- https://atom.io/download/deb -O /tmp/atom.deb >/dev/null 2>&1
      eval dpkg -i /tmp/atom.deb >/dev/null 2>&1
      eval rm -f /tmp/atom.deb
      eval apt -y --fix-broken install >/dev/null 2>&1
    fi
    }

install_sublime () {
    echo -e "\n  $greenplus installing sublime text editor"
    eval wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | sudo apt-key add -
    eval apt-get install apt-transport-https
    eval echo "deb https://download.sublimetext.com/ apt/stable/" > /etc/apt/sources.list.d/sublime-text.list
    apt_update && apt_update_complete
    eval apt -y install sublime-text
    }

# 06.01.21 - Function rewrite code-oss was added to Kali 2021.2 repo
install_vscode () {
    if [[  -f /usr/bin/code ]]; then
      echo -e "\n  $greenminus  vscode already installed - skipping"
    else
    	echo -e "\n  $greenplus installing vscode"
      apt_update && apt_update_complete && apt -y install code-oss
      echo -e "\n  $greenplus  vscode - installed "
    fi
    }

fix_sources () {
    fix_bad_apt_hash
    # new fix_sources main function - 04.06.2021 rev 1.2.2

    check_space=$(cat /etc/apt/sources.list | grep -c "# deb-src http://http.kali.org/kali kali-rolling main contrib non-free")
    check_nospace=$(cat /etc/apt/sources.list | grep -c "#deb-src http://http.kali.org/kali kali-rolling main contrib non-free")

    if [[ $check_space = 0 && $check_nospace = 0 ]]; then
    	echo -e "\n  $greenminus # deb-src or #deb-sec not found - skipping"
    elif [ $check_space = 1 ]; then
      echo -e "\n  $greenplus # deb-src with space found in sources.list uncommenting and enabling deb-src"
      cat /etc/apt/sources.list | sed 's/\# deb-src http\:\/\/http\.kali\.org\/kali kali-rolling main contrib non\-free/\deb-src http\:\/\/http\.kali\.org\/kali kali-rolling main contrib non\-free''/' > /tmp/new-sources.list
      cat /tmp/new-sources.list > /etc/apt/sources.list
      rm  /tmp/new-sources.list
      echo -e "\n  $greenplus new /etc/apt/sources.list written with deb-src enabled"
    elif [ $check_nospace = 1 ]; then
      echo -e "\n  $greenplus #deb-src without space found in sources.list uncommenting and enabling deb-src"
      cat /etc/apt/sources.list | sed 's/\#deb-src http\:\/\/http\.kali\.org\/kali kali-rolling main contrib non\-free/\deb-src http\:\/\/http\.kali\.org\/kali kali-rolling main contrib non\-free''/' > /tmp/new-sources.list
      cat /tmp/new-sources.list > /etc/apt/sources.list
      rm  /tmp/new-sources.list
      echo -e "\n  $greenplus new /etc/apt/sources.list written with deb-src enabled"
    fi
    }

run_update () {
    fix_sources
    echo -e "\n  $greenplus starting: pimpmyupgrade   \n"
    apt_update && apt_update_complete
    kernel_check=$(ls /lib/modules | sort -n | tail -n 1)
    echo -e "\n  $greenplus installing dkms build-essential linux-headers-$kernel_check \n"
    eval apt -y install dkms build-essential linux-headers-amd64 $silent
    }

make_rootgreatagain () {
    echo -e "\n\n KALI-ROOT-LOGIN INSTALLATION: - PAGE 1   "$red"*** READ CAREFULLY! ***"$white" \n"
    echo -e "   On Kali 2019.x and prior the default user was root"
    echo -e "   On Kali 2020.1 and newer this was changed, the default user was changed to be "
    echo -e "   an" $yellow$bold"actual user"$norm$white" on the system and not "$red$bold"root"$norm$white", this user is : kali (by default) "
    echo -e "\n   Press Y - If you wish to re-enable the ability to login as root and be root all the time"
    echo -e "     If you choose Yes - a second screen will prompt you to copy all of /home/kali to /root"
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

enable_rootlogin () {
    section="kali-root-login"
    check=$(whereis kali-root-login | grep -i -c "kali-root-login: /usr/share/kali-root-login")
    fix_section $section $check $force
    echo -e "\n\nEnabling Root Login Give root a password"
    passwd root
    echo -e "\n  $greenplus root login enabled \n"
    ask_homekali_to_root
    }

# 01.02.2021 - rev 1.1.2 begin - new screens for copying from /home/kali to /root, no detection, all based on used input
ask_homekali_to_root () {
    echo -e "\n\n KALI-ROOT-LOGIN INSTALLATION: - PAGE 2   "$red"*** READ CAREFULLY! ***"$white" \n"
    echo -e "   This section of the script is only executed if Yes was selected at the enable root login prompt\n"
    echo -e "   If you are planning on operating your kali install as root instead of the user kali, "
    echo -e "   by default there is nothing in /root, This script has the ability to copy everything"
    echo -e "   from /home/kali to /root for you. \n"
    echo -e "  $red Warning:$white This copy function $red will overwrite $white anything in /root with the entire contents of /home/kali"
    echo -e "   The copy statement that is going to be performed if you select Y is:\n "
    echo -e "    cp -Rvf /home/kali/* /home/kali/.* /root"
    echo -e "\n   Would you like to copy everything from /home/kali to /root ?"
    echo -e "     Press Y - to copy everything from /home/kali to /root"
    echo -e "     Press N - do not copy anything to /root and skip this function\n"
    read -n1 -p "   Please type Y or N : " userinput
      case $userinput in
        y|Y) ask_are_you_sure;;
        n|N) echo -e "\n\n  $redexclaim skipping copy of /home/kali to /root" ;;
        *) echo -e "\n\n  $redexclaim Invalid key try again, Y or N keys only $redexclaim"; ask_homekali_to_root;;
      esac
    }

# 01.03.2021 - rev 1.1.3 begin - added are you sure prompt
ask_are_you_sure () {
    echo -e "\n\n   Are you sure you want to copy all of /home/kali to /root ?"
    read -n1 -p "   Please type Y or N : " userinput
      case $userinput in
       y|Y) perform_copy_to_root;;
       n|N) echo -e "\n\n  $redexclaim skipping copy fo /home/kali to /root - not copying ";;
       *) echo -e "\n\n  $redexclaim Invalid key try again, Y or N keys only $redexclaim"; ask_are_you_sure;;
     esac
    }

# 01.02.2021 - rev 1.1.2 - copy to /root warning screens and function
perform_copy_to_root () {
    echo -e "\n\n  $greenplus Copying everything from /home/kali to /root... Please wait..."
    # add call to check_helpers here before doing the copy from /home/kali to /root
    eval cp -Rvf /home/kali/.* /home/kali/* /root >/dev/null 2>&1
    eval chown -R root:root /root
    echo -e "\n  $greenplus Everything from /home/kali has been copied to /root"
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


fix_sead_warning () {
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

fix_sead_run () {
    apt_update && apt_update_complete
    python-pip-curl
    python3_pip
    eval pip  uninstall impacket -y $silent
    eval pip3 uninstall impacket -y $silent
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

fix_impacket_array () {
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

fix_impacket () {
    eval apt -y remove impacket $silent    ## do not remove : python3-impacket impacket-scripts
    python-pip-curl
    python3_pip
    eval pip uninstall impacket -y $silent
    eval pip3 uninstall impacket -y $silent
    fix_impacket_array
    eval wget https://github.com/SecureAuthCorp/impacket/releases/download/impacket_0_9_19/impacket-0.9.19.tar.gz -O /tmp/impacket-0.9.19.tar.gz $silent
    eval tar xfz /tmp/impacket-0.9.19.tar.gz -C /opt $silent
    cd /opt
    chown -R root:root impacket-0.9.19
    chmod -R 755 impacket-0.9.19
    cd /opt/impacket-0.9.19
    eval pip3 install lsassy $silent
    eval pip install flask $silent
    eval pip install pyasn1 $silent
    eval pip install pycryptodomex $silent
    eval pip install pyOpenSSL $silent
    eval pip install ldap3 $silent
    eval pip install ldapdomaindump $silent
    eval pip install wheel $silent
    eval pip install .  $silent
    rm -f /tmp/impacket-0.9.19.tar.gz
    eval apt -y reinstall python3-impacket impacket-scripts $silent
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

only_upgrade () {
    fix_sources
    echo -e "\n  $greenplus starting pimpmyupgrade   \n"
    apt_update && apt_update_complete && apt_upgrade && apt_upgrade_complete
    run_update
    virt_what
    check_vm
    }

fix_upgrade () {
    fix_sources
    apt_update && apt_update_complete
    run_update
    apt_upgrade && apt_upgrade_complete
    virt_what
    check_vm
    }

bpt () {
    rm -rf /opt/the-essentials
    git clone https://github.com/blindpentester/the-essentials /opt/the-essentials
    cd /opt/the-essentials
    sh -c '/opt/the-essentials/the_essentials.sh --skip'
    exit_screen
    }

downgrade_msf () {
    eval apt -y remove metasploit-framework
    wget https://archive.kali.org/kali/pool/main/m/metasploit-framework/metasploit-framework_5.0.101-0kali1%2Bb1_amd64.deb -O /tmp/metasploit-framework_5.deb
    eval dpkg -i /tmp/metasploit-framework_5.deb
    eval gem cleanup reline
    eval msfdb init
    rm -f /tmp/metasploit-framework_5.deb
    apt-mark hold metasploit-framework
    echo -e "\n  $greenplus metasploit downgraded \n"
    echo -e "\n  $greenplus hold placed on metasploit-framework \n"
    }
gnome_disable_power_save () {
    gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-type nothing #(Disables automatic suspend on charging)
    gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-battery-type nothing #(Disables automatic suspend on battery)
    gsettings set org.gnome.settings-daemon.plugins.power power-button-action nothing #(Power button does nothing)
    gsettings set org.gnome.settings-daemon.plugins.power idle-brightness 0
    gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-battery-timeout 0
    gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-timeout 0
}
virt_what() {
    # Upgraded virt-what function - 04.07.2021 rev 1.2.2
    [ -f "/usr/sbin/virt-what" ] && virtwhat=1 || virtwhat=0

    if [ $virtwhat = 1 ]
     then
       echo -e "\n  $greenminus virt-what already installed - skipping \n"
     else
       echo -e "\n  $greenplus installing virt-what \n"
       eval apt -y install virt-what $silent
    fi
    }

vbox_fix_shared_folder_permission_denied () {
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
     wget http://download.virtualbox.org/virtualbox/LATEST.TXT -O /tmp/vbox-latest
     vboxver=$(cat /tmp/vbox-latest)
     # get new iso and place over old one in /usr/share/virtualbox
     wget http://download.virtualbox.org/virtualbox/$vboxver/VBoxGuestAdditions_$vboxver.iso -O /usr/share/virtualbox/VBoxGuestAdditions.iso
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
    qemu_check=$(virt-what | grep -i -c "kvm")           # m4ul3r Qemu/libvirt check
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
          eval apt -y reinstall open-vm-tools-desktop fuse $silent
          echo -e "\n  $greenplus restarting vmware tools"
          eval restart-vm-tools
          # Additional Fixes for Vmware
          #----------------------- additional vmware fixes
          #
          #----------------------- end of vmware additional fixes
          # exit_screen
       elif  [ $qemu_check = 1 ]
         then
          echo -e "\n  $greenplus *** QEMU/LIBVIRT DETECTED *** \n"
          eval apt -y reinstall xserver-xorg-video-qxl spice-vdagent
          echo -e "\n  $greenplus installing xserver-xorg-video-qxl spice-vdagent"
      else
        echo -e "\n $redstar Hypervisor not detected, Possible bare-metal installation not updating"
    fi
    }

# ascii art - DONT move
asciiart=$(base64 -d <<< "H4sIAAAAAAAAA31QQQrCQAy89xVz9NR8QHoQH+BVCATBvQmC
CEXI480kXdteTJfdzGQy2S3wi9EM/2MnSDm3oUoMuJlX3hmsMMSjA4uAtUTsSQ9NUkkKVgKKBX
p1lEC0auURW3owsQlTZtf4QtGZgjXYKT4inPtI23oEK7wXlyPnd8arKdKE0EPdUnhIf0v+iE2o
7BgVFVyec3u1OxFw+uRxbvPt8R6+MOpGq5cBAAA="  | gunzip )

pimpmykali_menu () {
    # DATE=$(date +%x); TIME=$(date +%X)
    clear
    echo -e "$asciiart"
    echo -e "\n     Select a option from menu:                           Rev:$revision"
    #echo -e "\n     $DATE $TIME                               Rev:$revision"
    echo -e "\n     *** APT UPGRADE WILL ONLY BE CALLED FROM MENU OPTION 9 ***"
    echo -e "\n  Menu Options:"                                                                   # function call list
    echo -e "\n  1 - Fix Missing             (pip pip3 golang gedit nmapfix build-essential)"     # fix_missing
    echo -e "  2 - Fix /etc/samba/smb.conf (adds the 2 missing lines)"                            # fix_smbconf
    echo -e "  3 - Fix Golang              (installs golang, adds GOPATH= to .zshrc and .bashrc)" # fix_golang
    echo -e "  4 - Fix Grub                (adds mitigations=off)"                                # fix_grub
    echo -e "  5 - Fix Impacket            (installs impacket)"                                   # fix_impacket
    echo -e "  6 - Enable Root Login       (installs kali-root-login)"                            # make_rootgreatagain
    echo -e "  7 - Install Atom            (installs atom)"                                       # install_atom
    echo -e "  8 - Fix nmap scripts        (clamav-exec.nse and http-shellshock.nse)"             # fix_nmap
    echo -e "  9 - Pimpmyupgrade           (apt upgrade with vbox/vmware detection)"              # only_upgrade
    echo -e "                              (sources.list, linux-headers, vm-video )"              # -
    echo -e "                              (will not upgrade: metasploit-framework)"              # -
    echo -e "  0 - Fix ALL                 (runs only 1 thru 8) \n"                               # fix_all
    echo -e "  N - NEW VM SETUP - Run this option if this is the first time running pimpmykali"   # menu item only no function
    echo -e "                     This will run Fix All (0) and Pimpmyupgrade (9)\n"              #
    echo -e "  Stand alone functions (only apply the single selection)"                           # optional line
    echo -e "  F - Broken XFCE Icons fix   (stand-alone function: only applies broken xfce fix)"  # fix_broken_xfce
    echo -e "  W - Gowitness Precomiled    (download and install gowitness)"                      # fix_gowitness
    echo -e "  G - Fix Gedit Conn Refused  (fixes gedit as root connection refused)"              # fix_root_connectionrefused
    echo -e "  C - Missing Google-Chrome   (install google-chrome only)"                          # check_chrome / fix_chrome
    echo -e "  V - Install MS-Vscode       (install microsoft vscode only)"                       # install_vscode
    echo -e "  S - Fix Spike               (remove spike and install spike v2.9)"                 # fix_spike
    echo -e "  ! - Nuke Impacket           (Type the ! character for this menu item)"             # fix_sead_warning
    echo -e "  D - Downgrade Metasploit    (Downgrade from MSF6 to MSF5)"                         # downgrade_msf  # - commented out 04.06.2021
    echo -e "  B - BlindPentesters         'The Essentials' tools & utilies collection\n"         # bpt
    echo -e "  P - DisablePowerSavingOptions (Disables all Power Saving options for gnome Desktop Environment)\n" # gnome_disable_power_save
    read -n1 -p "  Enter 0 thru 9, N, B, F, G, C, V, S or ! press X to exit: " menuinput

    case $menuinput in
        1) fix_missing;;
        2) fix_smbconf;;
        3) fix_golang;;
        4) fix_grub;;
        5) fix_impacket;;
        6) make_rootgreatagain;;
        7) install_atom;;
        8) fix_nmap ;;
        9) only_upgrade;;
        0) fix_all; run_update; virt_what; check_vm;;
        !) forced=1; fix_sead_warning;;
      f|F) fix_broken_xfce;;
      s|S) fix_spike;;
      g|G) fix_root_connectionrefused ;;
      c|C) check_chrome;;
      v|V) install_vscode;;
      w|W) fix_gowitness;;
      n|N) fix_all; fix_upgrade;;
      d|D) downgrade_msf;;
      b|B) bpt;;
      p|P) gnome_disable_power_save;;
      # h|H) fix_theharvester ;;
      x|X) echo -e "\n\n Exiting pimpmykali.sh - Happy Hacking! \n" ;;
      *) pimpmykali_menu ;;
    esac
    }

pimpmykali_help () {
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

check_arg () {
    if [ "$1" == "" ]
      then pimpmykali_menu
     else
      case $1 in
      --menu) pimpmykali_menu                  ;;
       --all) fix_all                          ;;
       --smb) fix_smbconf                      ;;
        --go) fix_golang                       ;;
  --impacket) fix_impacket                     ;;
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
      --subl) install_sublime                  ;; # hidden switch
      --atom) install_atom                     ;;
   --upgrade) only_upgrade                     ;;
# --harvester) fix_theharvester                ;;
      *) pimpmykali_help ; exit 0              ;;
    esac
    fi
    }

exit_screen () {
    eval apt -y --fix-broken install >/dev/null 2>&1
    echo -e "$asciiart"
    echo -e "\n\n    All Done! Happy Hacking! \n"

    exit
    }

check_for_root
check_distro
check_arg "$1"
exit_screen
