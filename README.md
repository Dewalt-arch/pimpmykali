# pimpmykali.sh

![pmk2 0 0](https://github.com/user-attachments/assets/08cdd9c8-83c7-41e0-a65c-8bf7690a7f36)


# Fixes for new imported Kali Linux virtual machines
  - Author assumes zero liability for any data loss or misuse of pimpmykali
  - Baremetal installations are unsupported
  - WSL/WSL2 installations are unsupported
  - Menu breakdown added below revision history

# Github index updated added +x permission:
  - Script is now be executable upon clone (perms: 755 rwxr-xr-x added to github)
  - There is no need to chmod +x pimpmykali.sh upon git clone

# Installation:
```console
# Remove existing pimpmykali folder
rm -rf pimpmykali/

# Clone pimpmykali repository & enter the folder
git clone https://github.com/Dewalt-arch/pimpmykali

cd pimpmykali

# Execute the script - For a new Kali VM, run menu option 'N'
# (The script must be run with root privileges)
sudo ./pimpmykali.sh

# Use --auto command line arg to bypass the menu and prompts

# Use --help for full list of available command line args
```

# Special Thanks to Pimpmykali-Mirrors Testers!!
  - Crazy_Man - https://github.com/The-Crazy-Man
  - Andro

# Code Contributors
  - Yaseen - https://github.com/AhamedYaseen03
  - Crazy_Man - https://github.com/The-Crazy-Man
  - blindpentester https://github.com/blindpentester
  - pswalia2u https://github.com/pswalia2u
  - Alek https://github.com/wodensec
  - Gr1mmie https://github.com/Gr1mmie
  - Aksheet https://github.com/Aksheet10
  - 0xC0FFEE VirtualBox Home Lab Build (updated link!)
    https://benheater.com/building-a-security-lab-in-virtualbox/
  - TheMadHuman https://github.com/TMH-Sec
  - Aashiksamuel https://github.com/aashiksamuel  (sublime install fix)
  - m4ul3r 
  - lbalmaceda https://github.com/lbalmaceda
1
# Writeups / Honorable Mentions
  - ip3c4c_n00b https://ip3c4c.com/2202_homelab_vmware/

# Revision 2.0.4 - Signing key fix
  - new function new_kali_signingkey
    - executed before each menu function
    - check if new signing key is already installed
      - if installed, skip
      - if not installed
        - download new signing key
        - sha1sum checksum verification of signing key
        - if checksum is valid, install new signing key
    - updated --commands to check for new signing key
    - added --fixsignkey to command line options
    - Standalone menu option S

# Revision 2.0.3 - arm64 + nukeimpacket
  - added arch check to function
    - if arch = arm64 exit 
    - if arch = amd64 continue

# Revision 2.0.2 - updated fix_ghidra function
  - updated DOWNLOAD_URL variable

# Revision 2.0.1 - updated install impacket-0.9.19
  - updated install_pip2_modules function
  - updated install_old_impacket function

# Revision 2.0.0 - Release
- New additions and feature requests
  - Menu option verification before execution 
    - on screen notification of which menu option is selected
    - y or Y to continue
    - n or N returns to main menu
  - speedrun variable to bypass menu and prompts 
  - --auto command line switch, uses speedrun var
    - set speedrun var to 1
    - bypasses menu and prompts
  - --autonoroot command line switch, uses speedrun var
    - set speedrun var to 1 
    - bypasses menu, prompts, and enable root login
  - exit status checks on most all functions
    - check done via case statement
  - updated package installed lookup uses apt-cache
    - speed improvement
  - updated --help menu with new command line switches
    - --bloodhound, --netexec, --cme, and many others 
    - use --help to view list and descriptions
  - waybackrust
    - installs to /usr/bin/waybackrust
    - included in fix_missing
    - command line switch --wayback
  - plumhound
    - installs to /opt/PlumHound
    - symlinks created /usr/local/bin/PlumHound.py and /usr/local/bin/plumhound
    - included in fix_missing
    - command line switch --plumhound
  - default to python3 and pip for python3
      - python2.7 symlinked to /bin/python2
      - pip2 installed to /usr/bin/pip2
  - setup_binfmt_mount
    - checks for kernel module binfmt_misc, loads module if not loaded
    - checks /etc/fstab for binfmt_misc entry, appends to fstab if not found
    - checks for binfmt_misc mount point, mounts if not mounted
    - command line switch --binfmt
  - setup_binfmt_winexe
    - checks /proc/sys/fs/binfmt_misc for DOSWin
    - creates /proc/sys/fs/binfmt_misc/DOSWin if not found
    - installs wine
    - command line switch --binfmt-winexe

- Added functions
    - update_linux_headers
      - check for linux-headers installed after only_upgrade function
      - ensures if new kernel is installed during only_upgrade linux-headers are installed
    - is_installed, is_installed_remove, is_installed_reinstall
      - reduce redundant code, exit status checks
    - install_pip2
      - install pip2 if not already installed
      - /usr/bin/pip2
    - install_pip3
      - install pip3 if not already installed
      - /usr/bin/pip
    - install_pipx
      - install pipx
      - pipx ensurepath
    - install_pip2_modules
      - install required pip2 modules for older tooling
    - install_pip3_modules
      - check for required modules, install if not installed
    - check_dmidecode function
      - used in check_vm function

- Updated functions
  - make_rootgreatagain updated with speedrun var
    - if --auto is used, bypass menu
    - only prompt to set root password
    - moved make_rootgreatagain to the earliest part of the script
  - fix_sead_warning, fix_impacket_array, install_old_impacket
    - install impacket 0.9.19 side by side with impacket latest
    - python3 and pip for python3 as default
    - pip2 for python2
    - command line switch --nukeimpacket 
      - uses speedrun var
      - bypasses prompts
  - fix_cme
    - installs from kali repo
  - fix_netexec, fix_nxc_symlinks
    - installs from github
  - fix_seclists 
    - installs from kali repo
  - fix_smb
    - checks for client min protocol = lanman1
  - fix_golang is now install_golang 
  - check_vm
    - ensure linux-headers are installed
    - calls update_linux_headers after apt upgrade
  - fix_virtualbox
    - install additions for detected virtualbox version on hostos
  - fix_gowitness 
    - always get latest release from github
    - installs additional dependencies
  - fix_pyftpdlib 
    - updated for python3

- Replaced functions
    - python_pip_curl replaced with install_pip2
    - fix_pipxlrd, fix_python_requests replaced with install_pip2_modules

- Removed functions
    - check_chrome, function was integrated with fix_chrome

- Updated Menu items
  - Menu option N, removed apt upgrade from function
    - only menu option 9 or --upgrade will run an apt upgrade
  - updated menu option 5 - Install Impacket
    - function will install Impacket latest from kali repo
  - Reduced overall number of menu items by using command line --args

- Updated TCM Security course setup installations
  - Practical Bug Bounty 
  - C# 101 for Hackers
  - Hacking IoT
  - PEH WebLabs
  - Hacking API

- Removed deprecated courses

- change history before 2.0.0 moved to changelog.txt


# Menu Breakdown of Pimpmykali

- All menu options will require confirmation after selection
  - Y or y to continue
  - N or n to return to menu

- Menu option N  (New Users/New VM's Should start here!)
  - executes menu option 0 fix all ( options 1 thru 8 )
  - command line switch: --newvm

- Menu option = Pimpmykali-Mirrors (rev 1.3.2)
  - obtain kali mirror list and process
  - round-trip-time ping test to all mirrors, select top 10 with shortest rtt
  - small download >1MB from the top 10 mirrors, select top 5 fastest transfers
  - large download 10MB test the final 5 mirrors, select fastest transfer
  - generate new /etc/apt/sources.list with the new selected mirror
  - prompt Y or N to write new changes to /etc/apt/sources.list
    - Y writes changes /etc/apt/sources.list
      - create backup of original sources.list in /etc/apt/sources.list_date_time
      - write new deb and deb-src lines with new mirror to /etc/apt/sources.list
    - N exits and makes no change to /etc/apt/sources.list
  - command line switch: --mirrors

- Menu Option ! - Nuke Impacket
  - installs impacket 0.9.19 side by side with impacket latest
  - pip3 as default
    - /usr/bin/pip
  - python3 as default
    - /bin/python
  - python2
    - /bin/python2
  - pip2 installed via curl
    - /usr/bin/pip2
  - pip2 modules installed for impacket 0.9.19
  - command line switch: --nukeimpacket

- Menu Option @ - Install Nessus (amd64 or arm64)
  - downloads and installs the current version of Nessus 
  - starts nessusd service 
  - command line switch: --nessus

- Menu Option $ - Uninstall Nessus (amd64 or arm64) 
  - stops all nessusd service
  - uninstalls nessus 
  - command line switch: --nukenessus

- Menu Option 1 - Fix missing
  - fix_sources
    - uncomment #deb-src from /etc/apt/sources.list
  - setup binfmt_misc mount in /etc/fstab
    - mount binfmt_misc /proc/sys/fs/binfmt_misc
  - fix .hushlogin
  - install libwacom-common if not installed
  - check if linux-headers is installed
  - check if dkms is installed
  - set ssh for wide compatibility
  - disables power management
    - xfce
    - gnome
  - blacklists pcspkr kernel module 
    - /etc/modprobe.d/nobeep.conf
  - installs if not installed
    - amass
    - assetfinder
    - bloodhound
    - chisel
    - crackmapexec
    - docker-compose from github
    - enumforlinxu
    - enumforlinux-ng
    - flameshot installed
    - ffuf
    - gedit installed
      - gedit display fix applied
    - ghidra
      - adds ghidra dark theme
    - gobuster
    - gowitness latest from github
    - golang
      - adds golang GOPATH to .bashrc and .zshrc
    - google-chrome
    - htop
    - httprobe
    - linpeas/winpeas from github
      - /opt/winpeas
      - /opt/linpeas
    - locate
    - mitm6
    - nextexec from Pennnyw0rth github
      - creates symlinks in /usr/local/bin
    - neo4j
    - plumhound
    - proxychains
    - pyftpdlib for python3
    - python3-pip installed and set as the default pip
      - /usr/bin/pip
    - python2 pip via curl
      - /usr/bin/pip2
    - python3 is the default 
      - /bin/python
    - python2
      -  /bin/python2
    - installs python2 modules for older tooling
      - setuptools
      - importlib
      - flask
      - ldap3==2.5.1
      - pycryptodome
      - xlrd==1.2.0
      - scapy==2.4.0
      - colorama
      - termcolor
      - service-identity
      - requests==2.2.1
    - rockyou
      - gunzip /usr/share/wordlists/rockyou.gz
    - seclists
    - set (social engineering toolkit)
    - spike
    - sqlmap
    - sshuttle
    - vscode
      - common vscode extensions
    - waybackrust
    - wfuzz
  - command line switch: --missing

- Menu Option 2 - Fix smb.conf
  - checks for in /etc/samba/smb.conf
    - client min protocol = LANMAN1
  - command line switch: --smbconf

- Menu Option 3 - Install Golang 
  - Installs golang
    - checks for GOPATH in .bashrc and .zshrc
    - if GOPATH is found, adds nothing
    - if not found, adds GOPATH statements to both .zshrc and .bashrc
  - command line switch: --golang

- Menu Option 4 - Fix Grub
  - adds mitigations=off to GRUB_CMDLINE_LINUX_DEFAULT
  - command line switch: --grub

- Menu Option 5
  - Installs latest impacket from kali repo
  - command line switch: --impacket

- Menu Option 6 - Enable root login
  - installs kali-root-login
    - prompts for root password
    - copy /home/kali/* to /root prompt (1.1.2)
    - prompt are you sure? to copy /home/kali to /root prompt (1.1.3)
  - command line switch: --root

- Menu Option 7
  - fix_dockercompose
    - installs docker.io from kali repo
    - check if docker compose is installed or not
    - if not installed, install latest from github
    - if installed, check local version vs github version
      - install newer version if found
    - Menu option 7 is included in Menu options 0, N or 1
  - command line switch: --dockercompose

- Menu Option 8 - Fix Nmap
  - wget nmap script fixes
    - clamav-exec.nse
    - http-shellshock.nse
    - included in fix_missing
  - command line switch: --nmap

- Menu Option 9 - Pimpmyupgrade
  - ensure linunx-headers are installed before and after apt upgrade
  - Hypervisor detection (vmware, virtualbox, qemu/libvirt)
    - installs additions for detected version of virtualbox on hostos
  - virtualbox shared folder fix applied
  - command line switch --upgrade

- Menu Option 0 - Fix all (1-8)
  - Executes ONLY Menu options 1 thru 8
  - command line switches:
    - --auto 
      - bypasses menu
      - enables root login
      - only prompt is to set the root account password
    - --autonoroot
      - bypasses menu
      - bypasses prompts
      - bypasses enable root login
    - --all
      - bypasses menu
      - bypasses enable root login
      - has all prompts

- Menu Option A
  - Setup for Mobile Application Penetration Tester course
  - command line switch: --mapt

- Menu Option B
  - Installs labs for TCM Practical Bugbounty course 
  - command line switch: --pbb

- Menu Option C
  - removed, see --chrome command line switch
  - is included in Menu options 0, N or 1

- Menu Option D - Fix Gedit Connection Refused
  - removed see --gedit command line switch
    - install gedit
    - Apply gedit unable to open display as root fix
  - is included in Menu options 0, N or 1

- Menu Option E 
  - Install TCM PEH Course WebApp Labs, docker
  - command line switch: --pehweblab

- Menu Option F
  - removed see --brokenxfce command line switch
    - Fixes XFCE Broken Icons "TerminalEmulator" Not Found
    - Fixes XFCE Open Catfish instead of Thunar

- Menu Option G
  - removed see --ghidra command line switch
  - is included in Menu options 0, N or 1

- Menu option H - Fix httprobe
  - removed see --httprobe command line switch
  - is included in Menu options 0, N or 1

- Menu Option I
  - removed see --mitm6 command line switch
  - is included in Menu options 0, N or 1

- Menu Option J
  - none

- Menu Option K
  - Reconfigure Keyboard, Language and Layout + Variant

- Menu Option L
  - removed see --sublime command line switch

- Menu Option M
  - none

- Menu Option N
  - listed above at the top

- Menu Option O - Practical API Hacking Course
  - Practical API Hacking course setup 
  - amd64 and arm64 aware
  - root user and normal user aware
  - installs docker.io docker-compose
    - docker service is enabled 
  - installs postman to /opt/Postman/Postman 
    - symlink is created for /opt/Postman/Postman at /usr/bin/postman
  - cleanup.sh script created 
  - installs crAPI to $HOME/labs
  - command line switch: --api

- Menu Option P
  - Download all the peas from github
    - linpeas to /opt/linpeas
    - winpeas to /opt/winpeas

- Menu Option Q

- Disable Power Management function moved to Menu options 0, N or 1
  - Detect desktop environment
    - XFCE
    - Gnome
  - Disable power management
  - is included in Menu options 0, N or 1

- Menu Option S - Fix Signing Key
  - Fix Signing Key

- Menu Option T
  - Reconfigure Timezone

- Menu Option U
  - Install Netexec (nxc)
  - command line switch: --netexec

- Menu Option V
  - Install MS VSCode
  - command line switch: --vscode

- Menu Option X
  - exit pimpmykali.sh menu

- Menu Option Y
  - Andrew B's IoT and Hardware Hacking Course Setup 
    - install dependencies sigrok xxd zlib1g-dev liblzma-dev liblzo2-dev
    - clone sasquatch to /opt/sasquatch
    - patches sasquatch with M1-Kali.patch.txt
    - builds patched sasquatch
    - installs to /usr/local/bin/sasquatch
    - calls fix_ghidra function to install ghidra from github
    - installs ghidra dark theme to /opt/ghidra-dark-theme
  - command line switch: --iot

- Menu Option Z
  - Install course requirements for Alex T's C# 101 for Hackers
    - installs vscode
    - installs vscode course extensions
    - installs dotnet, aspnetcore, dotnet-runtime
    - adds DOTNET_ROOT path statments to $HOME/.nameofshellrc 
  - command line switch: --csharp

# Command line switches and descriptions
  - To view all command line args
    - sudo ./pimpmykali.sh --help
    - --auto  
      - set speedrun var
      - bypass menu
      - only prompt is to set password for the root account
    - --autonoroot  
      - set speedrun var 
      - bypass menu
      - bypass enable root login
      - bypass prompts
    - --all
      - run menu option 0 (fix all) 
      - all prompts
      - bypass enable root login
    - --binfmt
      - enable and mount /proc/sys/fs/binfmt_misc
    - --binfmt-winexe
      - enable dos/windows exe in binfmt_misc, installs wine
    - --bloodhound  
      - install bloodhound
    - --brokenxfce  
      - apply broken xfce fix
    - --cme  
      - install crackmapexec
    - --checkvm  
      - detect hypervisor
        - vmware
        - virtualbox
        - qemu/utm
      - install guest additions for detected hypervisor
    - --dockercompose  
      - install docker compose
    - --flameshot
      - install flameshot
    - --fixsignkey
      - fix kali linux signing key
    - --gedit
      - install gedit
      - apply fix connection refused fix
    - --golang
      - install golang
    - --gowitness
      - install gowitness latest from github
    - --ghidra
      - install ghidra from github, add dark theme
    - --grub
      - update grub
    - --help  
      - this help menu
    - --httprobe  run fix_httprobe
    - --impacket  install impacket latest
    - --nukeimpacket  
      - install impacket 0.9.19
      - python3 as default
        - /bin/python
      - pip3 as default 
        - /usr/bin/pip
      - install pip2 via curl
        - /usr/bin/pip2
    - --mirrors  
      - run pimpmykali-mirrors speedtest
    - --mitm6  
      - reinstall mitm6
    - --missing
      - run menu option 1 (fix missing)
    - --neo4j
      - install neo4j
    - --newvm  
      - menu option N new vm setup
    - --nmap  
      - run fix nmap
    - --netexec
      - install netexec from github
    - --nessus
      - download nessus latest
      - install nessus 
      - start nessusd service
    - --nukenessus
      - stop nessusd service 
      - remove nessus
    - --peas
      - get all the peas from github (linpeas/winpeas)
      - linpeas to /opt/linpeas
      - winpeas to /opt/winpeas
    - --plumhound  
      - install plumhound
      - adds symlinks in /usr/local/bin to put plumhound in $PATH
    - --root
      - set speedrun var
      - enable root login
      - only prompt is to set root account password
    - --smbconf
      - run fix smb.conf 
    - --seclists
      - install seclists
    - --spike  
      - run fix_spike function
    - --sublime
      - install sublime
    - --vscode  
      - install ms-vscode
    - --wayback  install waybackrust
    - --upgrade
      - system upgrade
      - checks for linux-headers installed after upgrade
      - hypervisor detection
        - vmware
        - virtualbox
        - qemu/utm
      - install guest additions for detected hypervisor
    - Python fixes:
      - --pip2  
        - install pip2 via curl
        - /usr/bin/pip2
      - --pip3 
        - install pip3
        - /usr/bin/pip
      - --fixpip 
          - run fix pip function
          - ensure /usr/bin/pip is for python3
      - --pipx
        - install pipx
        - pipx ensurepath
    - TCM Security course setups
      - --api  Hacking API course setup
      - --csharp  C# course setup
      - --iot  IoT Hacking course setup
      - --mapt  Mobile Application Pentester course setup
      - --pbb  Practical Bugbounty course setup
      - --pehweblab  PEH course Web Lab setup

# TODO
  - clean up todo list :)
