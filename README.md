# pimpmykali.sh

[![rev1-2-9.png](https://i.postimg.cc/z3ZnQvzf/rev1-2-9.png)](https://postimg.cc/gLsXXY69)

# Fixes for new imported Kali Linux virtual machines
  - Author assumes zero liability for any data loss or misuse of pimpmykali
  - Can be used on a bare metal machines, but thats on you
  - Menu breakdown added below revision history

# Github index updated added +x permission:
  - Script is now be executable upon clone (perms: 755 rwxr-xr-x added to github)
  - There is no need to chmod +x pimpmykali.sh upon git clone

# Installation script:
  - rm -rf pimpmykali/
  - git clone https://github.com/Dewalt-arch/pimpmykali
  - cd pimpmykali
  - sudo ./pimpmykali.sh
  - For a new kali vm, run menu option N

# Code Contributors
  - blindpentester https://github.com/blindpentester
  - pswalia2u https://github.com/pswalia2u
  - Alek https://github.com/onomastus
  - Gr1mmie https://github.com/Gr1mmie
  - Aksheet https://github.com/Aksheet10
  - 0xC0FFEE Home Lab Build
    https://docs.google.com/document/d/1DH-epmXJMvQtOnDQYa3zUXvq9497Mm3276K8frNz2UM

# Revision 1.3.1 - Minor quality of life improvements
  - Minor code cleanup

# Revision 1.3.0 - TheMayor's Movement, Pivoting and Persistance course requirements for kali linux added
  - This is a stand alone function and is not called by any other part of Pimpmykali
  - Menu option M - setup for Mayors Movement, Pivoting and Persistance course
    - installs covenant and all additional required packages
    - downgrades msf to v5 ( auto-magic it is not going to ask about it )
    - creates startup script for covenant /usr/local/bin/startcovenant.sh
      - script checks if covenant is already running, if it is, kill covenant and start
      - otherwise just start covenant
    - startcovent.sh script is symlinked to /usr/local/bin/covenant for easy startup
    - command line to start covenant is 'covenant' from anywhere as it is in the /usr/local/bin path
    - creates desktop icon for "Start Covenant"
      - final desktop icon for "Start Covenant" has not been finalized and may change without notice  
  - Added environment variable to remove restart services on apt upgrade, will now default to this setting
  - Special Note:
  - Pimpmykali has been stored in the github arctic vault! (dont ask for updates in 1000 years)

# Menu Breakdown of Pimpmykali

- Menu option N  (New Users/New VM's Should start here!)
  - executes menu option 0 fix all ( menu options 1 thru 8 )
  - executes menu opiion 9 (pimpmyupgrade)

- Menu Option 1 - Fix missing
  - fix_sources
    - uncomment #deb-src from /etc/apt/sources.list
  - python-pip installation via curl
  - python3-pip installed
  - seclists installed
  - gedit installed (feature request)
  - flameshot installed (feature request)
  - locate installed (feature request)
  - fix_rockyou function
    - gunzip /usr/share/wordlists/rockyou.gz to /usr/share/wordlists/rockyou.txt
  - fix_golang function
    - installs golang
    - adds golang GOPATH to .bashrc and .zshrc
  - installs htop
  - installs python requests
  - installs python xlrd==1.2.0
  - disables xfce power management
  - blacklists pcspkr kernel module /etc/modprobe.d/nobeep.conf

- Menu Option 2 - Fix smb.conf
  - Fix /etc/samba/smb.conf
    - adds client min protocol = CORE  below [global]
    - adds client max protocol = SMB3  below [global]

- Menu Option 3 - Fix Golang
  - Installs golang
    - checks for GOPATH in .bashrc and .zshrc
    - if GOPATH is found, adds nothing
    - if not found, adds GOPATH statements to both .zshrc and .bashrc

- Menu Option 4 - Fix Grub
  - adds mitigations=off to GRUB_CMDLINE_LINUX_DEFAULT

- Menu Option 5
  - installs Impacket-0.9.19

- Menu Option 6 - Enable root login
  - installs kali-root-login
    - prompts for root password
    - copy /home/kali/* to /root prompt (1.1.2)
    - prompt are you sure? to copy /home/kali to /root prompt (1.1.3)

- Menu Option 7
  - installs Atom text editor

- Menu Option 8 - Fix Nmap
  - wget nmap script fixes
    - clamav-exec.nse
    - http-shellshock.nse (Thank you Alek!)

- Menu Option 9 - Pimpmyupgrade
  - additional notes will be added
  - fix : Hypervisor detection (vmware, virtualbox, qemu/libvirt)
    - add additional details here
  - fix : virtualbox shared folder fix applied     

- Menu Option 0 - Fix all (1-8)
  - Executes ONLY Menu options 1 thru 8

- Menu Option P - Disable Power Management
  - Based upon detection disable power management for that environment
  - Detect desktop environment
    - XFCE
    - Gnome

- Menu Option F
  - Fixes XFCE Broken Icons "TerminalEmulator" Not Found
  - Fixes XFCE Open Catfish instead of Thunar when double clicking Home or FileSystem Icon
    - this fix is a temporary fix and will be removed once xfce has been corrected

- Menu Option W
  - Install GoWitness precompiled binary

- Menu Option G
  - Apply gedit unable to open display as root fix

- Menu Option C
  - Install Google-Chrome

- Menu Option V
  - Install MS VSCode

- Menu Option S - Fix Spike
  - Fixes undefined symbol error thrown when using generic_send_tcp
    - this fix is temporary and will be removed once a corrected version is available

- Menu Option D - Downgrade metasploit-framework from 6 to 5
  - downgrades metasploit-framework (msfconsole) from msf6 to msf5
  - this is a temporary solution and will eventually be removed once a corrected version is available

- Menu Option ! - Nuke Impacket (yes its literally the ! character)
  - removes any prior installation of impacket (gracefully and forcefully)
    - installs impacket-0.9.19
    - installs python-pip via curl
    - installs python wheel

- Menu Option B    
  - BlindPentesters The_Essentials tools and utilities collection
    - Install all of BlindPentesters favorite tools and utilities to /opt (aprox 8GB)
    - Click the link below for a full list of the_essentials.sh script and its inner workings
    - https://github.com/blindpentester/the-essentials

- Menu Option Q
  - Set Qterminal for unlimited scrollback
     - check for HistoryLimited=True in ~/.config/qterminal.org/qterminal.ini
       - if found set HistoryLimited=False (unlimited scrollback)
       - if already set to False, exit function     

# TODO   
  - clean up todo list :)
