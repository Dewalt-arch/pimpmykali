# pimpmykali.sh

[![image.png](https://i.postimg.cc/BvYg4n1d/image.png)](https://postimg.cc/5Hzvm1g3)

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

# Revision 1.2.8 - Kali 2021.2 Updates
  - Changed installation for VSCode to use code-oss from repo
  - Virtualbox guest-os-tools were being installed twice - fixed
  - Added check for atom, if already installed, skip installation
  - misc minor fixes / cosmetic fixes
  -
  - Complete revision history has been moved to changelog.txt
    - clean up the readme.md page
    - Most recent update will always be displayed in readme.md (this page)

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
    - gunzip's /usr/share/wordlists/rockyou.gz to /usr/share/wordlists/rockyou.txt
  - fix_golang function
    - installs golang
    - adds golang GOPATH to .bashrc and .zshrc
  - installs htop
  - installs python requests
  - installs python xlrd
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
    - copy /home/kali to /root prompt (1.1.2)
    - added are you sure? prompt to copy /home/kali to /root prompt (1.1.3)

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
  - Executes ONLY Menu options 1 thru 8 Only

- Menu Option B    
  - BlindPentesters The_Essentials tools and utilities collection
    - Install all of BlindPentesters favorite tools and utilities to /opt (aprox 8GB)
    - Click the link below for a full list of the_essentials.sh script and its inner workings
    - https://github.com/blindpentester/the-essentials

- Menu Option F
  - Fixes XFCE Broken Icons "TerminalEmulator" Not Found
  - Fixes XFCE Open Catfish instead of Thunar when double clicking Home or FileSystem Icon
    - this fix is a temporary fix and will be removed once xfce has been corrected

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

# TODO   
  - clean up todo list :)
