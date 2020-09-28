# pimpmykali.sh

# Fixes for new imported Kali Linux virtual machines
- could be used on a bare metal machines, but thats on you

# Github index updated added +x permission: 
- Script should now be executable upon clone (perms: 755 rwxr-xr-x added to github) 
  - you should not need to chmod +x pimpmykali.sh upon clone

# Installation script:
- git clone https://github.com/Dewalt-arch/pimpmykali
- cd pimpmykali
- chmod +x pimpmykali.sh 
- sudo ./pimpmykali.sh

# Revision 0.3a: 
- the extraction of the impacket-0.9.19.tar.gz was leaving /opt/impacket-0.9.19 with 700 perms
  and an ownership of 503:root, this has been changed to ownership root:root and all files inside
  /opt/impacket-0.9.19 have had their permissions set to 755 after extraction of impacket-0.9.19.tar.gz
- Ascii art added to the menu
  
# Revision 0.3: 
- added checks for already installed installations, added --force command ( --force will run all fixes/reinstalls )
- fix_impacket function : added both .py and .pyc files to impacket removal array
  - added on screen notification of files being removed by the array
- fix_missing function  : has been reworked new vars check section force type
  - added fix_section function : fix_section is the workhorse for fix_missing
- reworked python-pip installation to its own function python-pip-curl and installs python-pip via curl 

# Revision 0.2: 
- Added colorized notifications, help system, command line arguements, case based menu system
- valid command line arguements are: help, all, go, grub, impacket, missing, menu, smb, grub, root
- anything other than --all or -all or all , will only run that function and then exit.
- command line arguements can be used with -- or - or just the word itself to try can catch for all possible cases
 
- example command line var: --help or -help or help will catch help and works for all valid command line arguements
  anything other the command line arugement catch exits and displays help 

# Fixes : 
- python-pip now removed from kali repos, installation via curl 
- python3-pip not installed
- seclists not installed
- golang not installed 
- kali-root-login not installed and reneables root login
  - reworked and added prompt
- impacket-0.9.19
  - removes any prior installation of impacket (gracefully and forcefully)
  - installs impacket-0.9.19 
  - installs python-pip via curl 
  - installs python wheel
- /etc/samba/smb.conf
  - adds the 2 lines below [global] for min max protocol
  - client min protocol = CORE
  - client max protocol = SMB3
- grub added detection of default /etc/default/grub
  - added mitigations=off 

# TODO   
- .bashrc alias and functions ( currently commented out and is not a part of the running script ) 
  - adds command ex function to extract from any archive with 1 command ex 
  - vpnip - displays tun0 ip address in the terminal via vpnip alias 
  - added /sbin to user path, can now ifconfig without sudo
