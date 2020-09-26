# pimpmykali.sh

Kali Linux Fixes for Newly Imported VM's

Installation :
    - Download pimpmykali.sh 
    - chmod +x pimpmykali.sh 
    - sudo ./pimpmykali.sh 
    
- Added colorized notifications, help system, command line arguements, case based menu system
- valid command line arguements are: help, all, go, grub, impacket, missing, menu, smb, grub, root
- anything other than --all or -all or all , will only run that function and then exit.
- command line arguements can be used with -- or - or just the word itself to try can catch for all possible cases
 
- example command line var: --help or -help or help will catch help and works for all valid command line arguements
  anything other the command line arugement catch exits and displays help 

Fixes
    python-pip missing
    
    python3-pip missing
    
    seclists not installed
    
    golang not installed 
        - adds path statements to .bashrc
        
    kali-root-login installed and reneables root login
        - reworked and added prompt
        
    impacket-0.9.19
        - removes any prior installation of impacket
        - installs impacket-0.9.19 
        - installs python wheel
        
    fixes smb.conf
        - add 2 lines below [global] for min max protocol
          - client min protocol = CORE
          - client max protocol = SMB3
          
    .bashrc alias and functions 
        - adds command ex function to extract from any archive with 1 command ex 
        - vpnip - displays tun0 ip address in the terminal via vpnip alias 
        
    .bashrc 
        - added /sbin to user path, can now ifconfig without sudo 

    grub added detection of default /etc/default/grub
        - added mitigations=off 
       
   
