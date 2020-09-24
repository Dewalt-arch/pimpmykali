# pimpmykali.sh - rev 0.1 

Kali Linux Fixes for Newly Imported VM's

Installation :
    - Download pimpmykali.sh 
    - chmod +x pimpmykali.sh 
    - sudo ./pimpmykali.sh 
    
Fixes : 
    python-pip missing
    
    python3-pip missing
    
    seclists not installed
    
    golang not installed (or configured)
        - adds path statements to .bashrc
        
    kali-root-login installed and reneables root login
        - reworked and added prompt
        
    impacket-0.9.19
        - removes any prior installation of impacket ( gracefully and forced ) 
        - installs impacket-0.9.19 
        - installs python-wheel ( python2 wheel )  
        
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
       
   
