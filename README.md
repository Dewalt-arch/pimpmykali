# pimpmykali.sh 

Kali Linux Fixes for Newly Imported VM's

Fixes : 
    python-pip missing
        - no reason this should be missing from a pentest distro
    
    python3-pip missing
        - no resson this should be missing from a pentest distro
    
    seclists not installed
        sudo apt install seclists 
        - can be found in /usr/share/seclists 
        
    golang not installed (or configured)
        - adds path statements to .bashrc 
        
    kali-root-login installed and reneables root login 
    
    impacket-0.9.19
        - removes any prior installation of impacket ( gracefully and forced ) 
        - installs impacket-0.9.19 
        - installs python-wheel ( python2 wheel ) 
        
    fixes smb.conf ( ADD 2 DAMN LINES OFFSEC!!! YA THATS RIGHT IM CALLING YOU OUT ON IT ) 

    .bashrc alias and functions 
        - adds command ex function to extract from any archive with 1 command ex 
        - vpnip - displays tun0 ip address in the terminal via vpnip alias 
        
    .bashrc 
        - added /sbin to user path, can now ifconfig without sudo 
    
    /etc/default/grub
        - added "migitgations=off" and updates grub
    

          
