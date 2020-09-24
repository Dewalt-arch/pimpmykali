#!/bin/bash 
# Rev 0.1 (CODENAME: IABBSN - Im a big boy script now!) 

check_for_root () {
     if [ "$EUID" -ne 0 ]
       then echo -e "\n\nError: Script must be run with sudo ./pimpmykali.sh or as the root user\n"
       exit
     fi
     }

fix_missing () { 
     apt -y update 
     apt -y remove kali-undercover 
     apt -y install python-pip python3-pip golang seclists
     } 

make_rootgreatagain () {
     echo -e "\n Do you want to enable root login in kali?"
     read -n1 -p " Please type Y or N : " userinput
     case $userinput in
         y|Y) enable_rootlogin ;;
         n|N) echo -e "\n skipping root login setup..." ;;
         *) echo -e "\n invalid key try again Y or N"; make_rootgreatagain ;;
     esac
     }

enable_rootlogin () {
    apt -y install kali-root-login
    echo -e "\n\nEnabling Root Login Give root a password"
    passwd root
    echo -e "\n\n"
    }    
   
fix_smbconf () {
    check_min=$(cat /etc/samba/smb.conf | grep -c -i "client min protocol")
    check_max=$(cat /etc/samba/smb.conf | grep -c -i "client max protocol")
    if [ $check_min -ne 0 ] && [ $check_max -ne 0 ]
      then
        echo -e "\n [-*-] client min protocol is already set not changing\n [-*-] client max protocol is already set not changing\n"
      else
        cat /etc/samba/smb.conf | sed 's/\[global\]/\[global\]\n   client min protocol = CORE\n   client max protocol = SMB3\n''/' > /tmp/fix_smbconf.tmp
        cat /tmp/fix_smbconf.tmp > /etc/samba/smb.conf
        rm -f /tmp/fix_smbconf.tmp
     fi
    }

fix_impacket () { 
    apt remove -y impacket
    
    arr=('addcomputer.py' 'atexec.py' 'dcomexec.py' 'dpapi.py' 'esentutl.py' 'findDelegation.py' 'GetADUsers.py' 'getArch.py' 'GetNPUsers.py'
         'getPac.py' 'getST.py' 'getTGT.py' 'GetUserSPNs.py' 'goldenPac.py' 'karmaSMB.py' 'kintercept.py' 'lookupsid.py' 'mimikatz.py' 'mqtt_check.py'
         'mssqlclient.py' 'mssqlinstance.py' 'netview.py' 'nmapAnswerMachine.py' 'ntfs-read.py' 'ntlmrelayx.py' 'ping6.py' 'ping.py' 'psexec.py'
         'raiseChild.py' 'rdp_check.py' 'registry-read.py' 'reg.py' 'rpcdump.py' 'rpcmap.py' 'sambaPipe.py' 'samrdump.py' 'secretsdump.py' 'services.py'
         'smbclient.py' 'smbexec.py' 'smbrelayx.py' 'smbserver.py' 'sniffer.py' 'sniff.py' 'split.py' 'ticketConverter.py' 'ticketer.py' 'wmiexec.py'
         'wmipersist.py' 'wmiquery.py') 

    for impacket_file in ${arr[@]}; do
        rm -f /usr/bin/$impacket_file
        rm -f /usr/local/bin/$impacket_file
        done 
    
    wget https://github.com/SecureAuthCorp/impacket/releases/download/impacket_0_9_19/impacket-0.9.19.tar.gz -O /tmp/impacket-0.9.19.tar.gz
    tar xfz /tmp/impacket-0.9.19.tar.gz -C /opt 
    cd /opt/impacket-0.9.19 
    pip install wheel
    pip install . 
    rm /tmp/impacket-0.9.19.tar.gz
    }

fix_golang () {
    cat /etc/skel/.bashrc | grep -i "export PATH=" -B1000 > /tmp/bashrc_top 
    cat /etc/skel/.bashrc | grep -i "don't put duplicate lines or lines starting with space in the history" -A5000 > /tmp/bashrc_bottom
    echo -e "export GOPATH=\$HOME/go\nexport GOROOT=/usr/local/go\nexport PATH=\$PATH:/sbin:\$GOROOT/bin:\$GOPATH/bin\n" >> /tmp/bashrc_top 
    echo -e "\nalias vpnip='ifconfig tun0 | grep -m1 inet | awk '\''{print(\$2)}'\'''" >> /tmp/bashrc_bottom
    echo -e "\nex ()\n{\n  if [ -f \$1 ] ; then \n   case \$1 in \n    *.tar.bz2)   tar xjf \$1 ;; "\
    "\n    *.tar.gz)    tar xzf \$1 ;;\n    *.tar.xz)    tar xJf \$1 ;;\n    *.bz2)       bunzip2 \$1 ;;"\
    "\n    *.rar)       unrar x \$1 ;;\n    *.gz)        gunzip \$1  ;;\n    *.tar)       tar xf \$1  ;;"\
    "\n    *.tbz2)      tar xjf \$1 ;;\n    *.tgz)       tar xzf \$1 ;;\n    *.zip)       unzip \$1   ;;"\
    "\n    *.Z)         uncompress \$1;;\n    *.7z)        7z x \$1 ;;\n    *)           echo \"'\$1' cannot be extracted via ex()\" ;;"\
    "\n    esac\n  else\n    echo \"'\$1' is not a valid file\"\n  fi\n }\n" >> /tmp/bashrc_bottom 
    cat /tmp/bashrc_top /tmp/bashrc_bottom > /root/.bashrc  
    cat /tmp/bashrc_top /tmp/bashrc_bottom > /home/kali/.bashrc
    rm -f /tmp/bashrc_top /tmp/bashrc_bottom
    }

fix_grub () {
    check_grub=$(cat /etc/default/grub | grep -i -c "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"" )
    if [ $check_grub -ne 1 ]
      then 
        echo -e '\nError: /etc/default/grub is not the default config - not changing'
    else
        cat /etc/default/grub | sed 's/GRUB_CMDLINE_LINUX_DEFAULT="quiet"/GRUB_CMDLINE_LINUX_DEFAULT="quiet mitigations=off"/' > /tmp/fix_grub.tmp
        cat /tmp/fix_grub.tmp > /etc/default/grub
        rm -f /tmp/fix_grub.tmp
        update-grub
    fi
    } 
    
check_for_root
fix_missing
fix_smbconf
fix_impacket
fix_golang
fix_grub
make_rootgreatagain

