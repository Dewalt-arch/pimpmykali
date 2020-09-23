#!/bin/bash 

check_for_root () {
    if [ "$EUID" -ne 0 ]
      then echo "Script must be run with sudo or as the root user"
      exit
    fi
    }

general_updates  () { 
    apt -y update 
    apt -y remove kali-undercover 
    apt -y install python-pip python3-pip golang kali-root-login seclists
    echo -e "\n\n Give Root a password: " 
    passwd root 
    } 

fix_smb_conf () {
    cat /etc/samba/smb.conf | grep -i "\[global\]" -B100 > /tmp/top.tmp
    cat /etc/samba/smb.conf | grep -i "Browsing\/Identification" -A1000 > /tmp/bottom.tmp 
    echo -e "    client min protocol = CORE \n    client max protocol = SMB3 \n" >> /tmp/top.tmp
    cat /tmp/top.tmp /tmp/bottom.tmp > /etc/samba/smb.conf
    rm -f /tmp/top.tmp /tmp/bottom.tmp 
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
        
    cd /opt 
    wget https://github.com/SecureAuthCorp/impacket/releases/download/impacket_0_9_19/impacket-0.9.19.tar.gz -O /tmp/impacket-0.9.19.tar.gz
    tar xvfz /tmp/impacket-0.9.19.tar.gz -C /opt 
    cd /opt/impacket-0.9.19 
    pip install wheel
    pip install . 
    rm /tmp/impacket-0.9.19.tar.gz
    }

fix_golang () {
    cat /etc/skel/.bashrc | grep -i "export PATH=" -B1000 > /tmp/bashrc_top 
    cat /etc/skel/.bashrc | grep -i "don't put duplicate lines or lines starting with space in the history" -A5000 > /tmp/bashrc_bottom
    echo -e "export GOPATH=\$HOME/go" >> /tmp/bashrc_top
    echo -e "export GOROOT=/usr/local/go" >> /tmp/bashrc_top
    echo -e "export PATH=\$PATH:/sbin:\$GOROOT/bin:\$GOPATH/bin"  >> /tmp/bashrc_top 
    echo -e "\nalias vpnip='ifconfig tun0 | grep -m1 inet | awk '\''{print(\$2)}'\'''\n" >> /tmp/bashrc_bottom
    echo -e "\nex ()\n{\n  if [ -f \$1 ] ; then \n   case \$1 in \n    *.tar.bz2)   tar xjf \$1 ;; "\
    "\n    *.tar.gz)    tar xzf \$1 ;;\n    *.tar.xz)    tar xJf \$1 ;;\n    *.bz2)       bunzip2 \$1 ;;"\
    "\n    *.rar)       unrar x \$1 ;;\n    *.gz)        gunzip \$1  ;;\n    *.tar)       tar xf \$1  ;;"\
    "\n    *.tbz2)      tar xjf \$1 ;;\n    *.tgz)       tar xzf \$1 ;;\n    *.zip)       unzip \$1   ;;"\
    "\n    *.Z)         uncompress \$1;;\n    *.7z)        7z x \$1 ;;\n    *)           echo \"'\$1' cannot be extracted via ex()\" ;;"\
    "\n    esac\n  else\n    echo \"'\$1' is not a valid file\"\n  fi\n }" >> /tmp/bashrc_bottom 
    cat /tmp/bashrc_top /tmp/bashrc_bottom > /root/.bashrc  
    cat /tmp/bashrc_top /tmp/bashrc_bottom > /home/kali/.bashrc
    rm -f /tmp/bashrc_top /tmp/bashrc_bottom
    }

check_for_root
general_updates
fix_smb_conf
fix_impacket
fix_golang
