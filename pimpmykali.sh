#!/bin/bash 
#
# pimpmykali.sh 
# Author: Dewalt
#
# Usage: sudo ./pimpmykali.sh  ( defaults to the menu system )  command line arguements are valid, only catching 1 arguement
#
# Rev 0.2  
#   - Added colorized notifications, help system, command line arguements, case based menu system
#
#   - valid command line arguements are: help, all, go, grub, impacket, missing, menu, smb, grub, root
#
#   - anything other than --all or -all or all , will only run that function and then exit.
#
#   - command line arguements can be used with -- or - or just the word itself to try can catch for all possible cases
#     example command line var: --help or -help or help will catch help and works for all valid command line arguements
#     anything other the command line arugement catch exits and displays help 
# 
#     Standard Disclaimer: Author assumes no liability for any damange
#

 greenplus='\e[1;33m[++]\e[0m'
 redminus='\e[1;31m[--]\e[0m'
 redexclaim='\e[1;31m[!!]\e[0m'
 redstar='\e[1;31m[**]\e[0m' 
 blinkexclaim='\e[1;31m[\e[5;31m!!\e[0m\e[1;31m]\e[0m'

check_distro() { 
     distro=$(uname -a | grep -i -c "kali") # CHANGE THIS

     if [ $distro -ne 1 ]
       then echo -e "\n $blinkexclaim Sorry I only work on Kali Linux $blinkexclaim \n"; exit  # false
     fi
     }
 
check_for_root () {
     if [ "$EUID" -ne 0 ]
       then echo -e "\n\nError: Script must be run with sudo ./pimpmykali.sh or as root \n"
       exit
     fi
     }

fix_missing () { 
     apt -y update 
     echo -e "\n $greenplus apt updated "
     apt -y remove kali-undercover 
     echo -e "\n $greenplus kali-undercover removed"
     apt -y install python3-pip seclists locate
     # 09.25.20 - Appears that python-pip is no longer able to be installed via apt and has been pulled from 
     # the kali repo by offsec
     curl https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
     python /tmp/get-pip.py
     rm -f /tmp/get-pip.py
     echo -e "\n $greenplus python-pip python3-pip seclists installed "
     } 

make_rootgreatagain () {
     echo -e "\n Do you want to enable root login in kali?"
     read -n1 -p " Please type Y or N : " userinput
     case $userinput in
         y|Y) enable_rootlogin ;;
         n|N) echo -e "\n $redexclaim skipping root login setup" ;;
         *) echo -e "\n invalid key try again Y or N"; make_rootgreatagain ;;
     esac
     }

enable_rootlogin () {
    apt -y install kali-root-login
    echo -e "\n\nEnabling Root Login Give root a password"
    passwd root
    echo -e "\n $greenplus root login enabled \n"
    }    
   
fix_smbconf () {
    check_min=$(cat /etc/samba/smb.conf | grep -c -i "client min protocol")
    check_max=$(cat /etc/samba/smb.conf | grep -c -i "client max protocol")
    if [ $check_min -ne 0 ] && [ $check_max -ne 0 ]
      then
        echo -e "\n $redminus client min protocol is already set not changing\n $redminus client max protocol is already set not changing\n\n"
      else
        cat /etc/samba/smb.conf | sed 's/\[global\]/\[global\]\n   client min protocol = CORE\n   client max protocol = SMB3\n''/' > /tmp/fix_smbconf.tmp
        cat /tmp/fix_smbconf.tmp > /etc/samba/smb.conf
        rm -f /tmp/fix_smbconf.tmp
        echo -e "\n $greenplus /etc/samba/smb.conf updated"
    fi
    }

fix_impacket () { 
    apt -y remove impacket  
    apt -y install python-pip python3-pip   
    
    arr=('addcomputer.py' 'atexec.py' 'dcomexec.py' 'dpapi.py' 'esentutl.py' 'findDelegation.py' 'GetADUsers.py' 'getArch.py' 'GetNPUsers.py'
         'getPac.py' 'getST.py' 'getTGT.py' 'GetUserSPNs.py' 'goldenPac.py' 'karmaSMB.py' 'kintercept.py' 'lookupsid.py' 'mimikatz.py' 'mqtt_check.py'
         'mssqlclient.py' 'mssqlinstance.py' 'netview.py' 'nmapAnswerMachine.py' 'ntfs-read.py' 'ntlmrelayx.py' 'ping6.py' 'ping.py' 'psexec.py'
         'raiseChild.py' 'rdp_check.py' 'registry-read.py' 'reg.py' 'rpcdump.py' 'rpcmap.py' 'sambaPipe.py' 'samrdump.py' 'secretsdump.py' 'services.py'
         'smbclient.py' 'smbexec.py' 'smbrelayx.py' 'smbserver.py' 'sniffer.py' 'sniff.py' 'split.py' 'ticketConverter.py' 'ticketer.py' 'wmiexec.py'
         'wmipersist.py' 'wmiquery.py') 

    for impacket_file in ${arr[@]}; do
        rm -f /usr/bin/$impacket_file
        rm -f /usr/local/bin/$impacket_file
        # echo -e "\n $greenplus impacket removed "
	done 
    
    wget https://github.com/SecureAuthCorp/impacket/releases/download/impacket_0_9_19/impacket-0.9.19.tar.gz -O /tmp/impacket-0.9.19.tar.gz  
    tar xfz /tmp/impacket-0.9.19.tar.gz -C /opt 
    cd /opt/impacket-0.9.19 
    pip install wheel  
    pip install .       
    rm /tmp/impacket-0.9.19.tar.gz
    echo -e "\n $greenplus python-pip and python3-pip installed" 
    echo -e " $greenplus python wheel installed"
    echo -e " $greenplus impacket installed \n" 
    }

fix_golang () {
    apt -y install golang
    echo -e "\n $greenplus golang installed"
    }

fix_grub () {
    check_grub=$(cat /etc/default/grub | grep -i -c "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"" )
    if [ $check_grub -ne 1 ]
      then 
        echo -e "\n $redexclaim Error: /etc/default/grub is not the default config - not changing"
      else
        cat /etc/default/grub | sed 's/GRUB_CMDLINE_LINUX_DEFAULT="quiet"/GRUB_CMDLINE_LINUX_DEFAULT="quiet mitigations=off"/' > /tmp/fix_grub.tmp
        cat /tmp/fix_grub.tmp > /etc/default/grub
        rm -f /tmp/fix_grub.tmp
        update-grub
	echo -e "\n $greenplus Added mitigations=off to GRUB_CMDLINE_LINUX_DEFAULT"
	echo -e "\n $redexclaim Reboot for changes to take effect \n"
    fi
    } 

bashrc_update () {
    check_bashrc_vpnip=$(cat $HOME/.bashrc | grep -i -c "vpnip=")
    if [ $check_bashrc_vpnip -ne 1 ]
      then 
        echo -e "\nalias vpnip='ifconfig tun0 | grep -m1 inet | awk '\''{print(\$2)}'\'''"
        echo -e "\n $greenplus added vpnip alias to $HOME/.bashrc"
      else
        echo -e "\n vpnip= found in .bashrc - not updating"
    fi

    check_bashrc_ex=$(cat $HOME/.bashrc | grep -i -c "ex ()")
    if [ $check_bashrc_ex -ne 1 ]
      then 
       echo -e "\nex ()\n{\n  if [ -f \$1 ] ; then \n   case \$1 in \n    *.tar.bz2)   tar xjf \$1 ;; "\
    "\n    *.tar.gz)    tar xzf \$1 ;;\n    *.tar.xz)    tar xJf \$1 ;;\n    *.bz2)       bunzip2 \$1 ;;"\
    "\n    *.rar)       unrar x \$1 ;;\n    *.gz)        gunzip \$1  ;;\n    *.tar)       tar xf \$1  ;;"\
    "\n    *.tbz2)      tar xjf \$1 ;;\n    *.tgz)       tar xzf \$1 ;;\n    *.zip)       unzip \$1   ;;"\
    "\n    *.Z)         uncompress \$1;;\n    *.7z)        7z x \$1 ;;\n    *)           echo \"'\$1' cannot be extracted via ex()\" ;;"\
    "\n    esac\n  else\n    echo \"'\$1' is not a valid file\"\n  fi\n }\n"
       echo -e "\n $greenplus Added ex () function to $HOME/.bashrc"
       else
       echo -e "\n $redminus ex () function found in .bashrc - not updating"
    fi
    
    # ADD THESE ALIASES  WEBSRV PORTNUMER   AND   KILLVPN
    # alias websrv='python3 -m http.server $1'
    # alias killvpn='killall -9 openvpn'

}
    
fix_all () {
    fix_missing
    fix_smbconf
    fix_impacket
    fix_golang
    make_rootgreatagain
    fix_grub
    }    

pimpmykali_menu () {
    clear 
    echo -e "\n pimpmykali.sh"
    echo -e "\n Select a option from menu: "
    echo -e "\n Options 1 thru 6 will only run that function and exit, 0 will run all "
    echo -e "\n  1 - Fix Missing             (installs python-pip python3-pip seclists)" # fix_missing
    echo -e "  2 - Fix /etc/samba/smb.conf (adds the 2 missing lines)"                   # fix_smbconf
    echo -e "  3 - Fix Golang              (installs golang)"                            # fix_golang
    echo -e "  4 - Fix Grub                (adds mitigations=off)"                       # fix_grub
    echo -e "  5 - Fix Impacket            (installs impacket)"                          # fix_impacket
    echo -e "  6 - Enable Root Login       (installs kali-root-login)\n"                 # make_rootgreatagain
    echo -e "  0 - Fix ALL                 (run 1, 2, 3, 4, 5 and 6 ) \n"                # fix_all 
   
    read -n1 -p " Make selection or press X to exit: " menuinput
      
    case $menuinput in
        1) fix_missing ;;
        2) fix_smbconf ;;
        3) fix_golang ;;
        4) fix_grub ;;
        5) fix_impacket ;;
        6) make_rootgreatagain ;;
        0) fix_all ;;
        x|X) echo -e "\n\n Exiting pimpmykali.sh - Happy Hacking! \n" ;;
        *) pimpmykali_menu ;;
    esac
    }   
     
pimpmykali_help () {
    # do not edit this echo statement, spacing has been fixed and is correct for display terminal
    echo -e "\n valid command line arguements are : \n \n --all        run all operations \n"\
            "--smb        only run smb.conf fix \n --go         only fix golang"\
            "\n --impacket   only fix impacket \n --grub       only add mitigations=off"\
            "\n --root       enable root login \n --missing    install missing" \
            "\n --menu       its the menu \n --help       you are here"
    exit             
    }             

check_arg () {
    if [ "$1" == "" ] 
      then pimpmykali_menu
     else
      case $1 in 
      --menu) pimpmykali_menu     ;; -menu) pimpmykali_menu     ;; menu) pimpmykali_menu ;;
       --all) fix_all             ;; -all) fix_all              ;; all) fix_all ;; 
       --smb) fix_smbconf         ;; -smb) fix_smbconf          ;; smb) fix_smbconf ;;
        --go) fix_golang          ;; -go) fix_golang            ;; go) fix_golang ;; 
  --impacket) fix_impacket        ;; -impacket) fix_impacket    ;; impacket) fix_impacket ;;   
      --grub) fix_grub            ;; -grub) fix_grub            ;; grub) fix_grub ;; 
      --root) make_rootgreatagain ;; -root) make_rootgreatagain ;; root) make_rootgreatagain ;;
   --missing) fix_missing         ;; -missing) fix_missing      ;; missing) fix_missing ;;  
      --help) pimpmykali_help     ;; -help) pimpmykali_help     ;; help) pimpmykali_help ;;
     *) pimpmykali_help ; exit 0 ;; 
     esac
fi
}

check_for_root
check_distro
check_arg "$1" 
