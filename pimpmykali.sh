#!/bin/bash 
#
# pimpmykali.sh 
# Author: Dewalt
#
# Usage: sudo ./pimpmykali.sh  ( defaults to the menu system )  command line arguements are valid, only catching 1 arguement
#

# Revision 0.3a: 
#   - the extraction of the impacket-0.9.19.tar.gz was leaving /opt/impacket-0.9.19 with 700 perms
#     and an ownership of 503:root, this has been changed to ownership root:root and all files inside
#     /opt/impacket-0.9.19 have had their permissions set to 755 after extraction of impacket-0.9.19.tar.gz
#   - ascii art added to the menu
#
#   Revision 0.3: 
#   - Added checks for already installed installations, added --force command ( --force will run all fixes/reinstalls )
#   - fix_impacket : added both .py and .pyc files to impacket removal array
#     - added on screen notification of files being removed by the array
#   - fix_missing  : has been reworked new vars check section force type
#     - added fix_section : fix_section is the workhorse for fix_missing
#
#   - 09.25.2020 - OffSec has removed python-pip from the kali repo
#   - reworked python-pip installation to its own function python-pip-curl and installs python-pip via curl 
#
#   Revision 0.2: 
#   - Added colorized notifications, help system, command line arguements, case based menu system
#   - valid command line arguements are: help, all, go, grub, impacket, missing, menu, smb, grub, root
#   - anything other than --all or -all or all , will only run that function and then exit.
#   - command line arguements can be used with -- or - or just the word itself to try can catch for all possible cases
#     example command line var: --help or -help or help will catch help and works for all valid command line arguements
#     anything other the command line arugement catch exits and displays help 
# 
#     Standard Disclaimer: Author assumes no liability for any damange
#

 greenplus='\e[1;33m[++]\e[0m'
 greenminus='\e[1;33m[--]\e[0m'
 redminus='\e[1;31m[--]\e[0m'
 redexclaim='\e[1;31m[!!]\e[0m'
 redstar='\e[1;31m[**]\e[0m' 
 blinkexclaim='\e[1;31m[\e[5;31m!!\e[0m\e[1;31m]\e[0m'
 force=0
 check=""
 section=""
 type=""
 
check_distro() { 
     distro=$(uname -a | grep -i -c "kali") # CHANGE THIS

     if [ $distro -ne 1 ]
       then echo -e "\n $blinkexclaim Sorry I only work on Kali Linux $blinkexclaim \n"; exit  # false
     fi
     }
 
check_for_root () {
     if [ "$EUID" -ne 0 ]
       then echo -e "\n\n Script must be run with sudo ./pimpmykali.sh or as root \n"
       exit
     fi
     }

fix_section () {
     echo $section force=$force type=$type check=$check
     if [ $check -ne 0 ] && [ $force -ne 0 ] 
      then 
       echo -e "\n $redstar Reinstallation : $section"
        apt -y reinstall $section  
       else
        if [ $check -ne 1 ] && [ $force -ne 1 ]
         then 
          apt -y $type $section   
          echo -e "\n $greenplus $section $type" 
         else
          echo -e "\n $greenminus $section already installed" 
        fi
       echo -e "      use --force to force reinstall" 
       section=""
       check=""
       type=""
      fi
      }
   
fix_missing () { 
     apt -y update && apt -y autoremove
     apt -y remove kali-undercover 2> /dev/null
     echo -e "\n $greenplus apt updated "

     # section= must be exact name of package in kali repo ( apt-cache search itemname ) 
     # check= custom check for that particular item 
     # type= install or remove 
     # force= to override force / set force var
     # fix_section $section $check $force
     
     #section="kali-undercover"
     #check=$(whereis kali-undercover | grep -i -c "kali-undercover: /usr/bin/kali-undercover")
     #type="remove"
     #fix_section $section $check $type $force
     
     section="python3-pip"
     check=$(python3 -m pip --version | grep -i -c "/usr/lib/python3/dist-packages/pip")
     type="install"
     fix_section $section $check $type $force

     section="seclists"
     check=$(whereis seclists | grep -i -c "seclists: /usr/bin/seclists /usr/share/seclists") 
     type="install"
     fix_section $section $check $type $force
     
     section="locate"
     check=$(whereis locate | grep -i -c "locate: /usr/bin/locate") 
     type="install"
     fix_section $section $check $type $force
     
     section="golang"
     check=$(go version | grep -i -c "go version")
     type="install"
     fix_section $section $check $type $force

     # 09.25.2020 - python-pip was removed from the kali repo and curl is the only method to install at this time
     python-pip-curl
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
    section="kali-root-login"
    check=$(whereis kali-root-login | grep -i -c "kali-root-login: /usr/share/kali-root-login") 
    $type="install"
    fix_section $section $check $type $force
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
    
python-pip-curl () {
    check_pip=$(pip --version | grep -i -c "/usr/local/lib/python2.7/dist-packages/pip") 
    if [ $check_pip -ne 1 ] 
     then 
      curl https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py  
      python /tmp/get-pip.py  
      rm -f /tmp/get-pip.py
      echo -e "\n $greenplus python-pip installed"
    else
      echo -e "\n $greenminus python-pip already installed"
    fi
    }

fix_impacket () { 
    apt -y remove impacket  
    apt -y install python3-pip  
    # python-pip has been removed from the kali repos
    python-pip-curl
    
    arr=('addcomputer.py' 'atexec.py' 'dcomexec.py' 'dpapi.py' 'esentutl.py' 'findDelegation.py' 'GetADUsers.py' 'getArch.py' 'GetNPUsers.py'
         'getPac.py' 'getST.py' 'getTGT.py' 'GetUserSPNs.py' 'goldenPac.py' 'karmaSMB.py' 'kintercept.py' 'lookupsid.py' 'mimikatz.py' 'mqtt_check.py' 'mssqlclient.py' 'mssqlinstance.py' 'netview.py' 'nmapAnswerMachine.py' 'ntfs-read.py' 'ntlmrelayx.py' 'ping6.py' 'ping.py' 'psexec.py' 'raiseChild.py' 'rdp_check.py' 'registry-read.py' 'reg.py' 'rpcdump.py' 'rpcmap.py' 'sambaPipe.py' 'samrdump.py' 'secretsdump.py' 'services.py' 'smbclient.py' 'smbexec.py' 'smbrelayx.py' 'smbserver.py' 'sniffer.py' 'sniff.py' 'split.py' 'ticketConverter.py' 'ticketer.py' 'wmiexec.py' 'wmipersist.py' 'wmiquery.py' 'addcomputer.pyc' 'atexec.pyc' 'dcomexec.pyc' 'dpapi.pyc' 'esentutl.pyc' 'findDelegation.pyc' 'GetADUsers.pyc' 'getArch.pyc' 'GetNPUsers.pyc' 'getPac.pyc' 'getST.pyc' 'getTGT.pyc' 'GetUserSPNs.pyc' 'goldenPac.pyc' 'karmaSMB.pyc' 'kintercept.pyc' 'lookupsid.pyc' 'mimikatz.pyc' 'mqtt_check.pyc' 'mssqlclient.pyc' 'mssqlinstance.pyc' 'netview.pyc' 'nmapAnswerMachine.pyc' 'ntfs-read.pyc' 'ntlmrelayx.pyc' 'ping6.pyc' 'ping.pyc' 'psexec.pyc' 'raiseChild.pyc' 'rdp_check.pyc' 'registry-read.pyc' 'reg.pyc' 'rpcdump.pyc' 'rpcmap.pyc' 'sambaPipe.pyc' 'samrdump.pyc' 'secretsdump.pyc' 'services.pyc' 'smbclient.pyc' 'smbexec.pyc' 'smbrelayx.pyc' 'smbserver.pyc' 'sniffer.pyc' 'sniff.pyc' 'split.pyc' 'ticketConverter.pyc' 'ticketer.pyc' 'wmiexec.pyc' 'wmipersist.pyc' 'wmiquery.pyc' ) 

    for impacket_file in ${arr[@]}; do
        rm -f /usr/bin/$impacket_file
        rm -f /usr/local/bin/$impacket_file
        echo -e "\n $greenplus $impacket_file removed "
	done 
    
    wget https://github.com/SecureAuthCorp/impacket/releases/download/impacket_0_9_19/impacket-0.9.19.tar.gz -O /tmp/impacket-0.9.19.tar.gz   
    tar xfz /tmp/impacket-0.9.19.tar.gz -C /opt  
    cd /opt/
    chown -R root:root impacket-0.9.19
    chmod -R 755 impacket-0.9.19
    pip install wheel   
    pip install .   
    rm /tmp/impacket-0.9.19.tar.gz
    echo -e "\n $greenplus python-pip python3-pip wheel impacket installed"
    }

fix_golang () {
     section="golang"
     check=$(go version | grep -i -c "go version")
    
     if [ $force -ne 0 ] 
      then 
       type="install"
      else
       type="reinstall"
     fi 
    
    fix_section $section $check $type $force
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
    # Still debating this section 
    # add this!!! export PATH=$PATH:/sbin:/usr/sbin
    # ADD THESE ALIASES  WEBSRV PORTNUMER   AND   KILLVPN
    # alias websrv='python3 -m http.server $1'
    # alias killvpn='killall -9 openvpn'

}
    
fix_all () {
    fix_missing $force 
    fix_smbconf 
    fix_impacket
    fix_golang $force
    make_rootgreatagain
    fix_grub
    }    

    
asciiart=$(base64 -d <<< "H4sIAAAAAAAAA31QQQrCQAy89xVz9NR8QHoQH+BVCATBvQmCCEXI480kXdteTJfdzGQy2S3wi9EM/2MnSDm3oUoMuJlX3hmsMMSjA4uAtUTsSQ9NUkkKVgKKBXp1lEC0auURW3owsQlTZtf4QtGZgjXYKT4inPtI23oEK7wXlyPnd8arKdKE0EPdUnhIf0v+iE2o7BgVFVyec3u1OxFw+uRxbvPt8R6+MOpGq5cBAAA=" | gunzip )
   
pimpmykali_menu () {
    clear
    echo -e "$asciiart"
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
     --force) force=1; fix_all    ;; -force) force=1; fix_all   ;; force) force=1; fix_all ;;
           *) pimpmykali_help ; exit 0 ;; 
     esac
fi
}

check_for_root
check_distro
check_arg "$1" 
