#!/bin/bash 
#
# pimpmykali.sh 
# Author: Dewalt
#
# Usage: sudo ./pimpmykali.sh  ( defaults to the menu system )  command line arguements are valid, only catching 1 arguement
#
# Revision 0.4a : 2nd warning screen added for --borked impacket removal system
#   - If you cant have a little fun with your own scripts your doing something wrong....
#   - last chance warning screen ( mostly novelty ), random launch code generation on each run of --borked
#   - list of target selection, targets locked, etc
#   - 10 second wait timer added to last chance launch screen before operations are preformed
#   - if no ctrl+c is entered to cancel the operation, fix_sead is run, followed by fix_impacket
#
# Revision 0.4 : Major Update for impacket 
#   - added flameshot as a part of the missing group to be installed
#   - added clamav-exec.nse wget to fix clamav-exec.nse failed during nmap --script vuln scans
#   - new commandline switch of --borked has been implemented for removal of impacket across various locations
#   - added --borked notice to menu system, help system
#   - added warning screen for --borked, only input of Y will proceed anything else exits
#   - fix_sead_warning, fix_sead_run, fix_impacket_array, fix_impacket all executed in order with --borked
#     - fix_sead_run removes any and all directories named impacket* in the following locations: 
#        /opt /usr/bin /usr/local/lib /usr/lib /home/$finduser/.local/bin /home/$finduser/.local/lib ~/.local/lib ~/.local/bin
#      - fix_sead_run, also removes via fix_impacket_array any .py or .pyc related to impacket in the following: 
#        /usr/bin/$impacket_file /usr/local/bin/$impacket_file 
#         (root)~/.local/bin/$impacket_file 
#         (user)/home/$finduser/.local/bin/$impacket_file
#
# Revision 0.3c: 
#   - per request kali-root-login enabling prompt has been reworked and reworded to be less confusing and
#     to give the user a better explaniation of what the script is doing at that stage 
#   - added to note that if you dont understand what this part of the script is doing hit N
#   - added colors for syntax highlighting in the onscreen messages of the script in places
#   - added fix_nmap function for fixing /usr/share/nmap/scripts/clamav-exec.nse (commented out at this time
#     clamav-exec.nse was an issue at one time but unknown if it is still relevent) 
#
# Revision 0.3c: 
#    - emergency fix to --force everything should be functioning properly now
#
# Revision 0.3b: 
#   - bug fix ( Thanks Shadowboss! ) for impacket installation, cd /opt/impacket-0.9.19 was missing
#   - feature request added : Gedit installation menu option 7, is included in fix_missing, all and force
#   - remove clear from exit screen
#
# Revision 0.3a: 
#   - the extraction of the impacket-0.9.19.tar.gz was leaving /opt/impacket-0.9.19 with 700 perms
#     and an ownership of 503:root, this has been changed to ownership root:root and all files inside
#     /opt/impacket-0.9.19 have had their permissions set to 755 after extraction of impacket-0.9.19.tar.gz
#   - ascii art added to the menu
#   - added exit screen
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
 #unicorn puke: 
 red=$'\e[1;31m'
 green=$'\e[1;32m' 
 blue=$'\e[1;34m'
 magenta=$'\e[1;35m'
 cyan=$'\e[1;36m'
 yellow=$'\e[1;93m'
 white=$'\e[0m'
 bold=$'\e[1m'
 norm=$'\e[21m'
 
 #launch_codes - a little fun in the script
 launch_codes_alpha=$(echo $((1 + RANDOM % 9999)))
 launch_codes_beta=$(echo $((1 + RANDOM % 9999)))
 launch_codes_charlie=$(echo $((1 + RANDOM % 9999)))

 # status indicators
 greenplus='\e[1;33m[++]\e[0m'
 greenminus='\e[1;33m[--]\e[0m'
 redminus='\e[1;31m[--]\e[0m'
 redexclaim='\e[1;31m[!!]\e[0m'
 redstar='\e[1;31m[**]\e[0m' 
 blinkexclaim='\e[1;31m[\e[5;31m!!\e[0m\e[1;31m]\e[0m'
 fourblinkexclaim='\e[1;31m[\e[5;31m!!!!\e[0m\e[1;31m]\e[0m'
 
 # variables needed in the script 
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
     # echo section=$section force=$force type=$type check=$check
     if [ $force -ne 0 ] 
      then 
        echo -e "\n $redstar Reinstallation : $section"
        apt -y reinstall $section  
      else
        if [ $check -ne 1 ]
         then 
          apt -y install $section   
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
     fix_golang $force
     fix_gedit $force 
     fix_flameshot $force
     fix_nmap
     python-pip-curl
     } 
    
fix_nmap () { 
    # clamav-exec.nse was/is broken on some kali installs, grab new one and overwrite old one at /usr/share/nmap/scripts/clamav-exec.nse
    rm -f /usr/share/nmap/scripts/clamav-exec.nse 
    echo -e "\n $redminus /usr/share/nmap/scripts/clamav-exec.nse removed \n" 
    wget https://github.com/nmap/nmap/blob/master/scripts/clamav-exec.nse -O /usr/share/nmap/scripts/clamav-exec.nse
    echo -e "\n $greenplus /usr/share/nmap/scripts/clamav-exec.nse replaced with working version \n"
    }

fix_flameshot () {
    section="flameshot"
    check=$(whereis gedit | grep -i -c "/usr/bin/flameshot") 
     if [ $check -ne 0 ] 
      then
       type="reinstall"
      else
       type="install"
     fi   
     fix_section $section $check $type $force
     }   

fix_gedit () {
    section="gedit"
    check=$(whereis gedit | grep -i -c "gedit: /usr/bin/gedit") 
     if [ $check -ne 0 ] 
      then
       type="reinstall"
      else
       type="install"
     fi   
     fix_section $section $check $type $force
     }   
     
make_rootgreatagain () {
     echo -e "\n KALI-ROOT-LOGIN INSTALLATION:   "$red"*** READ CAREFULLY! ***"$white" \n"
     echo -e " On Kali 2019.x and prior the default user was root"
     echo -e " On Kali 2020.1 and newer this was changed, the default user was changed to be "
     echo -e " an" $yellow$bold"actual user"$norm$white" on the system and not "$red$bold"root"$norm$white", this user is : kali (by default) "
     echo -e " \n  Your existing user configurations will not be affected or altered. "
     echo -e "  This will "$red"ONLY"$white" reenable the ability to login as root at boot and does "$red"NOT"$white" replace"
     echo -e "  any existing user, remove any user files or user configurations."
     echo -e "\n  If you wish to re-enable the ability to login to kali as root at the login screen "
     echo -e "  and be root all the time, press Y "
     echo -e "\n  If not, press N and the script will skip this section "
     echo -e "\n  "$bold$red"If you are confused or dont understand what"$norm$white
     echo -e "  "$bold$red"this part of the script is doing, press N"$norm$white
     echo -e "\n  Do you want to re-enable the ability to login as root in kali?"
     read -n1 -p "  Please type Y or N : " userinput
     case $userinput in
         y|Y) enable_rootlogin $force;;
         n|N) echo -e "\n $redexclaim skipping root login setup" ;;
         *) echo -e "\n invalid key try again Y or N"; make_rootgreatagain;;
     esac
     }

enable_rootlogin () {
    section="kali-root-login"
    check=$(whereis kali-root-login | grep -i -c "kali-root-login: /usr/share/kali-root-login") 
     if [ $force -ne 0 ] 
      then 
       type="install"
      else
       type="reinstall"
     fi 
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

fix_sead_warning () {
    # Note: The only way this function gets called is via --borked command line switch
    # search for, find, list and remove anything impacket* from the following and its not going to ask about it!
    # /opt /usr/bin /usr/local/lib /usr/lib /home/$finduser/.local/lib /home/$finduser/.local/bin ~/.local/lib ~/.local/bin

    finduser=$(logname)
    clear
 echo -e "

 "$bold$redexclaim$red" WARNING "$redexclaim$bold$red"  PIMPMYKALI IMPACKET REMOVAL FUNCTION  "$redexclaim$bold$red" WARNING "$redexclaim$white$norm"

                 *** READ FULLY BEFORE PRESSING ANY KEY ***
                
   "$red"DISCLAIMER:"$white" This is a last resort effort to remove impacket from the system
   and install a clean working install of impacket-0.9.19 and should be only
   used as such. This is for only if you screwed up your impacket as bad as 
   Bobloblaw (Blob) did!! (thank you blob! you are the wind beneath my impacket
   removal scripts!)
 
   This function of pimpmykali is reserved for the most severe cases of broken 
   impacket installs, multiple impacket installs, etc, and will attempt to 
   clean the system of impacket and any related files that may be preventing 
   a clean and working install of impacket-0.9.19
   
   It is not possible to forsee every possible scenario but this makes a best 
   attempt of the most common dirs and files to clean your system to remove 
   anything impacket related only from the areas listed below. 
 
   This WILL RECURSIVLY DELETE ANY DIR NAMED impacket* from the following: 
    /opt  /usr/bin  /usr/local/lib  /usr/lib  /home/$finduser/.local/bin 
    /home/$finduser/.local/lib  /root/.local/lib  /root/.local/bin 

   AND ANY related .py and .pyc files from impacket in the following: 
    /usr/bin  /local/local/bin  /root/.local/bin  /home/$finduser/.local/bin
    
   After this function completes the following will be run automatically 
    sudo ./pimpmykali.sh --impacket
    
   Answering only Y to the following prompt will preform the above actions, 
   pressing ANY OTHER KEY WILL EXIT
   
   "
    read -n1 -p " Press Y to execute or any other key to exit: " fixsead_userinput
    case $fixsead_userinput in
        y|Y) fix_sead_run ;;
        *) exit ;;
    esac
    }
    
fix_sead_run () {
    python-pip-curl
    apt update 2> /dev/null
    apt -y install python3-pip > /dev/null

    # gracefully attempt to remove impacket via pip and pip3        
    pip uninstall impacket -y > /dev/null
    pip3 uninstall impacket -y  > /dev/null
   
    # used to get the username running this script as sudo to check /home/$finduser/.local/lib and /home/$finduser/.local/bin
    finduser=$(logname)

    # Not playin here... anything impacket* in the following find statement goes BYE BYE and not ask about it.. its gone 
    SEAD=$(find /opt /usr/bin /usr/local/lib /usr/lib /home/$finduser/.local/bin /home/$finduser/.local/lib ~/.local/lib ~/.local/bin -name impacket* 2> /dev/null) 

    # added Last Chance Launch Sequence ** WARNING SCREEN ** and 10 second time out
    clear 
    echo -e "  If youve made it this far your having a really bad day with impacket... "
    echo -e "  Enjoy the last chance launch sequence!\n"
    echo -e "  Preparing to nuke Impacket...\n"
    echo -e "  $green[....]$white aquiring targets\n"
    echo -e "  $green[$red+$green..$red+$green]$white targets selected\n$SEAD\n"
    echo -e "  $green[-$red++$green-]$white targets locked\n"
    echo -e "  $green[++++]$white systems ready\n"
    echo -e "  $green[<$red@@$green>]$white taking aim\n" 
    echo -e "  $green[$red####$green]$white requesting launch code\n"
    echo -e "  $green[$red$launch_codes_alpha-$launch_codes_beta-$launch_codes_charlie$green]$white launch code confirmed\n"
    wait_time=10 # seconds

    echo -e "  Are you sure you meant to run this script?\n"
     temp_cnt=${wait_time}
     while [[ ${temp_cnt} -gt 0 ]];
      do
      printf "\r  You have %2d second(s) remaining to hit Ctrl+C to cancel this operation!" ${temp_cnt}
      sleep 1
      ((temp_cnt--))
    done
    echo -e "\n\n  No user input detected... Executing!!" 
    echo -e "\n  $fourblinkexclaim *** FIRE!! *** $fourblinkexclaim\n"
    echo -e "  $redstar function running removing :\n$SEAD\n"
    rm -rf $SEAD
    fix_impacket_array 
    fix_impacket
    exit_screen
    exit
    }

fix_impacket_array () {
    finduser=$(logname)   
    arr=('addcomputer.py' 'atexec.py' 'dcomexec.py' 'dpapi.py' 'esentutl.py' 'findDelegation.py' 'GetADUsers.py' 'getArch.py'
         'GetNPUsers.py' 'getPac.py' 'getST.py' 'getTGT.py' 'GetUserSPNs.py' 'goldenPac.py' 'karmaSMB.py' 'kintercept.py' 
         'lookupsid.py' 'mimikatz.py' 'mqtt_check.py' 'mssqlclient.py' 'mssqlinstance.py' 'netview.py' 'nmapAnswerMachine.py' 
         'ntfs-read.py' 'ntlmrelayx.py' 'ping6.py' 'ping.py' 'psexec.py' 'raiseChild.py' 'rdp_check.py' 'registry-read.py'
         'reg.py' 'rpcdump.py' 'rpcmap.py' 'sambaPipe.py' 'samrdump.py' 'secretsdump.py' 'services.py' 'smbclient.py'
         'smbexec.py' 'smbrelayx.py' 'smbserver.py' 'sniffer.py' 'sniff.py' 'split.py' 'ticketConverter.py' 'ticketer.py'
         'wmiexec.py' 'wmipersist.py' 'wmiquery.py' 'addcomputer.pyc' 'atexec.pyc' 'dcomexec.pyc' 'dpapi.pyc' 'esentutl.pyc'
         'findDelegation.pyc' 'GetADUsers.pyc' 'getArch.pyc' 'GetNPUsers.pyc' 'getPac.pyc' 'getST.pyc' 'getTGT.pyc' 
         'GetUserSPNs.pyc' 'goldenPac.pyc' 'karmaSMB.pyc' 'kintercept.pyc' 'lookupsid.pyc' 'mimikatz.pyc' 'mqtt_check.pyc' 
         'mssqlclient.pyc' 'mssqlinstance.pyc' 'netview.pyc' 'nmapAnswerMachine.pyc' 'ntfs-read.pyc' 'ntlmrelayx.pyc' 
         'ping6.pyc' 'ping.pyc' 'psexec.pyc' 'raiseChild.pyc' 'rdp_check.pyc' 'registry-read.pyc' 'reg.pyc' 'rpcdump.pyc' 
         'rpcmap.pyc' 'sambaPipe.pyc' 'samrdump.pyc' 'secretsdump.pyc' 'services.pyc' 'smbclient.pyc' 'smbexec.pyc' 
         'smbrelayx.pyc' 'smbserver.pyc' 'sniffer.pyc' 'sniff.pyc' 'split.pyc' 'ticketConverter.pyc' 'ticketer.pyc' 
         'wmiexec.pyc' 'wmipersist.pyc' 'wmiquery.pyc' ) 

     for impacket_file in ${arr[@]}; do
      rm -f /usr/bin/$impacket_file /usr/local/bin/$impacket_file ~/.local/bin/$impacket_file /home/$finduser/.local/bin/$impacket_file 
      # removed status of whats being removed from screen, too much screen garbage
      # echo -e "\n $greenplus $impacket_file removed from /usr/bin /usr/local/bin ~/.local/bin /home/$finduser/.local/bin"
     done 
     } 

fix_impacket () { 
    finduser=$(logname)
    # 2020.3 - package: impacket no longer exists in repo will throw error 
    apt -y remove impacket     ## do not remove : python3-impacket impacket-scripts
    apt -y install python3-pip  
    
    # python-pip has been removed from the kali repos, use python-pip-curl function for curl installation
    python-pip-curl
    
    # make sure pip and pip3 are there before we attempt to uninstall gracefully
    pip uninstall impacket -y
    pip3 uninstall impacket -y 

    fix_impacket_array 

    wget https://github.com/SecureAuthCorp/impacket/releases/download/impacket_0_9_19/impacket-0.9.19.tar.gz -O /tmp/impacket-0.9.19.tar.gz   
    tar xfz /tmp/impacket-0.9.19.tar.gz -C /opt  
    cd /opt
    chown -R root:root impacket-0.9.19
    chmod -R 755 impacket-0.9.19
    cd /opt/impacket-0.9.19
    pip install wheel   
    pip install .   
    rm -f /tmp/impacket-0.9.19.tar.gz
    # added as a result of blobs removal of impacket and problem with smbmap after
    apt -y reinstall python3-impacket impacket-scripts
    echo -e "\n $greenplus python-pip python3-pip wheel impacket installed"
    }

fix_golang () {
    section="golang"
    # check=$(go version | grep -i -c "go version")
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

    #
    # basrc_udpate - still debating this section or not.. adding go paths to ~/.bashrc aparentally breaks ability to compile?
    #
#bashrc_update () {
#    check_bashrc_vpnip=$(cat $HOME/.bashrc | grep -i -c "vpnip=")
#    if [ $check_bashrc_vpnip -ne 1 ]
#      then 
#        echo -e "\nalias vpnip='ifconfig tun0 | grep -m1 inet | awk '\''{print(\$2)}'\'''"
#        echo -e "\n $greenplus added vpnip alias to $HOME/.bashrc"
#      else
#        echo -e "\n vpnip= found in .bashrc - not updating"
#    fi
#
#    check_bashrc_ex=$(cat $HOME/.bashrc | grep -i -c "ex ()")
#    if [ $check_bashrc_ex -ne 1 ]
#      then 
#       echo -e "\nex ()\n{\n  if [ -f \$1 ] ; then \n   case \$1 in \n    *.tar.bz2)   tar xjf \$1 ;; "\
#               "\n    *.tar.gz)    tar xzf \$1 ;;\n    *.tar.xz)    tar xJf \$1 ;;\n    *.bz2)       bunzip2 \$1 ;;"\
#               "\n    *.rar)       unrar x \$1 ;;\n    *.gz)        gunzip \$1  ;;\n    *.tar)       tar xf \$1  ;;"\
#               "\n    *.tbz2)      tar xjf \$1 ;;\n    *.tgz)       tar xzf \$1 ;;\n    *.zip)       unzip \$1   ;;"\
#               "\n    *.Z)         uncompress \$1;;\n    *.7z)        7z x \$1 ;;\n    *)           echo \"'\$1' cannot be extracted via ex()\" ;;"\
#               "\n    esac\n  else\n    echo \"'\$1' is not a valid file\"\n  fi\n }\n"
#       echo -e "\n $greenplus Added ex () function to $HOME/.bashrc"
#       else
#       echo -e "\n $redminus ex () function found in .bashrc - not updating"
#    fi
#    # Still debating this section 
#    # add this!!! export PATH=$PATH:/sbin:/usr/sbin
#    # ADD THESE ALIASES  WEBSRV PORTNUMER   AND   KILLVPN
#    # alias websrv='python3 -m http.server $1'
#    # alias killvpn='killall -9 openvpn'
#    }

fix_all () {
    fix_missing $force 
    fix_smbconf 
    fix_impacket
    # ID10T REMINDER : fix_golang is being called in fix_missing, dont call it twice here!
    # fix_golang $force
    make_rootgreatagain $force
    fix_grub
    # ID10T REMINDER:     
    # fix_gedit is being called from fix_missing which is a part of fix_all, no need to call it a 2nd time 
    # fix_nmap  is being called from fix_missing which is a part of fix_all, no need to call it a 2nd time 
    }    
    
asciiart=$(base64 -d <<< "H4sIAAAAAAAAA31QQQrCQAy89xVz9NR8QHoQH+BVCATBvQmCCEXI480kXdteTJfdzGQy2S3wi9EM/2MnSDm3oUoMuJlX3hmsMMSjA4uAtUTsSQ9NUkkKVgKKBXp1lEC0auURW3owsQlTZtf4QtGZgjXYKT4inPtI23oEK7wXlyPnd8arKdKE0EPdUnhIf0v+iE2o7BgVFVyec3u1OxFw+uRxbvPt8R6+MOpGq5cBAAA=" | gunzip )
   
pimpmykali_menu () {
    revision="0.4a"
    clear
    echo -e "$asciiart"
    echo -e "\n     Select a option from menu:                           Rev:$revision"
    echo -e "\n Options 1 thru 6 will only run that function and exit, 0 will run all "
    echo -e "\n  1 - Fix Missing             (only installs pip pip3 seclists gedit flameshot)" # fix_missing
    echo -e "  2 - Fix /etc/samba/smb.conf (only adds the 2 missing lines)"                   # fix_smbconf
    echo -e "  3 - Fix Golang              (only installs golang)"                            # fix_golang
    echo -e "  4 - Fix Grub                (only adds mitigations=off)"                       # fix_grub
    echo -e "  5 - Fix Impacket            (only installs impacket)"                          # fix_impacket
    echo -e "  6 - Enable Root Login       (only installs kali-root-login)"                   # make_rootgreatagain
    echo -e "  7 - Install Gedit           (only installs gedit)\n"                           # fix_gedit
    # FIX_NMAP UNCOMMENT TO ENABLE
    # echo -e "  8 - Fix clamav-exec.nse     (only fix clamav-exec.nse for nmap)\n"             # fix_nmap
    echo -e "  0 - Fix ALL                 (run 1, 2, 3, 4, 5, 6 and 7) \n"                   # fix_all 
    echo -e "  use the --borked command line switch as a last resort to"
    echo -e "  remove/reinstall impacket only!! \n"
    read -n1 -p "  Make selection or press X to exit: " menuinput
      
    case $menuinput in
        1) fix_missing ;;
        2) fix_smbconf ;;
        3) fix_golang ;;
        4) fix_grub ;;
        5) fix_impacket ;;
        6) make_rootgreatagain ;;
        7) fix_gedit ;; 
        # FIX_NMAP UNCOMMENT TO ENABLE
        # 8) fix_nmap ;; 
        0) fix_all ;;
        # x|X) exit_screen ;;
        x|X) echo -e "\n\n Exiting pimpmykali.sh - Happy Hacking! \n" ;;
        *) pimpmykali_menu ;;
    esac
    }   
     
pimpmykali_help () {
    # do not edit this echo statement, spacing has been fixed and is correct for display terminal
    echo -e "\n valid command line arguements are : \n \n --all        run all operations \n"\
            "--smb        only run smb.conf fix \n --go         only fix/install golang"\
            "\n --impacket   only fix/install impacket \n --grub       only add mitigations=off"\
            "\n --root       only enable root login \n --missing    install all common missing packages" \
            "\n --menu       its the menu \n --gedit      only install gedit\n --flameshot  only fix/install flameshot" \
            "\n --borked     only to be used as last resort to remove-reinstall impacket\n --help       your looking at it"
    exit             
    }             

check_arg () {
    if [ "$1" == "" ] 
      then pimpmykali_menu
     else
      case $1 in 
      --menu) pimpmykali_menu          ;; -menu) pimpmykali_menu           ;; menu) pimpmykali_menu ;;
       --all) fix_all                  ;; -all) fix_all                    ;; all) fix_all ;; 
       --smb) fix_smbconf              ;; -smb) fix_smbconf                ;; smb) fix_smbconf ;;
        --go) fix_golang               ;; -go) fix_golang                  ;; go) fix_golang ;; 
     --gedit) fix_gedit                ;; -gedit) fix_gedit                ;; gedit) fix_gedit ;;  
  --impacket) fix_impacket             ;; -impacket) fix_impacket          ;; impacket) fix_impacket ;;   
      --grub) fix_grub                 ;; -grub) fix_grub                  ;; grub) fix_grub ;; 
      --root) make_rootgreatagain      ;; -root) make_rootgreatagain       ;; root) make_rootgreatagain ;;
   --missing) fix_missing              ;; -missing) fix_missing            ;; missing) fix_missing ;;  
      --help) pimpmykali_help          ;; -help) pimpmykali_help           ;; help) pimpmykali_help ;;
 --flameshot) fix_flameshot            ;; -flameshot) fix_flameshot        ;; flameshot) fix_flameshot ;;
     --force) force=1; fix_all $force  ;; -force) force=1; fix_all $force  ;; force) force=1; fix_all $force ;;
    --borked) fix_sead_warning; exit   ;; -borked) fix_sead_warning; exit  ;; borked) fix_sead_warning; exit ;; 
      --nmap) fix_nmap            ;; -nmap) fix_nmap            ;; nmap) fix_nmap ;;
           *) pimpmykali_help ; exit 0 ;; 
     esac
    fi
    }

exit_screen () { 
    # clear
    echo -e "$asciiart"
    echo -e "\n\n    All Done! Happy Hacking! \n"
    }

check_for_root
check_distro
check_arg "$1" 
exit_screen
