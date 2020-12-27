# pimpmykali.sh

# Fixes for new imported Kali Linux virtual machines
- could be used on a bare metal machines, but thats on you

# Github index updated added +x permission:
- Script should now be executable upon clone (perms: 755 rwxr-xr-x added to github)
  - you should not need to chmod +x pimpmykali.sh upon git clone anymore

# Installation script:
- rm -rf pimpmykali/
- git clone https://github.com/Dewalt-arch/pimpmykali
- cd pimpmykali
- sudo ./pimpmykali.sh
- For a new kali vm, run menu option N

# Revision 1.0.8 - New Menu Item n or N - Intended for new vm's
  - function will run fix_all, fix_missing, downgrade metasploit and pimpmyupgrade
  - menu options 0, D and 9) from a single menu item.
  - On-screen Menu display has been reworked and cleaned up a bit
  - This saves the user from running menu 0, then running D then running 9 individually.

# Revision 1.0.7 - GOPATH statements added to .zshrc and .bashrc
  - function will check for GOPATH in .zshrc and .bashrc
  - Checks added for root and regular users
  - if "GOPATH" is not found in .zshrc or .bashrc, statements will be added:
    - export GOPATH=$HOME/go
    - export PATH=$PATH:$GOPATH/bin
  - if "GOPATH" is found in .zshrc or .bashrc, no changes will be made
  - Menu Options 0 (Fix All), 1 (Fix Missing) or 3 (Fix GoLang) will activate this function

# Revision 1.0.6 - theHarvester fix removed
  - Python3.9.1 has arrived! No longer in Release Candidate status!
  - theHarvester fix is no longer necessary and has been commented as of this Revision
  - if no further complications, code will be removed completely

# Revision 1.0.5 - Gedit returns!
  - gedit has been added to fix_all and fix_missing functions

# Revision 1.0.4 - fix theHarvester (removed in 1.0.6)
 - This is only to be used in the following case :
   - Menu option H and will only be called via menu option H
   - Kali 2020.4 has been apt upgraded and python3.9 is installed
   - theHarvester is not functioning and is getting an error on uvloop
   - this will set python3 to default to python3.9
   - git clones uvloop, applies fixes and recompiles
   - git clones theHarvester, applies fixes and installs
 - additional checks will be added in the future

# Revision 1.0.3 - Metasploit 6 to Metasploit 5 Downgrade Option / Apt Upgrade returns!
  - Menu option D has been added to preform the downgrade
    - will not be called by any other function
    - only menu option D will execute the downgrade
    - metasploit will complain about 2 versions of reline being installed but do not believe it is an issue
    - places a hold on metasploit-framework so it will not be upgraded in the future
  - Pimpmyupgrade menu option 9
    - set as a stand alone function, and will not be called from any other function in the script
    - apt upgrade will only be called from this function
    - mark metasploit-framework to be ignored in the upgrade process
    - preform apt upgrade without upgrading metasploit-framework
    - unmark metasploit-framework from being held back
  - Fix All menu option 0 (modified)
    - now only runs menu options 1 thru 8 , does not include menu 9 (pimpmyupgrade)

# Revision 1.0.2 - Apt Upgrade Commented Out
  - Due to Metasploit being upgraded from msf5 -> MSF6
    apt upgrade has been commented out and will NOT be run
    at this time.

# Revision 1.0.1 Python-Requests
  - added python requests and colorama installations to fix_missing (menu option 1) and (menu option 0) fix_all

# Revision 1.0.0 Atom replaces Gedit  
  - pimpmykali has reached a state of consistency and stability in the function it preforms
    version is being bumped to v1.0.0 to be more in line with version numbering standards.
  - Atom has replaced gedit, gedit will no longer be installed by pimpmykali

# Revision 0.5j - rockyou.txt.gz
  - added fix_rockyou function
  - added gzip -dq /usr/share/wordlists/rockyou.txt.gz
   - fix_missing and fix_all both call this function
  - added restart-vm-tools as a part of menu 9 pimpmyupgrade
  - added fix for bad apt hash issue (automatically applied)
  - revision is going to be bumped to v1.0.0 upon next release

# Revision 0.5i - virtualbox specific fixes
   - virtualbox-guest-addditions-iso added to check_vm as a part of fix_upgrade
   - VBoxLinuxAdditions.run execution added to check_vm as a part of fix_upgrade
   - '/sbin/rcvboxadd quicksetup all' added to check_vm as a part of fix_upgrade

# Revision 0.5h
   - minor code cleanup
   - 2nd warning screen of nuke impacket has been disabled and will no longer show
   - removed --borked from main menu system as the ! menu item is now available
   - added htop to fix_missing

# Revision 0.5g
   - minor updates
   - moved wait_time, finduser and groups to global vars from local vars
   - general cleanup of script, comments, etc
   - 2nd warning screen of nuke impacket has been disabled and will no longer show

# Revision 0.5f
   - flameshot, gedit and seclists have been removed from fix_missing and
   - now will only be a part of fix_all or as an individual Option for installation
   - only command line switches with -- are now valid all others have been removed
   - all revision history except for the most 3 recent have been removed from the script
   - full revision history can be found here in REAME.md

# Revision 0.5e
   - Nuke Impacket added to menu, enter character ! to run nuke impacket
   - issues with people understanding how to use --borked on the command line
     a menu option of character ! was added to ease use of the nuke impacket function.
     the command:  sudo ./pimpmykali.sh --bored   was used to call the nuke-impacket
     function now thanks to a new menu item of ! it can be called from the menu system
     directly without the need for command line switches, but the switch is still available
   - command line switches with a single - or just the name have been removed all command line
     switches are now --nameofswtich as per the --help system indicates

# Revision 0.5d
   - bugfix Thank you to @AES ! for finding the bug, nmap wget script was pulling the wrong page
   - correct page has been added new version git pushd
   - unfortunatly versions 0.5c thru 0.4 are affected if you have an old version
     or havent ran pimpmykali.sh please git clone a fresh copy and re-run the nmap from the menu
     Menu Option 8 - Fix clamav-exec.nse
   - corrected http-shellshock.nse nmap script added - Thank you Alek & Blob!

# Revision 0.5c
   - fix_upgrade removed from fix_missing
   - fix_upgrade removed from fix_missing and is no longer 'forced' as a part of fix_missing
   - fix_upgrade will now only be called as a part of fix_all (menu 0) or fix_upgrade (menu 9)
     or command line switches --upgrade -upgrade or upgrade
   - general code cleanup, some additional comments added

# Revision 0.5b - The Essentials
   - Blindpentesters Essential Collection added
   - added Blindpentesters 'The Essentials' tools and utils collection
   - menu option 'B' for blindpentesters tools collection, installs, runs the_essentials.sh and exits

# Revision 0.5a
  - minor cosmetic fixes to pimpmyupgrade functions

# Revision 0.5
   - pimpmyupgrade added
   - fix_sources deb-src is not enabled in /etc/apt/sources.list - fixed
   - linux-headers-(uname -r) are not installed - fixed
   - new functions check_vm, virt_what, run_update are what comprise pimpmyupgrade
   - virt_what determines if vm is under virtualbox or vmware
   - check_vm checks for virtualbox or vmware and installs proper drivers for each
   - run_update runs fix_sources, runs apt upgrade calls virt_what, calls check_vm

# Revision 0.4b
   - minor updates
   - reworked fix_section works much better now
   - added slient 'mode' variable, uncomment silent= line to turn output on and off from apt etc
   - misc cleanup in the script

# Revision 0.4a
   - 2nd warning screen added for --borked impacket removal system
   - If you cant have a little fun with your own scripts your doing something wrong....
   - last chance warning screen ( mostly novelty ), random launch code generation on each run of --borked
   - list of target selection, targets locked, etc
   - seriously if you made it to --borked 2nd warning your having a bad day with impacket.. enjoy the giggle
   - 10 second wait timer added to last chance launch screen before operations are preformed
   - if no ctrl+c is entered to cancel the operation, fix_sead is run, followed by fix_impacket
   - added apt -y reinstall python3-impacket impacket-scripts to fix error with smbmap after impacket removal

# Revision 0.4
   - Major Update for impacket removal
   - added flameshot as a part of the missing group to be installed
   - added clamav-exec.nse wget to fix clamav-exec.nse failed during nmap --script vuln scans
   - new commandline switch of --borked has been implemented for removal of impacket across various locations
   - added --borked notice to menu system, help system
   - added warning screen for --borked, only input of Y will proceed anything else exits
   - fix_sead_warning, fix_sead_run, fix_impacket_array, fix_impacket all executed in order with --borked
     - fix_sead_run removes any and all directories named impacket* in the following locations (you have been warned):
        /opt /usr/bin /usr/local/lib /usr/lib /home/$finduser/.local/bin /home/$finduser/.local/lib ~/.local/lib ~/.local/bin
      - fix_sead_run, also removes via fix_impacket_array any .py or .pyc related to impacket in the following:
        /usr/bin/$impacket_file /usr/local/bin/$impacket_file
         (root)~/.local/bin/$impacket_file
         (user)/home/$finduser/.local/bin/$impacket_file

# Revision 0.3d
  - added flameshot to fix_missing as a part of the default installed tools
  - emergency fix to --force, everything should be functioning now

# Revision 0.3c
  - per request kali-root-login enabling prompt has been reworked and reworded to be less confusing and
    to give the user a better explanation of what the script is doing at that stage
  - added to note that if you dont understand what this part of the script is doing hit N
  - added colors for syntax highlighting in the onscreen messages of the script in places
  - added fix_nmap function for fixing /usr/share/nmap/scripts/clamav-exec.nse (commented out at this time
    clamav-exec.nse was an issue at one time but unknown if it is still relevent)
  - --force command line argument was being called without setting $force in fix_all $force - fixed

# Revision 0.3b
  - bug fix ( Thanks ShadeauxBoss! for finding it ) impacket installation was missing cd /opt/impacket-0.9.19
  - feature request added : Gedit installation menu option 7, is included in fix_missing, all and force
  - remove clear from exit screen

# Revision 0.3a
- the extraction of the impacket-0.9.19.tar.gz was leaving /opt/impacket-0.9.19 with 700 perms
  and an ownership of 503:root, this has been changed to ownership root:root and all files inside
  /opt/impacket-0.9.19 have had their permissions set to 755 after extraction of impacket-0.9.19.tar.gz
- Ascii art added to the menu

# Revision 0.3
- added checks for already installed installations, added --force command ( --force will run all fixes/reinstalls )
- fix_impacket function : added both .py and .pyc files to impacket removal array
  - added on screen notification of files being removed by the array
- fix_missing function  : has been reworked new vars check section force type
  - added fix_section function : fix_section is the workhorse for fix_missing
- reworked python-pip installation to its own function python-pip-curl and installs python-pip via curl

# Revision 0.2
- Added colorized notifications, help system, command line arguments, case based menu system
- valid command line arguments are: help, all, go, grub, impacket, missing, menu, smb, grub, root
- anything other than --all or -all or all , will only run that function and then exit.
- command line arguments can be used with -- or - or just the word itself to try can catch for all possible cases

- example command line var: --help or -help or help will catch help and works for all valid command line arguements
  anything other the command line arugement catch exits and displays help

What pimpmykali does:
- BlindPentesters The_Essentials tools and utilities collection
  - menu option B
- blank/black screen after login
  - pimpmyupgrade menu option #9
  - virtualbox shared folder permission denied - fixed
  - auto-detection of virtualbox or vmware hypervisor
- python-pip installation via curl
- python3-pip not installed
- seclists not installed
- golang not installed
- gedit installed (feature request)
- flameshot installed (feature request)
- locate installed (feature request)
- kali-root-login not installed and re-enables root login
  - reworked and added prompt
- nmap scripts clamav-exec.nse and http-shellshock.nse - fixed
- impacket-0.9.19
  - removes any prior installation of impacket (gracefully and forcefully)
  - installs impacket-0.9.19
  - installs python-pip via curl
  - installs python wheel
- impacket nuke function
  - menu option ! (its literally the ! character)
  - 1 warning screen (2nd warning screen removed)
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
  - adds /usr/sbin and /sbin to path
