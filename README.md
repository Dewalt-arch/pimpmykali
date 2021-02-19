# pimpmykali.sh

# Fixes for new imported Kali Linux virtual machines
  - Author assumes zero liability for any data loss or misuse of pimpmykali
  - Can be used on a bare metal machines, but thats on you
  - Menu breakdown added below revision history

# Github index updated added +x permission:
  - Script is now be executable upon clone (perms: 755 rwxr-xr-x added to github)
  - There is no need to chmod +x pimpmykali.sh upon git clone

# Installation script:
  - rm -rf pimpmykali/
  - git clone https://github.com/Dewalt-arch/pimpmykali
  - cd pimpmykali
  - sudo ./pimpmykali.sh
  - For a new kali vm, run menu option N

# Revision 1.2.0 - Menu Option N Modified
 - Kali 2021.1 + MSF-6.0.30-DEV Has been released live in the Kali Repo
 - Downgrade Metasploit has been removed from menu option N
 - Downgrade Metasploit is now only available via menu option D
 - Minor code cleanup

# Revision 1.1.9 - Gedit Connection Refused
  - added fix for gedit as root connection refused
  - Fix will be installed via :
    - 1 - Fix Missing
    - 0 - Fix All
    - N - New VM Setup
  - Menu item G to apply only this fix

# Revision 1.1.8 - Quality of life improvements
  - Added install for theharvester
  - xfce power management is now disabled
    - fix_xfcepower fix_xfce_root fix_xfce_user
      - will also be executed in menu option F - Fix Icons
  - pc speaker beep now disabled /etc/modprobe.d/nobeep.conf
    - silence_pcbeep
  - Items will be installed via the following :
    - 1 - Fix Missing
    - 0 - Fix All (Runs only options 1 thru 8)
    - N - New VM Setup  
  - Updated Readme.md documentation for menu items S, F
  - Minor updates for a few prompts  

# Revision 1.1.7 - libguestfs-tools cifs-utils added
  - libguestfs-tools added to fix_missing
  - cifs-utils added to fix_missing
  - Items will be installed via the following :
    - 1 - Fix Missing
    - 0 - Fix All (Runs only options 1 thru 8)
    - N - New VM Setup  

# Revision 1.1.6 - update to curl get-pip.py   
  - script has been updated to point directly to the python2.7 get-pip.py

# Revision 1.1.5 - Fix SPIKE
  - menu option S to apply this fix only
  - fix_spike will be applied thru the following menu options automatically
    - 1 - Fix Missing (fix_spike is a part of fix_missing)
    - 0 - Fix All (Runs only options 1 thru 8)
    - N - New VM Setup  
  - current version of spike2.9-1kali7 throws undefined symbol error
  - removes spike2.9-1kali7
  - installs spike_2.9-1kali6 (reverts spike to prior version)
  - apt adds hold to spike to prevent accidental future upgrades
  - apt hold will be removed at a future date once 2.9-1kali7 issues are resolved

# Revision 1.1.4 - Fix Broken XFCE Icons
  - menu option F to apply this fix only
    - Menu N and 9 will apply fix automatically as a part of their function
  - restores FileManager (Folder Icon on Taskbar) function  
  - restores TerminalEmulator (Terminal Icon) function
  - restores "File System" icon on desktop function
  - restores "Home" icon on desktop function

# Revision 1.1.3 - added Are you sure prompt
  - Added "Are you sure you want to copy all files from /home/kali to /root" prompt
  - Gives the user a last chance to abort the function
  - There are no major functional changes between 1.1.2 and 1.1.3 other than the additional
    prompt to the copy /home/kali to /root function
  - Answering Y - performs copy function of /home/kali to /root
  - Answering N - skips copy function and proceeds on to the next section of the script

# Revision 1.1.2 - copy /home/kali to /root screen and prompt
  - 1.1.2 Notes updated to reflect 1.1.3 addition and changes to 1.1.2 function
  - Recently there have been a number of users wanting to run as root in kali but finding there
    are no files or directories in /root once the root login is enabled and they login as root.

    This is the default as root was disabled, there is nothing in /root

  - This function ONLY executes If the user selects Yes at the enable root login prompt

  - A second screen and prompt was added to the Enable Root Login function
    - Prompts the user to copy everything from /home/kali to /root (And we mean everything!)
    - Answering Y - will prompt user for "Are you sure?" added in 1.1.3
    - Answering N - will skip the copy and end this function
  - No file-checking will be performed
  - Warning: This WILL overwrite anything in /root with the contents of /home/kali if Yes is selected
  - Function does NOT remove anything from /home/kali

# Revision 1.1.1 - quick fix
  - Quick fix applied to modifiy a specific function that was calling
  - the exit_screen when it should not have been

# Revision 1.1.0 - python module: xlrd added
  - added pip install xlrd==1.2.0 to fix missing
  - general code cleanup
  - Thank you to hackza for testing functions on Mac Vmware Fusion!

# Revision 1.0.9 - Qemu/Libvirt Detection added
  - Thank you m4ul3r! It was his idea and testing that we are able to add this!
  - detection of "kvm" hypervisor
  - upon that detection xserver-xorg-video-qxl spice-vdagent are installed

# Revision 1.0.8 - New Menu Item n or N
  - function will run fix_all, fix_missing, downgrade metasploit and pimpmyupgrade
  - executes menu options 0, D and 9 from a single menu item.
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
  - Menu option D has been added to perform the downgrade
    - will not be called by any other function
    - only menu option D will execute the downgrade
    - metasploit will complain about 2 versions of reline being installed but do not believe it is an issue
    - places a hold on metasploit-framework so it will not be upgraded in the future
  - Pimpmyupgrade menu option 9
    - set as a stand alone function, and will not be called from any other function in the script
    - apt upgrade will only be called from this function
    - mark metasploit-framework to be ignored in the upgrade process
    - perform apt upgrade without upgrading metasploit-framework
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
  - pimpmykali has reached a state of consistency and stability in the function it performs
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
   - 10 second wait timer added to last chance launch screen before operations are performed
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
  - bug fix impacket installation was missing cd /opt/impacket-0.9.19
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

- example command line var: --help or -help or help will catch help and works for all valid command line arguments
  anything other the command line arugement catch exits and displays help

# Menu Breakdown of Pimpmykali

Menu breakdown of what pimpmykali does:
- This section is being provided as a brief overview

Menu option N  (New Users/New VM's Should start here!)
- executes menu option 0 fix all ( menu options 1 thru 8 )
- executes menu opiion 9 (pimpmyupgrade)

Menu Option 1 - Fix missing
- fix_sources
  - uncomment #deb-src from /etc/apt/sources.list
- python-pip installation via curl
- python3-pip installed
- seclists installed
- gedit installed (feature request)
- flameshot installed (feature request)
- locate installed (feature request)
- fix_rockyou function
  - gunzip's /usr/share/wordlists/rockyou.gz to /usr/share/wordlists/rockyou.txt
- fix_golang function
  - installs golang
  - adds golang GOPATH to .bashrc and .zshrc
- installs htop
- installs python requests
- installs python xlrd
- disables xfce power management
- blacklists pcspkr kernel module /etc/modprobe.d/nobeep.conf

Menu Option 2 - Fix smb.conf
- Fix /etc/samba/smb.conf
  - adds client min protocol = CORE  below [global]
  - adds client max protocol = SMB3  below [global]

Menu Option 3 - Fix Golang
- Installs golang
  - checks for GOPATH in .bashrc and .zshrc
    - if GOPATH is found, adds nothing
    - if not found, adds GOPATH statements to both .zshrc and .bashrc

Menu Option 4 - Fix Grub
- adds mitigations=off to GRUB_CMDLINE_LINUX_DEFAULT

Menu Option 5
- installs Impacket-0.9.19

Menu Option 6 - Enable root login
- installs kali-root-login
  - prompts for root password
  - copy /home/kali to /root prompt (1.1.2)
    - added are you sure? prompt to copy /home/kali to /root prompt (1.1.3)

Menu Option 7
- installs Atom text editor

Menu Option 8 - Fix Nmap
- wget nmap script fixes
  - clamav-exec.nse
  - http-shellshock.nse (Thank you Alek!)

Menu Option 9 - Pimpmyupgrade
- additional notes will be added
- performs apt ugprade and places hold on metasploit-framework from being upgraded
  - due to msf6 to msf5 downgrade
- fix : black screen after login
  - add additional details here
- fix : Hypervisor detection (vmware, virtualbox, qemu/libvirt)
  - add additional details here
- fix : virtualbox shared folder fix applied     

Menu Option 0 - Fix all
- Executes Menu options 1 thru 8 Only

Menu Option B    
- BlindPentesters The_Essentials tools and utilities collection
  - Install all of BlindPentesters favorite tools and utilities to /opt (aprox 8GB)
  - Click the link below for a full list of the_essentials.sh script and its inner workings
  - https://github.com/blindpentester/the-essentials

Menu Option F
  - Fixes XFCE Broken Icons "TerminalEmulator" Not Found
  - Fixes XFCE Open Catfish instead of Thunar when double clicking Home or FileSystem Icon
    - this fix is a temporary fix and will be removed once xfce has been corrected

Menu Option S - Fix Spike
  - Fixes undefined symbol error thrown when using generic_send_tcp
    - this fix is temporary and will be removed once a corrected version is available  

Menu Option D - Downgrade metasploit-framework from 6 to 5
- included in menu option N
  - downgrades metasploit-framework (msfconsole) from msf6 to msf5
  - this is a temporary solution and will eventually be removed once a corrected version is available

Menu Option ! - Nuke Impacket (yes its literally the ! character)
- removes any prior installation of impacket (gracefully and forcefully)
  - installs impacket-0.9.19
  - installs python-pip via curl
  - installs python wheel
  - 1 warning screen (2nd warning screen removed)

# TODO   
  - clean up todo list :)
