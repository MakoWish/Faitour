#!/bin/bash


#===============================================================================
# Clear the terminal just so the menus look better
#===============================================================================
clear


#===============================================================================
# Check that we are running as root
#===============================================================================
if [ "$EUID" -ne 0 ]; then
	printf "\n\nThis script must be run as root/sudo! Exiting... \n\n"
	exit 5
fi


#===============================================================================
# Confirm removal
#===============================================================================
while true; do
	read -p 'Are you sure you would like to remove Faitour (Y|n)? ' yn
	case $yn in
		y|Y|"")
			echo 'Removing Faitour...'
			break;;
		n|N)
			echo 'Cancelling Faitour removal...'
			exit 0
			break;;
	esac
done


#===============================================================================
# Get this script's directory to flag for removal
#===============================================================================
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )


#===============================================================================
# Stop and remove the service
#===============================================================================
printf 'Stopping systemd faitour.service... '
systemctl stop faitour.service
echo 'done.'

if test -f '/etc/systemd/system/multi-user.target.wants/faitour.service'; then
	printf 'Removing service file "/etc/systemd/system/multi-user.target.wants/faitour.service"... '
	rm -f '/etc/systemd/system/multi-user.target.wants/faitour.service'
	echo 'done.'
fi
if test -f '/usr/lib/systemd/system/faitour.service'; then
	printf 'Removing service file "/usr/lib/systemd/system/faitour.service"... '
	rm -f '/usr/lib/systemd/system/faitour.service'
	echo 'done.'
fi

printf 'Reloading system daemon... '
systemctl daemon-reload
echo 'done.'


#===============================================================================
# Remove the install directory
#===============================================================================
while true; do
	read -p "Delete the installation directory ${INSTALL_DIR} (Y|n)? " yn
	case $yn in
		y|Y|"")
			printf "Removing installation directory ${INSTALL_DIR}... "
			rm -rf $INSTALL_DIR
			echo 'done.'
			break;;
		n|N)
			echo "Leaving installation directory ${INSTALL_DIR} in place."
			break;;
	esac
done


#===============================================================================
# All done!
#===============================================================================
printf 'Faitour removal complete. \n\n'
