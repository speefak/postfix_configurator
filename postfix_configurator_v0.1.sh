#!/bin/bash
# name          : postfix_configurator for gmx mail address
# desciption    : set postfix configuration includiung mail test parameter
# autor         : speefak ( itoss@gmx.de )
# licence       : (CC) BY-NC-SA
# version 	: 0.1
# notice 	:
# infosource	:
#
#------------------------------------------------------------------------------------------------------------
############################################################################################################
#######################################   define global variables   ########################################
############################################################################################################
#------------------------------------------------------------------------------------------------------------

 DefaultSenderMailAddress="sender@gmx.de"
 DefaultSenderMailAddressPassword="sender_passord"

 SystemUsersNames=$(awk -F: '$3 >= 1000 && $3 <= 1100 {print $1}' /etc/passwd | tr "\n" " ")
 SystemUserServiceNames="root www-data fail2ban"
 PostfixDir="/etc/postfix"
 PostfixLogFile="/var/log/mail.log" 

 HostName=$(hostname)
 HostDomainName="$(hostname).$(dnsdomainname)"
 HostIP=$(hostname -I | tr " " "\n" | sort -u | sed '/^$/d')

 Version=$(cat $(readlink -f $(which $0)) | grep "# version" | head -n1 | awk -F ":" '{print $2}' | sed 's/ //g')
 ScriptFile=$(readlink -f $(which $0))
 ScriptName=$(basename $ScriptFile)

#------------------------------------------------------------------------------------------------------------
############################################################################################################
########################################   set vars from options  ##########################################
############################################################################################################
#------------------------------------------------------------------------------------------------------------

	OptionVarList="
		CreateNewConfig;-cnc
		UpdatePostmapDB;-udb
		SendTestMail;-stm
		Monochrome;-m
		ScriptInformation;-si
	"

	# set entered vars from optionvarlist
	for InputOption in $(echo " $@" | tr " " "\n" ) ; do
		for VarNameVarValue in $OptionVarList ; do
			VarName=$(echo "$VarNameVarValue" | cut -d ";" -f1)
			VarValue=$(echo "$VarNameVarValue" | cut -d ";" -f2)
			if [[ $InputOption == $VarValue ]]; then
				eval $(echo "$VarName"="$InputOption")
			fi
		done
	done

#------------------------------------------------------------------------------------------------------------
############################################################################################################
###########################################   fixed functions   ############################################
############################################################################################################
#------------------------------------------------------------------------------------------------------------
load_color_codes () {
	Black='\033[0;30m'	&&	DGray='\033[1;30m'
	LRed='\033[0;31m'	&&	Red='\033[1;31m'
	LGreen='\033[0;32m'	&&	Green='\033[1;32m'
	LYellow='\033[0;33m'	&&	Yellow='\033[1;33m'
	LBlue='\033[0;34m'	&&	Blue='\033[1;34m'
	LPurple='\033[0;35m'	&&	Purple='\033[1;35m'
	LCyan='\033[0;36m'	&&	Cyan='\033[1;36m'
	LLGrey='\033[0;37m'	&&	White='\033[1;37m'
	Reset='\033[0m'
	# Use them to print in your required colours:
	# printf "%s\n" "Text in ${Red}red${Reset}, white and ${Blue}blue${Reset}."

	BG='\033[47m'
	FG='\033[0;30m'

	# reloard colored global vars
	for i in $(cat $0 | sed '/load_color_codes/q'  | grep '${Reset}'); do
		eval "$i"
	done
}
#------------------------------------------------------------------------------------------------------------------------------------------------
usage() {
	printf " iptables-blacklist version: $Version | script location $basename $0\n"
	clear
	printf "\n"
	printf " Usage: $(basename $0) <options> "
	printf "\n"
	printf " -h		=> (h)elp dialog \n"
	printf " -cnc		=> (c)reate (n)ew (c)onfig \n"
	printf " -udb		=> (u)pdate postmap (d)ata(b)ase \n"
	printf " -stm		=> (s)end (t)est (m)ails \n"
	printf " -m		=> (m)onochrome output \n"
	printf " -si		=> (s)how script (i)nformation \n"
	printf  "\n${Red} $1 ${Reset}\n"
	printf "\n"
	exit
}
#------------------------------------------------------------------------------------------------------------
script_information () {
	printf "\n"
	printf " Scriptname: $ScriptName\n"
	printf " Version:    $Version \n"
	printf " Location:   $(pwd)/$ScriptName\n"
	printf " Filesize:   $(ls -lh $0 | cut -d " " -f5)\n"
	printf "\n"
	exit 0
}
#------------------------------------------------------------------------------------------------------------
write_new_postfix_configuration () {

	# enter $DefaultSenderMailAddress and DefaultSenderMailAddressPassword
	printf "\n\n"
	read -e -p " Enter default mail address: " 			-i "$DefaultSenderMailAddress" 		DefaultSenderMailAddress
	read -e -p " Enter default mail address password: " 		-i "$DefaultSenderMailAddressPassword" 	DefaultSenderMailAddressPassword

	# check for non empty inputs
	if [[ -z $DefaultSenderMailAddress ]];		then usage "no sender mail address entered" ; fi
	if [[ -z $DefaultSenderMailAddressPassword ]];	then usage "no sender mail password entered" ; fi
	printf "\n"

	# write sasl_password file
	File="$PostfixDir/sasl_password"
	FileContent="mail.gmx.net $DefaultSenderMailAddress:$DefaultSenderMailAddressPassword"
	printf " write $File => \n$FileContent\n\n"
	echo "$FileContent" > $File

	# write sender_canonical file
	File="$PostfixDir/sender_canonical"
	FileContent=$(for i in $SystemUsersNames $SystemUserServiceNames ; do echo "$i $DefaultSenderMailAddress" ; done)
	printf " write $File: \n$FileContent\n\n"
	echo "$FileContent" > $File

	# write generic file
	File="$PostfixDir/generic"
	FileContent=$(for i in $SystemUsersNames $SystemUserServiceNames ; do echo "$i@$HostName $DefaultSenderMailAddress" ; done)
	printf " write $File: \n$FileContent\n\n"
	echo "$FileContent" > $File
}
#------------------------------------------------------------------------------------------------------------
update_postfix_postmap_database () {

	# delete existing postmap databases 
	rm /etc/postfix/generic.db
	rm /etc/postfix/sasl_password.db
	rm /etc/postfix/sender.db
	rm /etc/postfix/sender_canonical.db

	# create new postmap databases from config files 
	postmap 	/etc/postfix/generic
	postmap	/etc/postfix/sasl_password
	postmap 	/etc/postfix/sender
	postmap    /etc/postfix/sender_canonical

	# set persmissions
	chown -R root:root /etc/postfix
	sudo chmod 600 	/etc/postfix/sasl_password.db
	sudo chmod 600  /etc/postfix/sasl_password

	# restart postfix service
	sudo /etc/init.d/postfix reload sh update_postfix_DB.sh
}
#------------------------------------------------------------------------------------------------------------
send_test_mail () {

	# send mail for various systemusers
	for Mailaddress in $DefaultSenderMailAddress $SystemUsersNames $SystemUserServiceNames ; do

		Date=$(date '+%F %H:%M:%S')

		# proceed dialog
		if [[ $FirstRun == false ]]; then
			printf "\npress any key to send test mail for user/address => $Yellow$Mailaddress$Reset <= / press c to cancel testing"
			read -n 1 -p " " Exit
			printf "\n\n"
			if [[ $Exit == [cC] ]] ;
				then break
			fi
		fi
		FirstRun=false

		# create mail content
		SubjectLine="Testmail from $(hostname) | $Date | $Mailaddress"
		MailBody="This is a test mail from $(hostname) ($HostIP) | $Date"

		# send mail
		printf "\n sending mail: $Mailaddress\n\n"
		echo "$MailBody" | mail -s "$SubjectLine" "$Mailaddress"

		# wait for log entry
		sleep 1

		# get postfix mail ID
		#PostfixMailID=$(sudo journalctl --since "2 minutes ago" | grep postfix | tail -n 10  | grep $Mailaddress | awk -F "]: " '{print $2}' | cut -d ":" -f1 | tail -n1)
		PostfixMailID=$( grep postfix "$PostfixLogFile" 2>/dev/null | tail -n 10  | grep $Mailaddress | awk -F "]: " '{print $2}' | cut -d ":" -f1 | tail -n1)

		# get values from logfile
		LogContent=$( grep $PostfixMailID "$PostfixLogFile" 2>/dev/null)
		MailFromSystemuser=$(echo "$LogContent" | grep -m1 " from=" 2>/dev/null | awk -F " from=<" '{printf $2}' | cut -d ">" -f1)
		MailFromAddress=$(echo "$LogContent" | head -n3 | tail -n1 | grep -m1 " from=" 2>/dev/null | awk -F " from=<" '{printf $2}' | cut -d ">" -f1)
		MailToAddress=$(echo "$LogContent" | grep -m1 " to=<" 2>/dev/null | awk -F " to=<" '{printf $2}' | cut -d ">" -f1)

		#MailFromSystemuser=$(echo "$LogContent" | grep -oP 'from=<\K[^>]+' | grep -m1 )
		#MailFromAddress=$(echo "$LogContent" | grep -oP 'from=<\K[^>]+' | grep .m2 )
		#MailToAddress=$(echo "$LogContent" | grep -oP 'to=<\K[^>]+' )


		# check for log entry
		if [[ -z $PostfixMailID ]]; then
			MissingMailAddress=$(echo "$MissingMailAddress" "$PostfixMailID")
			printf " mail ID for ${Red}$Mailaddress${Reset} in $PostfixLogFile not found \n\n"
			continue
		fi

		# parse colored output
		printf "$(echo "$LogContent" |\
			sed 's/status=sent/'${Green}'status=sent'${Reset}'/g' |\
			sed 's/status=bounced/'${Red}'status=bounced'${Reset}'/g' )\n\n"

		# printf status message
		printf " from:   $MailFromAddress ($MailFromSystemuser)\n"
		printf " to:     $MailToAddress\n"

		if [[ -n $(grep "$status=sent" <<< "$LogContent") ]]; then
			printf " status: ${Green}sent${Reset}\n"
		else
		#elif [[ -n $(grep "$status=sent" <<< "$LogContent") ]]; then
			printf " mailstatus => ${Red}ERROR${Reset}\n"
		fi
	done
}
#------------------------------------------------------------------------------------------------------------
############################################################################################################
#############################################   start script   #############################################
############################################################################################################
#------------------------------------------------------------------------------------------------------------------------------------------------

	# check for help dialog
	if [[ -z $1 ]] || [[ $1 == -h ]]; then usage ;fi

#------------------------------------------------------------------------------------------------------------------------------------------------

	# check for monochrome output
	if [[ -z $Monochrome ]]; then
		load_color_codes
	fi

#------------------------------------------------------------------------------------------------------------------------------------------------

	# check for script information
	if [[ -n $ScriptInformation ]]; then script_information ; fi

#------------------------------------------------------------------------------------------------------------------------------------------------

	# check for root permission
	if [ "$(whoami)" = "root" ]; then echo "";else echo "Are You Root ?";exit 1;fi

#------------------------------------------------------------------------------------------------------------------------------------------------

	# check for create new config
	if [[ -n $CreateNewConfig ]]; then
		write_new_postfix_configuration
		update_postfix_postmap_database
	fi

#------------------------------------------------------------------------------------------------------------

	if [[ -n $UpdatePostmapDB ]]; then
		update_postfix_postmap_database
	fi

#------------------------------------------------------------------------------------------------------------

	# check for send test mails
	if [[ -n $SendTestMail ]]; then
		send_test_mail
	fi

#------------------------------------------------------------------------------------------------------------

exit



# changelog 0.2 => TODO setup correct hostname in main.cf postfix config






