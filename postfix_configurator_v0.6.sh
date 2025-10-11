#!/bin/bash
# name          : postfix_configurator for gmx mail address
# desciption    : set postfix configuration for satelite system, test mail fuction for defaul system users
# autor         : speefak ( itoss@gmx.de )
# licence       : (CC) BY-NC-SA
# version 	: 0.6
# notice 	:
# infosource	:
#
#------------------------------------------------------------------------------------------------------------
############################################################################################################
#######################################   define global variables   ########################################
############################################################################################################
#------------------------------------------------------------------------------------------------------------

 DefaultSenderMailAddress="sender"
 DefaultSenderMailAddressPassword="sender_password"

 SystemUsersNames=$(awk -F: '$3 >= 1000 && $3 <= 1100 {print $1}' /etc/passwd | tr "\n" " ")
 SystemUserServiceNames="root www-data fail2ban"

 PostfixDir="/etc/postfix"
 PostfixLogFile="/var/log/mail.log"
 PostfixBackupFileName="$(date +'%Y-%m-%d-%H%M%S')_postfix-config.tar.gz"

 RequiredPackets="bash sed awk bsd-mailx postfix bind9-dnsutils"

 HostName=$(hostname)
 DNSDomainName=$(grep ^domain /etc/resolv.conf | awk '{printf $2}' || dnsdomainname)
 FQDN="$(hostname).$DNSDomainName"
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
		BackupConfig;-bc
		CreateNewConfig;-cnc
		EditConfig;-ec
		UpdatePostmapDB;-udb
		SendTestMail;-stm
		Monochrome;-m
		CheckForRequiredPackages;-cfrp
		ScriptInformation;-si
		HelpDialog;-h
	"

	# set entered vars from optionvarlist
	OptionAllocator=" "									# for option seperator "=" use cut -d "="
	SAVEIFS=$IFS
	IFS=$(echo -en "\n\b")
	for InputOption in $(echo " $@" | sed 's/ -/\n-/g' ) ; do  				# | sed -e 's/-[a-z]/\n\0/g'
		for VarNameVarValue in $OptionVarList ; do
			VarName=$(echo "$VarNameVarValue" | cut -d ";" -f1)
			VarValue=$(echo "$VarNameVarValue" | cut -d ";" -f2)
			if [[ -n $(echo " $InputOption" | grep -w " $VarValue" 2>/dev/null) ]]; then
#				InputOption=$(sed 's/[ 0]*$//'<<< $InputOption)
				InputOption=$(sed 's/ $//g'<<< $InputOption)
				InputOptionValue=$(awk -F "$OptionAllocator" '{print $2}' <<< "$InputOption" )
				if [[ -z $InputOptionValue ]]; then
					eval $(echo "$VarName"="true")
				else
					eval $(echo "$VarName"='$InputOptionValue')
				fi
			fi
		done
	done
	IFS=$SAVEIFS

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
	# clear colocodes from logfiles: cat $Logfile | sed 's/\x1B\[[0-9;]*m//g'

	BG='\033[47m'
	FG='\033[0;30m'

	# parse required colours for sed usage: sed 's/status=sent/'${Green}'status=sent'${Reset}'/g' |\
	if [[ $1 == sed ]]; then
		for ColorCode in $(cat $0 | sed -n '/^load_color_codes/,/FG/p' | tr "&" "\n" | grep "='"); do
			eval $(sed 's|\\|\\\\|g' <<< $ColorCode)						# sed parser '\033[1;31m' => '\\033[1;31m'
		done
	fi
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
#TODO	printf " -ec		=> (e)dit (c)onfig \n"
	printf " -udb		=> (u)pdate postmap (d)ata(b)ase \n"
	printf " -stm <a>	=> (s)end (t)est (m)ails (a => automode)\n"
	printf " -bc		=> (b)ackup (c)onfig \n"
	printf " -m		=> (m)onochrome output \n"
	printf " -si		=> (s)how script (i)nformation \n"
    printf " -cfrp		=> (c)heck (f)or (r)equired (p)ackages \n"
	printf  "\n${Red} $1 ${Reset}\n"
	printf "\n"
	exit
}
#------------------------------------------------------------------------------------------------------------------------------------------------
script_information () {
	printf "\n"
	printf " Scriptname: $ScriptName\n"
	printf " Version:    $Version \n"
	printf " Location:   $(pwd)/$ScriptName\n"
	printf " Filesize:   $(ls -lh $0 | cut -d " " -f5)\n"
	printf "\n"
	exit 0
}
#------------------------------------------------------------------------------------------------------------------------------------------------
check_for_required_packages () {

	InstalledPacketList=$(dpkg -l | grep ii | awk '{print $2}' | cut -d ":" -f1)

	for Packet in $RequiredPackets ; do
		if [[ -z $(grep -w "$Packet" <<< $InstalledPacketList) ]]; then
			MissingPackets=$(echo $MissingPackets $Packet)
		fi
	done

	# print status message / install dialog
	if [[ -n $MissingPackets ]]; then
		printf  "missing packets: \e[0;31m $MissingPackets\e[0m\n"$(tput sgr0)
		read -e -p "install required packets ? (Y/N) "			-i "Y" 		InstallMissingPackets
		if   [[ $InstallMissingPackets == [Yy] ]]; then

			# install software packets
			sudo apt update
			sudo apt install -y $MissingPackets
			if [[ ! $? == 0 ]]; then
				exit
			fi
		else
			printf  "programm error: $LRed missing packets : $MissingPackets $Reset\n\n"$(tput sgr0)
			exit 1
		fi

	else
		printf "$LGreen all required packets detected$Reset\n"
	fi
}
#------------------------------------------------------------------------------------------------------------------------------------------------
backup_postfix_config () {

	printf "\n Backup postfix configuration ( $PostfixDir).. \n\n"
	cd $PostfixDir
	tar -czvf "$PostfixBackupFileName" *
	cd

	printf "\n Postfix backup created: $PostfixDir/$PostfixBackupFileName \n"
}
#------------------------------------------------------------------------------------------------------------------------------------------------
write_new_postfix_configuration () {

	# enter $DefaultSenderMailAddress and DefaultSenderMailAddressPassword
	printf "\n\n"
	read -e -p " Enter default mail address: " 			-i "$DefaultSenderMailAddress" 		DefaultSenderMailAddress
	read -e -p " Enter default mail address password: " 		-i "$DefaultSenderMailAddressPassword" 	DefaultSenderMailAddressPassword

	# check for non empty inputs
	if [[ -z $DefaultSenderMailAddress ]];		then usage "no sender mail address entered" ; fi
	if [[ -z $DefaultSenderMailAddressPassword ]];	then usage "no sender mail password entered" ; fi
	printf "\n"

	# write hostname to main.cf
	File="$PostfixDir/main.cf"
	printf " set $HostName / $DNSDomainName / $FQDN in $File \n\n"
	sed -i 's/myhostname = .*/myhostname = '$HostName'/' $File
	sed -i 's/myorigin = .*/myorigin = '$HostName'/' $File
#	sed -i 's/mydestination = .*/mydestination = '$FQDN', '$HostName', localhost\.'$DNSDomainName', localhost/' $File
	sed -i 's/mydestination = .*/mydestination = /' $File					 # no entries for Satelitesystem to avoid any local mail processing

	# write sasl_password file
	File="$PostfixDir/sasl_password"
	FileContent="mail.gmx.net $DefaultSenderMailAddress:$DefaultSenderMailAddressPassword"
	printf " write $File: \n\n$FileContent\n\n\n"
	echo "$FileContent" > $File

	# write sender_canonical file
	File="$PostfixDir/sender_canonical"
	FileContent=$(for i in $SystemUsersNames $SystemUserServiceNames ; do echo "$i $DefaultSenderMailAddress" ; done)
	printf " write $File: \n\n$FileContent\n\n\n"
	echo "$FileContent" > $File

	# write generic file
	File="$PostfixDir/generic"
	FileContent=$(for i in $SystemUsersNames $SystemUserServiceNames ; do echo "$i@$HostName $DefaultSenderMailAddress" ; done)
	printf " write $File: \n\n$FileContent\n\n\n"
	echo "$FileContent" > $File
}
#------------------------------------------------------------------------------------------------------------------------------------------------
update_postfix_postmap_database () {

	# delete existing postmap databases
	rm -f /etc/postfix/generic.db
	rm -f /etc/postfix/sasl_password.db
	rm -f /etc/postfix/sender_canonical.db

	# create new postmap databases from config files
	printf " update postmap database:\n\n"
	for i in generic sasl_password sender_canonical ; do
		printf "$PostfixDir/$i\n"
		postmap $PostfixDir/$i
	done
	printf "\n\n"

	# set persmissions
	chown -R root:root /etc/postfix
	sudo chmod 600 	/etc/postfix/sasl_password.db
	sudo chmod 600  /etc/postfix/sasl_password

	# restart postfix service
	sudo /etc/init.d/postfix reload
}
#------------------------------------------------------------------------------------------------------------------------------------------------
send_test_mail () {

	# check for logfile
	if [[ ! -f $PostfixLogFile ]]; then
		usage " Logfile not found: $PostfixLogFile "
	fi

	# send mail for various systemusers
	for Mailaddress in $DefaultSenderMailAddress $SystemUsersNames $SystemUserServiceNames ; do

		Date=$(date '+%F %H:%M:%S')

		# proceed dialog
		if [[ $FirstRun == false ]] && [[ ! $SendTestMail == a ]] ; then
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
		sleep 2

		# get postfix mail ID
		#PostfixMailID=$(sudo journalctl --since "2 minutes ago" | grep postfix | tail -n 10  | grep $Mailaddress | awk -F "]: " '{print $2}' | cut -d ":" -f1 | tail -n1)
		PostfixMailID=$( timeout 10 grep postfix "$PostfixLogFile" 2>/dev/null | tail -n 10  | grep $Mailaddress | awk -F "]: " '{print $2}' | cut -d ":" -f1 | tail -n1)

		# get values from logfile
		LogContent=$( grep $PostfixMailID "$PostfixLogFile" 2>/dev/null)
		MailFromSystemuser=$(echo "$LogContent" | grep -m1 " from=" 2>/dev/null | awk -F " from=<" '{printf $2}' | cut -d ">" -f1)
		MailFromAddress=$(echo "$LogContent" | grep -m1 " to=<" 2>/dev/null | awk -F " to=<" '{printf $2}' | cut -d ">" -f1)
		MailToAddress=$(echo "$LogContent" | head -n3 | tail -n1 | grep -m1 " from=" 2>/dev/null | awk -F " from=<" '{printf $2}' | cut -d ">" -f1)

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
		load_color_codes sed
		printf "$(echo "$LogContent" |\
			sed 's/status=sent/'${Green}'status=sent'${Reset}'/g' |\
			sed 's/status=bounced/'${Red}'status=bounced'${Reset}'/g' )\n\n"

		# printf status message
		printf " from:   $MailFromAddress ($MailFromSystemuser)\n"
		printf " to:     $MailToAddress\n"

		load_color_codes
		if [[ -n $(grep "$status=sent" <<< "$LogContent") ]]; then
			printf " status: ${Green}sent${Reset}\n"
		else
		#elif [[ -n $(grep "$status=sent" <<< "$LogContent") ]]; then
			printf " mailstatus => ${Red}ERROR${Reset}\n"
		fi
		
		# draw seperator line 
		width=$(tput cols)
		line=$(printf "%0.s-" $(seq 1 $width))
		printf "\n%s\n" "$line"
	done
}
#------------------------------------------------------------------------------------------------------------------------------------------------
############################################################################################################
#############################################   start script   #############################################
############################################################################################################
#------------------------------------------------------------------------------------------------------------------------------------------------

	# check help dialog
	if [[ -n $HelpDialog ]] || [[ -z $1 ]]; then usage "help dialog" ; fi

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

	# check for required packages
	if [[ -n $CheckForRequiredPackages ]];  then
		check_for_required_packages
	fi

#------------------------------------------------------------------------------------------------------------------------------------------------

	# check for postfix backup
	if [[ -n $BackupConfig ]];  then
		backup_postfix_config
	fi 
	
#------------------------------------------------------------------------------------------------------------------------------------------------

	# check for create new config
	if [[ -n $CreateNewConfig ]]; then
		backup_postfix_config
		write_new_postfix_configuration
		update_postfix_postmap_database
	fi

#------------------------------------------------------------------------------------------------------------------------------------------------

	if [[ -n $UpdatePostmapDB ]]; then
		update_postfix_postmap_database
	fi

#------------------------------------------------------------------------------------------------------------------------------------------------

	# check for send test mails
	if [[ -n $SendTestMail ]]; then
		send_test_mail
	fi

#------------------------------------------------------------------------------------------------------------------------------------------------

exit

# changelog 0.5 => add function check for required packages
# changelog 0.4 => add backup function
# changelog 0.4 => add -stm automode / add help dialog var / clear mydestination postfix var
# changelog 0.3 => add logfile check / update code for postfix update function => add output notice / update load_colorcode for sed usage
# changelog 0.2 => setup correct hostname in main.cf postfix config and generic 

