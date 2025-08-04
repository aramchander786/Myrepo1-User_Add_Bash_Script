#!/bin/bash
######################################################################################################################################################        #                                                                                                                        #
        #                  #Custom script, was developed by A Ramchander, is not a final one, versioning is ON.                  #
	#                                                                                                                        #
	##########################################################################################################################
######################################################################################################################################################
PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/usr/local/bin
timestamp=$(date '+%Y%m%d%H%M')
######################################################################################################################################################  
                                                     function syntax () {
	                                             cat <<EOC
                    Usage : $(basename $0) <list of servers (one per line)> <list of users to create> [ --home=<directory for user homes> ]

                    List of users in following format:
              <username>:<initial group>:<additional groups (seperated by comma)>:<GECOS (Name, email, function, ...)>:<SSH public key (optional)>

                    If an SSH key is provided, account will be set to SSHONLY without password expiration
                                 #If there is no key, the line has to end with a colon ':'
                
EOC
                                                                     }     

if [ $# -lt 2 ]; then
	echo -e "\nERROR : Invalid number of arguments"
        syntax	
	exit 1
fi
serverlist=$1
userlist=$2
home_base=${3:7}
if [ ! -r "$serverlist" ]; then
        echo -e "\nERROR : Server list $serverlist is not readable or does not exist"
        usage
        exit 2
fi

if [ ! -r "$userlist" ]; then
        echo -e "\nERROR : User list $userlist is not readable or does not exist"
        usage
        exit 3
fi

if [ ${#home_base} -eq 1 ]; then
        echo -e "\nERROR : $alt_home is not a valid home directory"
        usage
        exit 3
fi
user=$(id -nu)
prefix="$(basename $0 .sh).$serverlist.$userlist.$timestamp"
rscript="${prefix}.remote.sh"
remote_dir="/tmp/${prefix}"
rscript_out="${prefix}.remote.out"
outdir="${prefix}.out.dir"
mkdir -p $outdir
outfile="${prefix}.out"
uspwfile="userpw.out"

ssh="/usr/bin/ssh -b classroom -o StrictHostKeyChecking=no -o PasswordAuthentication=no -o ChallengeResponseAuthentication=no -o KbdInteractiveAuthentication=no "
scp="/usr/bin/scp -q -o StrictHostKeyChecking=no -o PasswordAuthentication=no -o ChallengeResponseAuthentication=no -o KbdInteractiveAuthentication=no "
declare -a userarray
declare -a passwdarray
declare -a cryptarray

function generate_password {
	_pw=$(tr -dc _A-Z-a-z-0-9 < /dev/urandom | head -c12)
	export _salt=$(openssl rand 1000 | strings | grep -io [0-9A-Za-z\.\/] | head -n 16 | tr -d '\n' )
	export _pw=$_pw
	pwentry=$(perl -e 'print crypt("$ENV{'_pw'}","\$6\$"."$ENV{'_salt'}"."\$")')

	echo "$pwentry $_pw"
}

while read line; do
	userarray[${#userarray[*]}]=$(echo "\"$line\"")
	A=$(echo "$line" | cut -d':' -f5)
	if [ "x$A" = "x" ] 
	then
		declare -a stringarray
		stringarray=$(generate_password)
		cryptarray[${#cryptarray[*]}]=$(echo ${stringarray[0]}  |awk '{print $1}')
		passwdarray[${#passwdarray[*]}]=$(echo ${stringarray[0]}  |awk '{print $2}')
	else
		cryptarray[${#cryptarray[*]}]="SSH-ONLY"
		passwdarray[${#passwdarray[*]}]="SSH-ONLY"
	fi
		
		
done < $userlist

cat > $rscript <<EOF
remote_dir=$remote_dir
rscript_out=$rscript_out

# set home base if --home was used
if [ ${#home_base} -gt 1 ]; then
	mkdir -p $home_base
	home_base="-b $home_base"
else
	home_base=""
fi

uarr=(${userarray[@]}) # array with usera
carr=('${cryptarray[@]}') # array with encrypted passwords
a=(\$(echo \${carr[@]} | tr ' ' '\n'))

server=\$1
stamp=\$(date "+%Y-%m-%d;%H:%M")

[ -e \$remote_dir/\$rscript_out ] && rm -f \$remote_dir/\$rscript_out
[ -e \$remote_dir/\$rscript_out.log ] && rm -f \$remote_dir/\$rscript_out.log

touch \$remote_dir/\$rscript_out	# Assure the file is available, otherwise script think that connection is failed if no changes are done
chmod 644 \$remote_dir/\$rscript_out	# Assure the file is readable for others, otherwise script will fail on RHEL-8 systems
touch \$remote_dir/\$rscript_out.log	# Assure the file is available, otherwise script think that connection is failed if no changes are done
chmod 644 \$remote_dir/\$rscript_out.log    # Assure the file is readable for others, otherwise script will fail on RHEL-8 systems


exec &> \$remote_dir/\$rscript_out.log


i=0
for user in "\${uarr[@]}"; do
	
	username=\$(echo \$user | awk -F\: '{print \$1}')
	pwentry="\${a[\$i]}"
	igroup=\$(echo \$user | awk -F\: '{print \$2}') # initial group
	agroup="\$(echo \$user | awk -F\: '{print \$3}' | tr -d ' ')" # additional group(s)
	gecos="\$(echo \$user | awk -F\: '{print \$4}')"
	sshkey="\$(echo \$user | awk -F\: '{print \$5}')"
	
	if [ "x\$username" == "x" ] || [ "x\$igroup" == "x" ] || [ "x\$gecos" == "x" ]; then
		echo "INFO : Invalid or empty line in userlist. Skipping \$user..." >> \$remote_dir/\$rscript_out
		((i++))
		continue
	fi

	if [ "\$(toupper \$sshkey)" == "SUONLY" ]; then # assure group nologin is available
		if ! getent group nologin; then
			groupadd -g 3100001 nologin
		fi
	fi
	
	
	if ! getent group \$igroup; then
		igroupid=10000
		[ "\$(toupper \$sshkey)" == "SUONLY" ] && igroupid=1000 # functional group
		while getent group \$igroupid; do (( igroupid++ )); done # get next free groupid
		groupadd -g \$igroupid \$igroup
	else
		igroupid=\$(getent group \$igroup | awk -F \: '{print \$3}')
	fi

	oifs=\$IFS
	IFS=','
	for ag in \$agroup; do
		[ \${#ag} -le 1 ] && continue # do not deal with empty groups
		
		if ! getent group \$ag; then
			agid=10000
			[ "\$(toupper \$sshkey)" == "SUONLY" ] && agid=1000 # functional group
			while getent group \$agid; do (( agid++ )); done # get next free groupid
			groupadd -g \$agid \$ag
			echo "NOTICE : Added group \$ag with GID \$agid" >> \$remote_dir/\$rscript_out
		fi


	done  # for ag in \$agroup; do
	IFS=\$oifs

	if getent passwd \$username; then
		eumod=false # bool to check if existing user was modified
		
		ugecos="\$(getent passwd \$username | cut -d ':' -f5)"
		if [ "\$ugecos" != "\$gecos" -a "\$(toupper \$gecos)" != "NOUPDATE" ]; then
			echo "NOTICE : Updating GECOS with \"\$gecos\"" >> \$remote_dir/\$rscript_out
			usermod -c "\$gecos" \$username
			eumod=true
		fi
		
		oifs=\$IFS
		IFS=','
		for ag in \$agroup; do
			if ! getent group \$ag | grep "\$username"; then
				echo "\$username exists, but is not member of \$ag"
				eumod=true
				if usermod -a -G \$ag \$username; then
					echo "\$username added to group \$ag" >> \$remote_dir/\$rscript_out
				else
					echo "WARNING : Could not add \$username to \$ag" >> \$remote_dir/\$rscript_out
				fi
			else
				echo "\$username exists and is member of \$ag" >> \$remote_dir/\$rscript_out
			fi
		done
		IFS=\$oifs
		if [ "\$(toupper \$sshkey)" == "SUONLY" ]; then
			groups \$username | grep nologin || usermod -a -G nologin \$username
			eumod=true
		fi
		! \$eumod && echo "\$username exists and no change is done" >> \$remote_dir/\$rscript_out
	else
		uaparm="" # useradd parameter to be used for -G if agroup is not empty
		[ "\$(toupper \$sshkey)" == "SUONLY" ] && ! echo \$agroup | grep -q nologin && agroup="\$agroup nologin"
		[ \${#agroup} -gt 1 ] && uaparm="-G \$agroup"
                 echo "INFO : useradd \$home_base -g \$igroupid \$uaparm -s /bin/bash -c \"\$gecos\" \$username" >> \$remote_dir/\$rscript_out

		if ! useradd \$home_base -g \$igroupid \$uaparm -s /bin/bash -c "\$gecos" -m \$username; then
			echo "ERROR : Cannot add user \$username" >> \$remote_dir/\$rscript_out
			continue
		fi
		echo "INFO : Added user \$username with groups \$igroup,\$agroup" >> \$remote_dir/\$rscript_out
	fi # if getent passwd \$username; then

	homedir=\$(getent passwd \$username | awk -F \: '{print \$6}')
	
	[ ! -d \$homedir/.ssh ] && mkdir -p -m 0700 \$homedir/.ssh && chown \$username.\$igroup \$homedir/.ssh
	[ ! -f \$homedir/.ssh/authorized_keys ] && touch \$homedir/.ssh/authorized_keys && chown \$username.\$igroup \$homedir/.ssh/authorized_keys && chmod 0600 \$homedir/.ssh/authorized_keys
	
	if [ "\$(toupper \$sshkey)" == "SUONLY" ]; then
		echo "NOTICE : Account \$username set to SUONLY without password aging" >> \$remote_dir/\$rscript_out
		/usr/sbin/usermod -p "*SUONLY*" \$username
		# RHEL 6.6 has a bug where -d -1 does not work anymore ...
		# chage -d -1 -m -1 -M -1 -W -1 \$username
		chage -d 0 -m -1 -M -1 -W -1 \$username
		sed -i "/^\$username:/ s/:0:/::" /etc/shadow
		
		continue # next user
	fi
	
	if [ \${#sshkey} -gt 10 ]; then # this seem to be a valid SSH key
		if ! grep "\$sshkey" \$homedir/.ssh/authorized_keys; then
			echo "NOTICE : SSH key added for user \$username" >> \$remote_dir/\$rscript_out
			echo "\$sshkey" >> \$homedir/.ssh/authorized_keys
		fi
		pw=\$(grep "^\$username:" /etc/shadow | awk -F \: '{print \$2}')
		[ \${#pw} -eq 0 ] && pw="nopassword" # if user is just created there is no password to check
		[ "\$pw" == "!!" ] && pw="nopassword" # user was created earlier, but without password and got locked then ...
		if [ "\${pw:0:1}" != "*" ] && [ "\${pw:0:1}" != "!" ] && ! echo \$pw | grep -i "nologin"; then # account seem to have a password
			echo "NOTICE : Account \$username set to SSHONLY without password aging" >> \$remote_dir/\$rscript_out
			/usr/sbin/usermod -p "*SSHONLY*" \$username
		        # RHEL 6.6 has a bug where -d -1 does not work anymore ...
		        # chage -d -1 -m -1 -M -1 -W -1 \$username
		        chage -d 0 -m -1 -M -1 -W -1 \$username
		        sed -i "/^\$username:/ s/\:0\:/\:\:/" /etc/shadow
		fi
	else # no ssh key provided
		pw=\$(grep "^\$username" /etc/shadow | awk -F \: '{print \$2}')
		if [ "\${pw:0:1}" != "$" ] && [ "\${pw:0:1}" != "*" ] && [ "\${pw:0:1}" != "!" ] || [ "\$pw" == "!!" ] || [ "\$pw" == "!" ]; then
			echo "NOTICE : Set standard password for user \$username" >> \$remote_dir/\$rscript_out
#			echo "\$std_pwd" | passwd --stdin \$username
#			usermod -p '\$6\$T7D31MTc\$rGq6GHEBEx.GdeGvP3tIb5.KtP6EVEThrKARkspsMgVMLIIWg7yKX76fgydwJgcd4xeGxUH3DT7eASZvDIByM0' \$username
			usermod -p "\$pwentry" \$username
			chage -d 0 \$username
		fi
	fi
	((i++))
	echo

done # for user in "\${uarr[@]}"; do

EOF

##########################################################################
#        function to wait till all connections are finished
##########################################################################
function wait_for_servers () {
        loops=0
        locks=$(ls -1 $outdir/*.lock 2>/dev/null | wc -l)
        trapmsg="This process cannot be stopped, since it runs on remote servers. Remove the lock files to force a stop ..."

        trap "echo $trapmsg" SIGINT SIGTERM
        if [ $locks -ge 1 ]; then echo "There are connections to finish." ; fi
        while [ $locks -ge 1 ]; do
                echo "Waiting for servers : $(ls -1 $outdir/*.lock | rev | awk -F "[./]+" '{printf "%s ",$2}' | rev)"
                sleep 5
                if [ $loops -gt 180 ]; then     # since sleep is 5, 180 should be 15 minutes
                        echo 
                        echo 
                        echo "It seems that the change script hangs on a server (check which is still the same)" 
                        echo "You might want to connect to that server and kill the hanging process" 
                        echo "but check the log files in $remote_dir first (if there are any)." 
                        echo 
                        loops=0
                fi
#                tput el1        # erase current line
#                tput rc # goto begin of line
                locks=$(ls -1 $outdir/*.lock 2>/dev/null | wc -l)
                (( loops += 1 ))
        done && echo "" 
        trap - SIGINT SIGTERM
}

function fix_issue () {
        server=$1
        res=0
        cmds="sudo /bin/bash $remote_dir/$rscript $server"
#        cmds="/bin/bash $remote_dir/$rscript $server"

        touch $outdir/$server.lock # lock file so that it's seen which server is checked
	
	$ssh -t $user@$server "mkdir -p -m 0777 $remote_dir" >> $prefix.log 2>&1
        if [ $? -ne 0 ]; then
                echo "Connection to $server : FAILED " >> $prefix.log
		echo "Could not create temporary directory" >> $prefix.log
                res=1
	else
		$scp $rscript $user@$server:$remote_dir/$rscript >> $prefix.log 2>&1
		if [ $? -ne 0 ]; then
			echo "Connection to $server : FAILED" >> $prefix.log
			echo "Could not copy to temporary directory" >> $prefix.log
			res=2
		else
			$ssh -t $user@$server "$cmds" >> $prefix.log 2>&1
			if [ $? -ne 0 ]; then
				echo "Connection to $server : FAILED" >> $prefix.log
				echo "Command $cmds not executed." >> $prefix.log
				echo "!!! Output not removed from $server !!!" >> $prefix.log
				res=4
			else
			$scp $user@$server:$remote_dir/$rscript_out.log $outdir/$server.out.log >> $prefix.log 2>&1
				if [ $? -ne 0 ]; then
					echo "Connection to $server : FAILED" >> $prefix.log
					echo "Output from $server not copied to $outdir/$server.out.log" >> $prefix.log
					echo "!!! Output not removed from $server !!!" >> $prefix.log
					res=8
				else
					$scp $user@$server:$remote_dir/$rscript_out $outdir/$server.out >> $prefix.log 2>&1
					$ssh -t $user@$server "rm -rf $remote_dir" >> $prefix.log 2>&1
					echo "Connection to $server : OK" >> $prefix.log
					res=0
				fi
			fi
		fi
	fi
        [ $res -ne 0 ] && echo $server >> $prefix.bg-conn_failed
        rm -f $outdir/$server.lock
        return $res
}

maxstarts=20    # Don't create more than maxstarts instances
for server in $(awk -F ";" '{print $1}' $serverlist | tr -d '\"'); do
        locks=$(ls -1 $outdir/*.lock 2>/dev/null | wc -l)

        if [ $locks -ge $maxstarts ]; then echo "Max processes of $maxstarts reached" ; fi

        while [ $locks -ge $maxstarts ]; do
                sleep 5;
                echo -n "."
                locks=$(ls -1 $outdir/*.lock 2>/dev/null | wc -l)
        done
        echo ""  # wait till next process can be started
        echo "Background connection to $server" 

        fix_issue $server &
        sleep 1 # Don't fill process list too fast
done

wait_for_servers # wait till background connections are finished

cp $prefix.log $prefix.final.log

if [ -e $prefix.bg-conn_failed ]; then
        cp $prefix.bg-conn_failed $prefix.conn-2nd.try
        rm -f $prefix.bg-conn_failed
        for server in $(cat $prefix.conn-2nd.try); do
                echo -n "Second attempt to connect to $server : "
                echo -n "Second attempt to connect to $server : " >> $prefix.final.log
                fix_issue $server
		res=$?
                if [ $res -ne 0 ]; then
                        echo $server >> $prefix.failed
                        echo "FAILED" >> $prefix.final.log
                        echo "FAILED" 
			if [ $res -eq 8 ]; then
				echo "!!! Output not removed from $server !!!" >> $prefix.failed
			fi
                else
                        echo "OK" >> $prefix.final.log
                        echo "OK" 
                fi
        done
fi

rm -f $rscript

if [ -e $prefix.failed ]; then
        echo
        echo "Manually check required for this server(s) (see $prefix.failed) :"
        echo
        echo $(cat $prefix.failed)
fi

echo
echo "Servers on which all went fine :"
echo $(grep "OK" $prefix.final.log | awk '{print $3}' | grep -v "\[")
echo

[ -e $outfile ] && rm -f $outfile
echo "List from $(basename $0) will be written to $outfile"
#echo "$header" > $outfile
for server in $(awk -F ";" '{print $1}' $serverlist | tr -d '\"'); do
	if [ -e $outdir/$server.out ]; then
	    if [ $(stat $outdir/$server.out | tr -d '[^ ]+' | grep "Size" | awk -F "[\t: ]+" '{print $2}') -gt 0 ]; then
		echo "Output from $server" >> $outfile
		cat $outdir/$server.out >> $outfile
		echo >> $outfile
	    else
		echo "$server : Connection OK : No Output;" >>$outfile
	    fi
	else
		echo "$server : Connection FAILED : No Output;" >>$outfile
	fi
done
cp -p $outfile $outfile.txt
chmod 644 $outfile.txt
k=0
for i in "${userarray[@]}"
do
	username=$(echo $i | cut -d':' -f 1)
        echo "User $username has password ${passwdarray[$k]}"
        ((k++))
done > ${outdir}/$uspwfile

###################################################################################
###################################################################################
#**********************************************************************************#
echo "
Do not forget to send the password to users which were successfully
created without a SSH key. You can find the passwords in ${outdir}/${uspwfile}
"
#********************************************************************************#
##################################################################################
