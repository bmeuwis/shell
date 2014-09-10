SRCDIR=/var/log
LISTDIR=/root/OUT
FWCMD=/sbin/iptables
FWSAVE=/sbin/iptables-save
WHITELIST=$LISTDIR/whitelist.txt
BLACKLIST=$LISTDIR/blacklist.txt
SAVEFILE=$LISTDIR/iptables.`date +%a`

SSHPORT="202"                                                           # Create allowed ports list
ALLOWED="$SSHPORT"                      # SSH
ALLOWED=$ALLOWED" 80"                   # HTTP
ALLOWED=$ALLOWED" 443"                  # HTTPS
ALLOWED=$ALLOWED" 8080"                 # Apex/GlassFish
ALLOWED=$ALLOWED" 8081"                 # JasperReports
ALLOWED=$ALLOWED" 1527"                 # Oracle listener


function report {
echo "`date` ($$) ${@}"
}

function list_vars {
report SRCDIR = $SRCDIR
report LISTIDR = $LISTDIR
report FWCMD = $FWCMD
report FWSAVE = $FWSAVE
report WHITELIST = $WHITELIST
report BLACKLIST = $BLACKLIST
report SAVEFILE = $SAVEFILE
report SSHPORT = $SSHPORT
report ALLOWED = $ALLOWED
}

function kernel_stuff {                                                 # Enable kernel-monitoring support
report Enabling kernel monitoring                                       # cfr. Linux Firewalls, Ch. 4 (Robert L. Ziegler)

echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts                 # Enable broadcast echo protection

for f in /proc/sys/net/ipv4/conf/*/accept_source_route; do              # Disable Source Routed Packets
   echo 0 > $f
done

echo 1 > /proc/sys/net/ipv4/tcp_syncookies                              # Enable TCP SYN Cookie Protection

for f in /proc/sys/net/ipv4/conf/*/accept_redirects; do                 # Disable ICMP Redirect Acceptance
   echo 0 > $f
done

for f in /proc/sys/net/ipv4/conf/*/send_redirects; do                   # Don't send Redirect Messages
   echo 0 > $f
done

for f in /proc/sys/net/ipv4/conf/*/rp_filter; do                        # Drop Spoofed Packets coming in on an interface, which if replied to,
   echo 1 > $f                                                          # would result in the reply going out a different interface
done

   # Log packets with impossible addresses
for f in /proc/sys/net/ipv4/conf/*/log_martians; do
   echo 1 > $f
done
}

function create_whitelist {
report Creating the whitelist

cat << EOD > $WHITELIST
192.168.0.0/24          # Local network
134.54.0.9                      # Agfa IP
188.40.104.150          # akira
78.46.91.181            # farragut
78.46.91.185            # cartouche
141.135.0.98            # current Telenet
EOD

DYNDNS=`nslookup elcaro1.dyndns.org | tail -2 | grep Address | awk '{ print $2 }'`      # Telenet Home Address through DynDNS
report Adding Telenet Home Address $DYNDNS to whitelist.
echo "$DYNDNS" >> $WHITELIST

/usr/bin/who | grep bmeuwis | while read line                           # Add IP of currently logged on user bmeuwis
do
FQDN=`echo $line | cut -d '(' -f 2 | sed -e 's:)::g' | sort | uniq`
MYIP=`nslookup $FQDN | tail -2 | head -1 | awk '{ print $2 }'`
echo "$MYIP" >> $WHITELIST
report bmeuwis currently logged on with IP $MYIP 
report and FQDN $FQDN - adding to whitelist.
done

grep "Accepted password for bmeuwis" /var/log/secure | awk '{ print $11 }' | sort |  uniq >> $WHITELIST # Add IP of previously accepted user bmeuwis

mv $WHITELIST $WHITELIST.tmp
cat $WHITELIST.tmp | awk '{ print $1 }' | sort | uniq >> $WHITELIST
}

function create_blacklist {                                             # List all found IPs in secure that occur more than 3 times
report Creating the blacklist

MYTMP=/tmp/$$.out
report ... parsing /var/log/secure
cat /var/log/secure | grep "Failed password for root" | awk '{ print $11 }' | sort | uniq > $MYTMP
cat /var/log/secure | grep "Failed password for invalid user" | awk '{ print $13 }' | sort | uniq >> $MYTMP
cat /var/log/secure | grep "Invalid user" | awk '{ print $10 }' | sort | uniq >> $MYTMP
report ... parsing /etc/hosts.deny
cat /etc/hosts.deny | awk '{ print $2 }' | grep "^[0-9]"  | sort | uniq >> $MYTMP
cat $MYTMP | sort | uniq >> $BLACKLIST
rm $MYTMP

# List all IPs that contain certain strings we know are script kiddies and occur more than 3 times
report ... parsing access_logs for "phpmyadmin"
find /var/log/httpd -name '*access_log' -exec grep " 404 " {} \; | grep -i "phpmyadmin"  | awk '{ print $1 }'  \
  | sort | uniq -c | grep -v " [1-3] [0-9]" | awk '{ print $2 }'  >> $BLACKLIST
report ... parsing access_logs for "dragostea" \& "w00tw00t" \& "Morfeus strikes"
find /var/log/httpd -name '*access_log' -exec egrep -i 'dragostea|w00tw00t|morfeus strikes'  {} \; | awk '{ print $1 }' \
  | sort | uniq >> $BLACKLIST

mv $BLACKLIST $BLACKLIST.tmp
cat $BLACKLIST.tmp | grep -v "^###" | grep -v "188.40.104.150" | sort | uniq >> $BLACKLIST
}

function clean_blacklist {                                              # Clean out those addresses that can not be resolved by iptables
report Cleaning up blacklist - non-resolvable addresses
touch $BLACKLIST.good
cat $BLACKLIST | grep -v "^#" | while read line
do
x=`echo $line | awk '{ print $1 }'`
/sbin/iptables -A INPUT -t filter -s $x -j DROP > /dev/null 2>&1
RC=$?
[ $RC -eq 0 ] && echo $line >> $BLACKLIST.good
[ $RC -ne 0 ] && report Problem adding to blacklist : $line
done
}

function check_blacklist {
report Making sure no IPs in the blacklist that should not
cat $BLACKLIST.good | grep -v -e "access.telenet" -e "testip" -e "193.239.211.5" -e "193.239.211.4" > $BLACKLIST
echo "### Generated by $0 on `date`" >> $BLACKLIST
}

report Starting to build the firewall ...

function build_firewall {                                               # Drop all existing filter rules
report Now dropping all existing rules ...                              # and get rid of other chains generated by install
$FWCMD -F
$FWCMD -X

$FWCMD -A INPUT -i lo -j ACCEPT                                         # Unlimited traffic on the loopback interface is allowed
$FWCMD -A OUTPUT -o lo -j ACCEPT
}

function process_whitelist {                                            # First, run through $WHITELIST, accepting all traffic from
report Running through WHITELIST ...                                    # the hosts and networks contained therein.
for x in `grep -v ^# $WHITELIST | awk '{print $1}'`; do
report " ... permitting $x"
$FWCMD -A INPUT -t filter -s $x -j ACCEPT
done
}

function process_blacklist {                                            # Now run through $BLACKLIST, dropping all traffic from
report Running through BLACKLIST ...                                    # the hosts and networks contained therein.
report Blocking `cat $BLACKLIST | grep -v "^#" | wc -l | awk '{ print $1 }'` IPs
for x in `grep -v ^# $BLACKLIST | awk '{print $1}'`; do
report "   ... blocking $x"
#$FWCMD -A INPUT -t filter -s $x -j LOG                                 # Uncomment if you want to log in the messages-file.
$FWCMD -A INPUT -t filter -s $x -j DROP
done
}

function open_ports {                                                   # Next, the permitted ports: What will we accept
report Accepting ports ...                                              # from hosts not appearing on the blacklist?
for port in $ALLOWED; do
report "   ... accepting port $port"
$FWCMD -A INPUT -t filter -p tcp --dport $port -j ACCEPT
done
}

function secure_ssh {
# The first rule records the IP address of each attempt to access port 22 using the recent module.
# The second rule checks to see if that IP address has attempted to connect 3 or more times
# within the last 60 seconds, and if not then the packet is accepted.
# Note this rule would require a default policy of DROP on the input chain.

report Securing SSH
$FWCMD -A INPUT -p tcp --dport $SSHPORT -m recent --set --name ssh --rsource
$FWCMD -A INPUT -p tcp --dport $SSHPORT -m recent ! --rcheck --seconds 60 --hitcount 3 --name ssh --rsource -j ACCEPT
}

function drop_the_rest {                                                # Finally, unless it's mentioned above, and it's an
report Dropping all the rest and logging to messages-file               # inbound startup request, just drop it.
$FWCMD -A INPUT -t filter -p tcp --syn -j LOG                           # Uncomment if you want to log in the messages-file.
$FWCMD -A INPUT -t filter -p tcp --syn -j DROP
}

function housekeeping {
$FWSAVE > $SAVEFILE                                                     # Save iptables config
$FWSAVE > /etc/sysconfig/iptables                                       # Make sure at reboot the rules are the same
chmod 600 $BLACKLIST $WHITELIST $SAVEFILE                               # Change rights on saved files
rm $BLACKLIST.tmp $BLACKLIST.good                                       # Some cleanup
}

### MAIN PROGRAM ###

create_whitelist                                                        # Creating the new whitelist
create_blacklist                                                        # Creating or adding to the blacklist with new offenders
clean_blacklist                                                         # Check for non-resolvable IPs
check_blacklist                                                         # Avoid accidents to happen ...
build_firewall
process_whitelist
process_blacklist
open_ports
secure_ssh
drop_the_rest
housekeeping                                                            # Clean up after you

report Ending $0
