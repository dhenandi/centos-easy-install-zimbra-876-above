#!/bin/bash
clear

##### Configure Hostname ######
echo -n "Enter your Hostname (ex : mail/webmail) : "
read HOST_NAME

echo -n "Enter your Hostname (ex : dhenandi.com) : "
read DOMAIN_NAME

##########
echo "Preparing Configuration..."

#### Variable For Zimbra ####
HOSTNAME=$HOST_NAME
DOMAIN=$DOMAIN_NAME
CONTAINERIP=$(ip addr | grep eth0 | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1  -d'/')
RANDOMHAM=$(date +%s|sha256sum|base64|head -c 10)
RANDOMSPAM=$(date +%s|sha256sum|base64|head -c 10)
RANDOMVIRUS=$(date +%s|sha256sum|base64|head -c 10)
PASSWORD="Secret123!"
TIME=`date -d "today" "+%Y%m%d00"`

#### FOR PTR ####
BLOCK1=`echo $CONTAINERIP | cut -d "." -f1`;
BLOCK2=`echo $CONTAINERIP | cut -d "." -f2`;
BLOCK3=`echo $CONTAINERIP | cut -d "." -f3`;
BLOCK4=`echo $CONTAINERIP | cut -d "." -f4`;
	
mkdir -p /tmp/zcs
chmod 777 -R /tmp/zcs
echo "export LC_ALL=en_US.UTF-8" >> /etc/profile

## Configuring /etc/hosts and Installing the DNS Server ##
echo "Configuring hosts and DNS..."
	
echo "domain $DOMAIN" > /etc/resolv.conf
echo "search $DOMAIN" >> /etc/resolv.conf
echo "nameserver 127.0.0.1" >> /etc/resolv.conf
echo "nameserver 8.8.8.8" >> /etc/resolv.conf
echo "nameserver 8.8.8.8" >> /etc/resolv.conf


cp /etc/hosts /tmp/zcs/hosts.backup
echo "127.0.0.1         localhost" > /etc/hosts
echo "$CONTAINERIP      $HOSTNAME.$DOMAIN       $HOSTNAME" >> /etc/hosts

GREPHOST=`ls /etc/sysconfig/network | grep -i hostname | cut -d "=" -f1`

if [[ "$GREPHOST" = "HOSTNAME" ]]; then
	sed -i '/HOSTNAME/d' /etc/sysconfig/network
	echo "HOSTNAME=$host_name" >> /etc/sysconfig/network
	hostname $host_name
else
	sed -i '/HOSTNAME/d' /etc/sysconfig/network
	echo "HOSTNAME=$host_name" >> /etc/sysconfig/network
	hostname $host_name
fi

echo "Make Sure Your Configuration is Correct"
echo "=============================================="
echo "Host Name   : $HOSTNAME"
echo "Domain Name : $DOMAIN"
echo "IP Address  : $CONTAINERIP"
echo "Password    : $PASSWORD"
echo "----------------------------------------------"
echo "Your /etc/hosts content : "
echo "----------------------------------------------"
cat /etc/hosts
echo "=============================================="
echo "Press ENTER if it's Correct , Press CTRL+C if there's anything to fix..."
read presskey


## Configuring Timezone
mv /etc/localtime /etc/localtime.bak
ln -s /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# Disable service sendmail, postfix or SELINUX

sed -i s/'SELINUX'/'#SELINUX'/g /etc/sysconfig/selinux
echo 'SELINUX=disabled' >> /etc/sysconfig/selinux
setenforce 0
service iptables stop
service ip6tables stop
chkconfig iptables off
chkconfig ip6tables off
service sendmail stop
service postfix stop
chkconfig sendmail off
chkconfig postfix off

# Update repo and install package needed by Zimbra

echo ""
echo -e "[INFO] : Update repos and install packages required by Zimbra"
echo ""

yum -y update
yum -y install perl perl-core wget screen w3m elinks openssh-clients openssh-server bind bind-utils unzip nmap sed nc sysstat libaio rsync telnet aspell ntp openssh-clients

# Connecting to NTP Server

ntpdate 0.id.pool.ntp.org

# Configuring DNS Server
FOLDERDNSRECORD="/var/named";
REVERSEDNS="$BLOCK3.$BLOCK2.$BLOCK1.in-addr.arpa";

echo ""
echo -e "[INFO] : Configuring DNS Server"
echo ""

## Configure named.conf
NAMED=`ls /etc/ | grep named.conf.back`;

        if [ "$NAMED" == "named.conf.back" ]; then
	cp /etc/named.conf.back /etc/named.conf        
        else
	cp /etc/named.conf /etc/named.conf.back        
        fi

sed -i s/"listen-on port 53 { 127.0.0.1; };"/"listen-on port 53 { 127.0.0.1; any; };"/g /etc/named.conf
sed -i s/"allow-query     { localhost; };"/"allow-query     { localhost; any; };"/g /etc/named.conf

# Forward DNS

echo 'zone "'$DOMAIN'" IN {' >> /etc/named.conf
echo "        allow-update { none; };" >> /etc/named.conf
echo '        file "'$DOMAIN'";' >> /etc/named.conf
echo "        type master;" >> /etc/named.conf
echo "};" >> /etc/named.conf


touch /var/named/$DOMAIN
chgrp named /var/named/$DOMAIN

echo '$TTL 2D' > $FOLDERDNSRECORD/$DOMAIN
echo "@       IN SOA  ns1.$DOMAIN. root.$DOMAIN. (" >> $FOLDERDNSRECORD/$DOMAIN
echo '                                        2017062700	; serial' >> $FOLDERDNSRECORD/$DOMAIN
echo '                                        3H      		; refresh' >> $FOLDERDNSRECORD/$DOMAIN
echo '                                        1H      		; retry' >> $FOLDERDNSRECORD/$DOMAIN
echo '                                        1W      		; expire' >> $FOLDERDNSRECORD/$DOMAIN
echo '                                        1D )    		; minimum' >> $FOLDERDNSRECORD/$DOMAIN
echo "" >> $FOLDERDNSRECORD/$DOMAIN

echo "$DOMAIN.		IN      NS      ns1.$DOMAIN." >> $FOLDERDNSRECORD/$DOMAIN
echo "$DOMAIN.		IN      MX      0 $HOSTNAME.$DOMAIN." >> $FOLDERDNSRECORD/$DOMAIN
echo "ns1		IN      A       $CONTAINERIP" >> $FOLDERDNSRECORD/$DOMAIN
echo "$HOSTNAME		IN      A       $CONTAINERIP" >> $FOLDERDNSRECORD/$DOMAIN

# Reverse DNS

echo 'zone "'$REVERSEDNS'" in {' >> /etc/named.conf
echo "        allow-update { none; };" >> /etc/named.conf
echo '        file "'$REVERSEDNS'";' >> /etc/named.conf
echo "        type master;" >> /etc/named.conf
echo "};" >> /etc/named.conf

touch /var/named/$REVERSEDNS
chgrp named /var/named/$REVERSEDNS


echo '$TTL 2D' > $FOLDERDNSRECORD/$REVERSEDNS
echo "@       IN SOA  ns1.$DOMAIN. root.$DOMAIN. (" >> $FOLDERDNSRECORD/$REVERSEDNS
echo '                                        2017062700        ; serial' >> $FOLDERDNSRECORD/$REVERSEDNS
echo '                                        3H                ; refresh' >> $FOLDERDNSRECORD/$REVERSEDNS
echo '                                        1H                ; retry' >> $FOLDERDNSRECORD/$REVERSEDNS
echo '                                        1W                ; expire' >> $FOLDERDNSRECORD/$REVERSEDNS
echo '                                        1D )              ; minimum' >> $FOLDERDNSRECORD/$REVERSEDNS
echo "" >> $FOLDERDNSRECORD/$REVERSEDNS

echo "$REVERSEDNS. IN NS           ns1.$DOMAIN." >> $FOLDERDNSRECORD/$REVERSEDNS
echo "$BLOCK4.$REVERSEDNS.     IN PTR          ns1.$DOMAIN." >> $FOLDERDNSRECORD/$REVERSEDNS
echo "$BLOCK4.$REVERSEDNS.     IN PTR          $HOSTNAME.$DOMAIN." >> $FOLDERDNSRECORD/$REVERSEDNS


# Restart Service named

service named restart
chkconfig named on

echo ""
echo "Configuring Firewall, network, /etc/hosts and DNS server has been finished. please install Zimbra now"


## Building and adding the Scripts keystrokes and the config.defaults
touch /tmp/zcs/installZimbra-keystrokes
cat <<EOF >/tmp/zcs/installZimbra-keystrokes
y
y
y
y
y
n
y
y
y
y
y
y
y
n
y
EOF

touch /tmp/zcs/installZimbraScript
cat <<EOF >/tmp/zcs/installZimbraScript
AVDOMAIN="$DOMAIN"
AVUSER="admin@$DOMAIN"
CREATEADMIN="admin@$DOMAIN"
CREATEADMINPASS="$PASSWORD"
CREATEDOMAIN="$DOMAIN"
DOCREATEADMIN="yes"
DOCREATEDOMAIN="yes"
DOTRAINSA="yes"
EXPANDMENU="no"
HOSTNAME="$HOSTNAME.$DOMAIN"
HTTPPORT="8080"
HTTPPROXY="TRUE"
HTTPPROXYPORT="80"
HTTPSPORT="8443"
HTTPSPROXYPORT="443"
IMAPPORT="7143"
IMAPPROXYPORT="143"
IMAPSSLPORT="7993"
IMAPSSLPROXYPORT="993"
INSTALL_WEBAPPS="service zimlet zimbra zimbraAdmin"
JAVAHOME="/opt/zimbra/common/lib/jvm/java"
LDAPBESSEARCHSET="set"
LDAPHOST="$HOSTNAME.$DOMAIN"
LDAPPORT="389"
LDAPREPLICATIONTYPE="master"
LDAPSERVERID="2"
MAILBOXDMEMORY="486"
MAILPROXY="TRUE"
MODE="https"
MYSQLMEMORYPERCENT="30"
POPPORT="7110"
POPPROXYPORT="110"
POPSSLPORT="7995"
POPSSLPROXYPORT="995"
PROXYMODE="redirect"
REMOVE="no"
RUNARCHIVING="no"
RUNAV="yes"
RUNCBPOLICYD="no"
RUNDKIM="yes"
RUNSA="yes"
RUNVMHA="no"
SERVICEWEBAPP="yes"
SMTPDEST="admin@$DOMAIN"
SMTPHOST="$HOSTNAME.$DOMAIN"
SMTPNOTIFY="yes"
SMTPSOURCE="admin@$DOMAIN"
SNMPNOTIFY="yes"
SNMPTRAPHOST="$HOSTNAME.$DOMAIN"
SPELLURL="http://$HOSTNAME.$DOMAIN:7780/aspell.php"
STARTSERVERS="yes"
SYSTEMMEMORY="1.9"
TRAINSAHAM="ham.$RANDOMHAM@$DOMAIN"
TRAINSASPAM="spam.$RANDOMSPAM@$DOMAIN"
UIWEBAPPS="yes"
UPGRADE="yes"
USEEPHEMERALSTORE="no"
USESPELL="yes"
VERSIONUPDATECHECKS="TRUE"
VIRUSQUARANTINE="virus-quarantine.$RANDOMVIRUS@$DOMAIN"
ZIMBRA_REQ_SECURITY="yes"
ldap_bes_searcher_password="$PASSWORD"
ldap_dit_base_dn_config="cn=zimbra"
ldap_nginx_password="$PASSWORD"
mailboxd_directory="/opt/zimbra/mailboxd"
mailboxd_keystore="/opt/zimbra/mailboxd/etc/keystore"
mailboxd_keystore_password="$PASSWORD"
mailboxd_server="jetty"
mailboxd_truststore="/opt/zimbra/common/lib/jvm/java/jre/lib/security/cacerts"
mailboxd_truststore_password="changeit"
postfix_mail_owner="postfix"
postfix_setgid_group="postdrop"
ssl_default_digest="sha256"
zimbraFeatureBriefcasesEnabled="Enabled"
zimbraFeatureTasksEnabled="Enabled"
zimbraIPMode="ipv4"
zimbraMailProxy="TRUE"
zimbraMtaMyNetworks="127.0.0.0/8 [::1]/128 $CONTAINERIP/32 [::1]/128 [fe80::]/64"
zimbraPrefTimeZoneId="Asia/Bangkok"
zimbraReverseProxyLookupTarget="TRUE"
zimbraVersionCheckNotificationEmail="admin@$DOMAIN"
zimbraVersionCheckNotificationEmailFrom="admin@$DOMAIN"
zimbraVersionCheckSendNotifications="TRUE"
zimbraWebProxy="TRUE"
zimbra_ldap_userdn="uid=zimbra,cn=admins,cn=zimbra"
zimbra_require_interprocess_security="1"
INSTALL_PACKAGES="zimbra-core zimbra-ldap zimbra-logger zimbra-mta zimbra-snmp zimbra-store zimbra-apache zimbra-spell zimbra-memcached zimbra-proxy "
EOF

##Install the Zimbra Collaboration ##

echo "Downloading Zimbra Collaboration"

cd /tmp/zcs 
wget -c https://files.zimbra.com/downloads/8.7.11_GA/zcs-8.7.11_GA_1854.RHEL6_64.20170531151956.tgz
tar -zxvf zcs-*

echo "Installing Zimbra Collaboration just the Software"
cd /tmp/zcs/zcs-* && ./install.sh -s < /tmp/zcs/installZimbra-keystrokes

echo "Installing Zimbra Collaboration injecting the configuration"
/opt/zimbra/libexec/zmsetup.pl -c /tmp/zcs/installZimbraScript

su - zimbra -c 'zmcontrol restart'

echo " "
echo "Your Zimbra Mail Server is Ready to Use"
echo " "
echo "Admin Console: https://$CONTAINERIP:7071"
echo " "
echo "Web Client: https://$CONTAINERIP"
echo " "
