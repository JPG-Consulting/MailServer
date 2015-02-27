#!/bin/bash


# ====================================================================
#                           Functions
# ====================================================================
function generate_password() {
	local __passwd=""

	if hash makepasswd 2>/dev/null; then
		__passwd=$( makepasswd --minchars=12 --maxchars=14 )
	else
		__passwd=$( tr -dc A-Za-z0-9 < /dev/urandom | head -c 12 | xargs )
	fi
	
	echo "$__passwd"
}

function package_is_installed() {
	local __var=""
	for __var in "$@"; do
		if ! dpkg -s $__var > /dev/null 2>&1; then
			return 1
		fi
	done
	return 0
}

function prompt_yesno() {
	local __default_yn="";
	if [[ $1 =~ .*\[Y/n\].* ]]; then
		__default_yn="y"
	elif [[ $1 =~ .*\[y/N\].* ]]; then
		__default_yn="n"
	fi

	read -s -r -n 1 -p "$1"
	while true; do
		if [[ $REPLY =~ ^[yY]$ ]]; then
			echo "$REPLY"
			return 0
		elif [[ $REPLY =~ ^[nN]$ ]]; then
			echo "$REPLY"
			return 1
		elif [ -z "$REPLY" ]; then
			if [ "$__default_yn" = "y" ]; then
				echo "$__default_yn"
				return 0
			elif [ "$__default_yn" = "n" ]; then
				echo "$__default_yn"
				return 1
			fi
		fi
		read -s -r -n 1
	done
}

function read_password() {
	local __resultvar=$1
	local __passwd=""
	local __passwd_vrfy=""

	if [ "$#" -ne 1 ]; then
    	echo "Error: read_password: Illegal number of parameters"
		exit 1
	fi

	while true; do
		read -s -p "Enter new password: " __passwd
		echo
		read -s -p "Retype new password: " __passwd_vrfy
		echo
		if [ "$__passwd" = "$__passwd_vrfy" ]; then
			__passwd="$(echo -e "${__passwd}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
			if [ -n "$__passwd" ]; then
 				break
			else
				echo "No password supplied"
			fi
		else
			echo "Sorry, passwords do not match"
		fi
	done
	
	eval $__resultvar="'$__passwd'"
}

set_imapd_conf() {
	local __key=""
	local __value=""

	IFS=':' read -r __key __value <<< "$1"
	__value=$(echo -e "${__value}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

	if ! grep -qi "^$__key: " /etc/imapd.conf; then
		if grep -qi "^#$__key:" /etc/imapd.conf; then
			sed -i "s/^#$__key:.*$/$__key: $__value/" /etc/imapd.conf
		else
			echo "$__key: $__value" >> /etc/imapd.conf
		fi
	else
		sed -i "s/^$__key:.*$/$__key: $__value/" /etc/imapd.conf
	fi
}



# Am I root?
if [ $(id -u) -ne 0 ]; then
	echo "Sorry, this script can only be executed by root"
	exit 1
fi

# Check supported version
if command -v lsb_release >/dev/null 2>&1; then
	if [ "$(lsb_release -is)" == "Debian" ]; then
		DEBIAN_VERSION=$(lsb_release -rs)
	fi
elif [ -f  /etc/debian_version ]; then
	DEBIAN_VERSION=$(cat /etc/debian_version)
elif [[ -r /etc/os-release ]]; then
	. /etc/os-release
	if [[ $ID = debian ]]; then
		DEBIAN_VERSION="$VERSION_ID"
	fi
fi
read -d . DEBIAN_VERSION_MAJOR <<< "$DEBIAN_VERSION"
if [ -z "$DEBIAN_VERSION_MAJOR" ]; then
	echo "Sorry, this installer works only on Debian 7"
	exit 1
elif [ "$DEBIAN_VERSION_MAJOR" != "7" ]; then
	echo "Sorry, this installer works only on Debian 7"
	exit 1
fi

# update sources
echo "Retrieving new list of packages"
if ! apt-get -y -qq update; then
	echo "Error: apt-get update failed"
	exit 1
fi


# Check wget
if ! command -v wget >/dev/null 2>&1; then
	if ! apt-get -y -qq install wget; then
        echo "Error: can't install wget"
        exit 1
    fi
fi

# Check OpenSSH
if ! package_is_installed openssh-server; then
	if prompt_yesno "Do you wish to install OpenSSH [Y/n]? "; then
		echo "Installing OpenSSH"
		if ! apt-get -y -qq install openssh-server; then
			echo "Error: couldn't install openssh-server"
			exit 1
		fi
	fi
fi

if package_is_installed openssh-server; then
	# Ugly nested ifs. Better way?
	if ! package_is_installed denyhosts; then
		if ! package_is_installed fail2ban; then

			if prompt_yesno "Do you wish to install denyhosts [Y/n]? "; then
				if ! apt-get -y -qq install denyhosts; then
					echo "Error: couldn't install denyhosts"
					exit 1
				fi
			else
				if prompt_yesno "Do you wish to install fail2ban [Y/n]? "; then
					if ! apt-get -y -qq install fail2ban; then
						echo "Error: couldn't install fail2ban"
						exit 1
					fi
				fi
			fi
		fi
	fi
fi

# Database
if ! package_is_installed mariadb-server; then
	if ! package_is_installed mysql-server; then
		echo "Installing MySQL server"
		if ! DEBIAN_FRONTEND=noninteractive apt-get -y -qq install mysql-server; then
			echo "Error: couldn't install mysql-server"
			exit 1
		fi
	fi

	if ! package_is_installed mysql-client; then
		if ! apt-get -y -qq install mysql-client; then
			echo "Error: couldn't install mysql-client"
			exit 1
		fi
	fi

fi

if ! package_is_installed libpam-mysql; then
	if ! apt-get -y -qq install libpam-mysql; then
		echo "Error: couldn't install libpam-mysql"
		exit 1
	fi
fi

# SASL
if ! package_is_installed sasl2-bin; then
	if ! apt-get -y -qq install sasl2-bin; then
		echo "Error: couldn't install sasl2-bin"
		exit 1
	fi
fi

if ! package_is_installed libsasl2-modules; then
	if ! apt-get -y -qq install libsasl2-modules; then
		echo "Error: couldn't install libsasl2-modules"
		exit 1
	fi
fi

# Postfix
if ! package_is_installed postfix; then
	echo "Installing postfix MTA"
	if [ -x /etc/init.d/sendmail ]; then
		/etc/init.d/sendmail stop
	fi

	if ! DEBIAN_FRONTEND=noninteractive apt-get -y -qq install postfix; then
		echo "Error: couldn't install postfix"
		exit 1
	fi

	if ! package_is_installed postfix-mysql; then
		if ! apt-get -y -qq install postfix-mysql; then
			echo "Error: couldn't install postfix-mysql"
			exit 1
		fi
	fi
fi

# Cyrus
if ! package_is_installed cyrus-imapd; then
	echo "Installing Cyrus IMAP server"
	if ! DEBIAN_FRONTEND=noninteractive apt-get -y -qq install cyrus-imapd; then
		echo "Error: couldn't install cyrus-imapd"
		exit 1
	fi
fi

if ! package_is_installed cyrus-admin; then
	if ! apt-get -y -qq install cyrus-admin; then
		echo "Error: couldn't install cyrus-admin"
		exit 1
	fi
fi

if ! package_is_installed cyrus-pop3d; then
	if prompt_yesno "Do you wish to install Pop3 support [y/N]? "; then
		if ! apt-get -y -qq install cyrus-pop3d; then
			echo "Error: couldn't install cyrus-pop3d"
			exit 1
		fi
	fi
fi

# PHP 5
if ! package_is_installed php5; then
	echo "Installing PHP5"
	if ! apt-get -y -qq install php5; then
		echo "Error: couldn't install php5"
		exit 1
	fi

fi

apt-get -y -qq install php5-mysql php5-curl php5-gd php5-intl php-pear php5-imagick php5-imap php5-mcrypt php5-memcache php5-ming php5-ps php5-pspell php5-recode php5-snmp php5-sqlite php5-tidy php5-xmlrpc php5-xsl

# Apache
if ! package_is_installed apache2; then
	echo "Installing Apache2 HTTP server"
	if ! DEBIAN_FRONTEND=noninteractive apt-get -y -qq install apache2; then
		echo "Error: couldn't install apache2"
		exit 1
	fi
fi

if ! package_is_installed libapache2-mod-php5 > /dev/null 2>&1; then
	if ! apt-get -y -qq install libapache2-mod-php5; then
		echo "Error: couldn't install libapache2-mod-php5"
		exit 1
	fi
fi

# Roundcube
if prompt_yesno "Do you wish to install webmail support [y/N]? "; then
	if ! package_is_installed roundcube; then
		echo "Installing Roundcube webmail"
		if ! apt-get -y -qq install roundcube; then
			echo "Error: couldn't install roundcube"
			exit 1
		fi
	fi

	if ! package_is_installed roundcube-mysql; then
		if ! apt-get -y -qq install roundcube-mysql; then
			echo "Error: couldn't install roundcube-mysql"
			exit 1
		fi
	fi
fi



# cleanup
apt-get -y -qq autoremove
apt-get -y -qq clean

# ====================================================================
#
# ====================================================================

# --------------------------------------------------------------------
#                              Database
# --------------------------------------------------------------------
DATABASE_USER="cpadmin"
DATABASE_PASSWORD="$( generate_password )"
DATABASE_DBNAME="cpanel"

# Create default tables
mysql -uroot -e "CREATE DATABASE IF NOT EXISTS $DATABASE_DBNAME;"
mysql -uroot -e "USE $DATABASE_DBNAME;CREATE TABLE IF NOT EXISTS accounts (id int(10) unsigned NOT NULL AUTO_INCREMENT, type varchar(32) CHARACTER SET ascii NOT NULL DEFAULT 'plain', password text CHARACTER SET ascii COLLATE ascii_bin, PRIMARY KEY (id)) ENGINE=InnoDB  DEFAULT CHARSET=utf8;"
mysql -uroot -e "USE $DATABASE_DBNAME;CREATE TABLE IF NOT EXISTS clients (id int(10) unsigned NOT NULL AUTO_INCREMENT, name varchar(255) NOT NULL, PRIMARY KEY (id)) ENGINE=InnoDB  DEFAULT CHARSET=utf8;"
mysql -uroot -e "USE $DATABASE_DBNAME;CREATE TABLE IF NOT EXISTS domains (id int(10) unsigned NOT NULL AUTO_INCREMENT, name varchar(255) CHARACTER SET ascii DEFAULT NULL, client_id int(10) unsigned NOT NULL, PRIMARY KEY (id), KEY client_id (client_id), UNIQUE KEY name (name)) ENGINE=InnoDB  DEFAULT CHARSET=utf8;"
mysql -uroot -e "USE $DATABASE_DBNAME;CREATE TABLE IF NOT EXISTS mail (id int(10) unsigned NOT NULL AUTO_INCREMENT, mail_name varchar(245) CHARACTER SET ascii NOT NULL DEFAULT '', quota int(10) NOT NULL default '0', account_id int(10) unsigned NOT NULL, domain_id int(10) unsigned NOT NULL, PRIMARY KEY (id), UNIQUE KEY dom_id (domain_id,mail_name), KEY account_id (account_id)) ENGINE=InnoDB  DEFAULT CHARSET=utf8;"
mysql -uroot -e "USE $DATABASE_DBNAME;CREATE TABLE IF NOT EXISTS mail_aliases (id int(10) unsigned NOT NULL AUTO_INCREMENT, mail_id int(10) unsigned NOT NULL, alias varchar(245) character set ascii NOT NULL, PRIMARY KEY  (id), UNIQUE KEY mail_id (mail_id,alias)) ENGINE=InnoDB DEFAULT CHARSET=utf8;"

mysql -uroot -e "USE $DATABASE_DBNAME;CREATE VIEW pam_mail_users AS SELECT CONCAT_WS('@', mail.mail_name, domains.name) AS email, accounts.password AS password FROM accounts, domains, mail WHERE domains.id = mail.domain_id AND mail.account_id = accounts.id;"

mysql -uroot -e "USE $DATABASE_DBNAME;ALTER TABLE domains ADD CONSTRAINT domains_ibfk_1 FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE ON UPDATE CASCADE;"
mysql -uroot -e "USE $DATABASE_DBNAME;ALTER TABLE mail ADD CONSTRAINT mail_ibfk_2 FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE ON UPDATE CASCADE, ADD CONSTRAINT mail_ibfk_1 FOREIGN KEY (account_id) REFERENCES $DATABASE_DBNAME.accounts (id) ON DELETE CASCADE ON UPDATE CASCADE;"
mysql -uroot -e "USE $DATABASE_DBNAME;ALTER TABLE mail_aliases ADD CONSTRAINT mail_aliases_ibfk_1 FOREIGN KEY (mail_id) REFERENCES mail (id) ON DELETE CASCADE ON UPDATE CASCADE;"

mysql -uroot -e "CREATE USER '$DATABASE_USER'@'localhost' IDENTIFIED BY '$DATABASE_PASSWORD';"
mysql -uroot -e "GRANT SELECT, INSERT, UPDATE, DELETE ON $DATABASE_DBNAME.* TO '$DATABASE_USER'@'localhost';"
mysql -uroot -e "FLUSH PRIVILEGES;"

# Initial client
VIRTUAL_COMPANY_NAME="My Company"
VIRTUAL_DOMAIN_NAME="$( hostname -f )"

mysql -uroot -e "INSERT INTO $DATABASE_DBNAME.clients (name) VALUES ('$VIRTUAL_COMPANY_NAME');"
mysql -uroot -e "INSERT INTO $DATABASE_DBNAME.domains (name, client_id) VALUES ('$VIRTUAL_DOMAIN_NAME', 1);"

if prompt_yesno "Create an email account [Y/n]? "; then
	VIRTUAL_EMAIL_USER="info"
	VIRTUAL_EMAIL_PASSWORD=""

	read -p "Email username [$VIRTUAL_EMAIL_USER]: " input_var
	if [ -n "$input_var" ]; then
		VIRTUAL_EMAIL_USER="$input_var"
	fi

	read_password VIRTUAL_EMAIL_PASSWORD

	mysql -uroot -e "INSERT INTO $DATABASE_DBNAME.accounts (type, password) VALUES ('crypt', '$( mkpasswd $VIRTUAL_EMAIL_PASSWD )');"
	mysql -uroot -e "INSERT INTO $DATABASE_DBNAME.mail (mail_name, account_id, domain_id) VALUES ('$VIRTUAL_EMAIL_USER', 1, 1);"
fi

# --------------------------------------------------------------------
#                                SASL
# --------------------------------------------------------------------
if package_is_installed sasl2-bin; then
	# Add -r options to merge user and realm
	sed -i 's|^OPTIONS="-c -m /var/run/saslauthd"$|OPTIONS="-r -c -m /var/run/saslauthd"|' /etc/default/saslauthd

	# restart service
	/etc/init.d/saslauthd restart
fi

# --------------------------------------------------------------------
#                            Postfix MTA
# --------------------------------------------------------------------

if package_is_installed postfix; then
	# On Debian we need to add 'postfix' user to the 'mail' group
	adduser postfix mail
	adduser postfix sasl

	# Postfix database data
	if [ ! -d /etc/postfix/mysql ]; then
		mkdir /etc/postfix/mysql
	fi

	# Some generic config
	postconf -e "myhostname = $( hostname -f )"
	postconf -e "mydestination = localhost"
	postconf -e "relay_domains ="
	postconf -e "relayhost ="
	postconf -e "inet_interfaces = all"

	postconf -e "virtual_mailbox_base = /var/mail/vhosts"

	# Domains
	if [ ! -f /etc/postfix/mysql/domains.cf ]; then
		touch /etc/postfix/mysql/domains.cf
	fi

	echo "hosts = 127.0.0.1" > /etc/postfix/mysql/domains.cf
	echo "user = $DATABASE_USER" >> /etc/postfix/mysql/domains.cf
	echo "password = $DATABASE_PASSWORD" >> /etc/postfix/mysql/domains.cf
	echo "dbname = $DATABASE_DBNAME" >> /etc/postfix/mysql/domains.cf
	echo "query = SELECT name AS virtual FROM domains WHERE name='%s'" >> /etc/postfix/mysql/domains.cf
	
	postconf -e "virtual_mailbox_domains = mysql:/etc/postfix/mysql/domains.cf"

	# Virtual mailboxes
	if [ ! -f /etc/postfix/mysql/mailbox_maps.cf ]; then
		touch /etc/postfix/mysql/mailbox_maps.cf
	fi

	echo "hosts = 127.0.0.1" > /etc/postfix/mysql/mailbox_maps.cf
	echo "user = $DATABASE_USER" >> /etc/postfix/mysql/mailbox_maps.cf
	echo "password = $DATABASE_PASSWORD" >> /etc/postfix/mysql/mailbox_maps.cf
	echo "dbname = $DATABASE_DBNAME" >> /etc/postfix/mysql/mailbox_maps.cf
	echo "query = SELECT CONCAT(domains.name, '/', mail.mail_name, '/') FROM domains, mail WHERE mail.domain_id = domains.id AND mail.mail_name='%u' AND domains.name='%d'" >> /etc/postfix/mysql/mailbox_maps.cf
	
	postconf -e "virtual_mailbox_maps = mysql:/etc/postfix/mysql/mailbox_maps.cf"

	# Alias maps
	if [ ! -f /etc/postfix/mysql/alias_maps.cf ]; then
		touch /etc/postfix/mysql/alias_maps.cf
	fi

	echo "hosts = 127.0.0.1" > /etc/postfix/mysql/alias_maps.cf
	echo "user = $DATABASE_USER" >> /etc/postfix/mysql/alias_maps.cf
	echo "password = $DATABASE_PASSWORD" >> /etc/postfix/mysql/alias_maps.cf
	echo "dbname = $DATABASE_DBNAME" >> /etc/postfix/mysql/alias_maps.cf
	echo "query = SELECT CONCAT_WS('@', mail.mail_name, domains.name) AS destination FROM mail_aliases, mail, domains WHERE mail_aliases.mail_id=mail.id AND mail.domain_id=domains.id AND mail_aliases.alias='%u' AND domains.name='%d'" >> /etc/postfix/mysql/alias_maps.cf
	

	postconf -e "virtual_alias_maps = mysql:/etc/postfix/mysql/alias_maps.cf"

	## Quotas
	#if [ ! -f /etc/postfix/mysql/mailbox_limit_maps.cf ]; then
	#	touch /etc/postfix/mysql/mailbox_limit_maps.cf
	#fi
	#
	#echo "hosts = 127.0.0.1" > /etc/postfix/mysql/mailbox_limit_maps.cf
	#echo "user = $DATABASE_USER" >> /etc/postfix/mysql/mailbox_limit_maps.cf
	#echo "password = $DATABASE_PASSWORD" >> /etc/postfix/mysql/mailbox_limit_maps.cf
	#echo "dbname = $DATABASE_DBNAME" >> /etc/postfix/mysql/mailbox_limit_maps.cf
	#echo "query = SELECT mail.quota FROM domains, mail WHERE mail.domain_id = domains.id AND mail.mail_name='%u' AND domains.name='%d'" >> /etc/postfix/mysql/mailbox_limit_maps.cf
	#
	#postconf -e "virtual_create_maildirsize = yes"
	#postconf -e "virtual_mailbox_extended = yes"
	#postconf -e "virtual_mailbox_limit_maps = mysql:/etc/postfix/mailbox_limit_maps.cf"
	#postconf -e "virtual_mailbox_limit_override = yes"
	#postconf -e "virtual_maildir_limit_message = Sorry, the your maildir has overdrawn your diskspace quota, please free up some of spaces of your mailbox try again."
	#postconf -e "virtual_overquota_bounce = yes"

	# Secure the files
	chown -R root:postfix /etc/postfix/mysql
	chmod 750 /etc/postfix/mysql
	chmod 640 /etc/postfix/mysql/*.cf

	# Create a vmail user
	groupadd -g 5000 vmail
	useradd -g vmail -u 5000 -s /usr/sbin/nologin vmail

	postconf -e "virtual_minimum_uid = 5000"
	postconf -e "virtual_uid_maps = static:5000"
	postconf -e "virtual_gid_maps = static:5000"

	# SASL
	postconf -e "smtpd_sasl_path = smtpd"
	postconf -e "smtpd_sasl_auth_enable = yes"
	postconf -e "broken_sasl_auth_clients = yes"
	postconf -e "smtpd_sasl_security_options = noanonymous"
	# Next line is commeted asit is not supported prior to 2.10
	#postconf -e "smtpd_relay_restrictions = permit_sasl_authenticated reject_unauth_destination"
	# Previous versions
	postconf -e "smtpd_recipient_restrictions = permit_sasl_authenticated reject_unauth_destination"
	
	
	# PAM settings for smtpd
	if package_is_installed libpam-mysql; then
		if [ ! -f /etc/pam.d/smtp ]; then
			touch /etc/pam.d/smtp
		fi
		echo "auth    sufficient                      pam_mysql.so user=$DATABASE_USER passwd=$DATABASE_PASSWORD host=127.0.0.1 db=$DATABASE_DBNAME table=pam_mail_users usercolumn=email passwdcolumn=password crypt=1" > /etc/pam.d/smtp
		echo "auth    [success=1 default=ignore]      pam_unix.so nullok_secure" >> /etc/pam.d/smtp
		echo "auth    requisite                       pam_deny.so" >> /etc/pam.d/smtp
		echo "auth    required                        pam_permit.so" >> /etc/pam.d/smtp
		echo "account sufficient pam_mysql.so user=$DATABASE_USER passwd=$DATABASE_PASSWORD host=localhost db=$DATABASE_DBNAME table=pam_mail_users usercolumn=email passwdcolumn=password crypt=1" >> /etc/pam.d/smtp
		echo "account [success=1 new_authtok_reqd=done default=ignore]        pam_unix.so" >> /etc/pam.d/smtp
		echo "account requisite                       pam_deny.so" >> /etc/pam.d/smtp
		echo "account required                        pam_permit.so" >> /etc/pam.d/smtp
	fi

	# Debian postfix runs in chroot so we need some extra tunning
	if package_is_installed sasl2-bin; then
		if [ -d /var/spool/postfix ] && [ -d /var/run/saslauthd ]; then
			if ! grep -qE "^/var/run/saslauthd\s+/var/spool/postfix/var/run/saslauthd" /etc/fstab; then
				echo "/var/run/saslauthd /var/spool/postfix/var/run/saslauthd bind defaults,nodev,noauto,bind 0 0" >> /etc/fstab
			fi

			if [ ! -d /var/spool/postfix/var ]; then
				mkdir /var/spool/postfix/var
				dpkg-statoverride --add root root 777 /var/spool/postfix/var
			fi

			if [ ! -d /var/spool/postfix/var/run/saslauthd ]; then
				mkdir -p /var/spool/postfix/var/run/saslauthd
				chown -R root:sasl /var/spool/postfix/var/run/saslauthd
				chmod 710 /var/spool/postfix/var/run/saslauthd
				dpkg-statoverride --add root sasl 710 /var/spool/postfix/var/run/saslauthd
			fi

			mount /var/spool/postfix/var/run/saslauthd

			if ! grep -qE "^mount\s+/var/spool/postfix/var/run/saslauthd$" /etc/rc.local; then
				sed -i '$i \# Mount saslauthd bind point at postfix chroot\nmount /var/spool/postfix/var/run/saslauthd\n' /etc/rc.local
			fi
		fi

		if [ ! -f /usr/lib/sasl2/smtpd.conf ]; then
			touch  /usr/lib/sasl2/smtpd.conf
		fi
		echo "pwcheck_method: saslauthd" >  /usr/lib/sasl2/smtpd.conf
		echo "mech_list: LOGIN PLAIN" >>  /usr/lib/sasl2/smtpd.conf
		echo "allowanonymouslogin: 0" >>  /usr/lib/sasl2/smtpd.conf

	fi

	if package_is_installed cyrus-imapd; then
		# Create a LMTP socket inside the chroot environment
		if ! grep -qE "^\s*lmtppostfix\s+" /etc/cyrus.conf; then
			sed -i '/^[[:blank:]]lmtpunix[[:blank:]]/a\        lmtppostfix     cmd="lmtpd" listen="/var/spool/postfix/private/lmtp.cyrus" prefork=0 maxchild=20' /etc/cyrus.conf
		fi
		postconf -e "virtual_transport = lmtp:unix:/private/lmtp.cyrus"
	fi


	# restart the service
	/etc/init.d/postfix restart
fi

# --------------------------------------------------------------------
#                               Cyrus
# --------------------------------------------------------------------
if package_is_installed cyrus-imapd; then
	set_imapd_conf "altnamespace: yes"
	set_imapd_conf "unixhierarchysep: yes"
	set_imapd_conf "admins: cyrus"
	set_imapd_conf "virtdomains: userid"
	set_imapd_conf "sasl_pwcheck_method: saslauthd"
	set_imapd_conf "sasl_mech_list: PLAIN LOGIN"

	# Fix Complains about certain missing directories
	if [ ! -e /var/run/cyrus/lock ]; then
		mkdir /var/run/cyrus/lock
		chown cyrus:mail /var/run/cyrus/lock
		chmod 700 /var/run/cyrus/lock
	fi

	if [ ! -e /var/run/cyrus/proc ]; then
		mkdir /var/run/cyrus/proc
		chown cyrus:mail /var/run/cyrus/proc
		chmod 700 /var/run/cyrus/proc
	fi

	# PAM settings for imap
	if package_is_installed libpam-mysql; then
		if [ ! -f /etc/pam.d/imap ]; then
			touch /etc/pam.d/imap
		fi
		echo "auth    sufficient                      pam_mysql.so user=$DATABASE_USER passwd=$DATABASE_PASSWORD host=127.0.0.1 db=$DATABASE_DBNAME table=pam_mail_users usercolumn=email passwdcolumn=password crypt=1" > /etc/pam.d/imap
		echo "auth    [success=1 default=ignore]      pam_unix.so nullok_secure" >> /etc/pam.d/imap
		echo "auth    requisite                       pam_deny.so" >> /etc/pam.d/imap
		echo "auth    required                        pam_permit.so" >> /etc/pam.d/imap
		echo "account sufficient pam_mysql.so user=$DATABASE_USER passwd=$DATABASE_PASSWORD host=localhost db=$DATABASE_DBNAME table=pam_mail_users usercolumn=email passwdcolumn=password crypt=1" >> /etc/pam.d/imap
		echo "account [success=1 new_authtok_reqd=done default=ignore]        pam_unix.so" >> /etc/pam.d/imap
		echo "account requisite                       pam_deny.so" >> /etc/pam.d/imap
		echo "account required                        pam_permit.so" >> /etc/pam.d/imap
	fi

	# restart the service
	/etc/init.d/cyrus-imapd restart

	# If we created a mail user it is time to add it
	if [ -n "$VIRTUAL_EMAIL_USER" ] && [ -n "$VIRTUAL_DOMAIN_NAME" ]; then
		CYRUS_PASSWORD="$( generate_password )"
		echo "cyrus:$CYRUS_PASSWORD" | chpasswd
		echo "$CYRUS_PASSWORD" | saslpasswd2 -p -c cyrus
		
		cyradm -u cyrus -w "$CYRUS_PASSWORD"  127.0.0.1 <<< "cm user/$VIRTUAL_EMAIL_USER@$VIRTUAL_DOMAIN_NAME"
	fi
fi

if package_is_installed cyrus-pop3d; then
	# PAM settings for pop3 
	if package_is_installed libpam-mysql; then
		if [ ! -f /etc/pam.d/pop ]; then
			touch /etc/pam.d/pop
		fi
		echo "auth    sufficient                      pam_mysql.so user=$DATABASE_USER passwd=$DATABASE_PASSWORD host=127.0.0.1 db=$DATABASE_DBNAME table=pam_mail_users usercolumn=email passwdcolumn=password crypt=1" > /etc/pam.d/pop
		echo "auth    [success=1 default=ignore]      pam_unix.so nullok_secure" >> /etc/pam.d/pop
		echo "auth    requisite                       pam_deny.so" >> /etc/pam.d/pop
		echo "auth    required                        pam_permit.so" >> /etc/pam.d/pop
		echo "account sufficient pam_mysql.so user=$DATABASE_USER passwd=$DATABASE_PASSWORD host=localhost db=$DATABASE_DBNAME table=pam_mail_users usercolumn=email passwdcolumn=password crypt=1" >> /etc/pam.d/pop
		echo "account [success=1 new_authtok_reqd=done default=ignore]        pam_unix.so" >> /etc/pam.d/pop
		echo "account requisite                       pam_deny.so" >> /etc/pam.d/pop
		echo "account required                        pam_permit.so" >> /etc/pam.d/pop
	fi

	# restart the service
	/etc/init.d/cyrus-imapd restart
fi
