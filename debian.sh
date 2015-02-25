#!/bin/bash

# SSH
SSH_USER="administrator"

# Mail Vars
MAIL_DOMAIN=$( hostname )
MAIL_USER="info"
MAIL_PASSWD=""

# MySQLVars
DATABASE_PACKAGE="mysql"
DATABASE_USER="cpanel"
DATABASE_PASSWORD="1234"
DATABASE_DBNAME="cpanel"

# PAM
PAM_MYSQL_CRYPTO=0

CYRUS_PASSWORD="1234"

# ====================================================================
#                            Functions
# ====================================================================

function package_install() {
	local __packages=""

	if [ "$#" -lt 1 ]; then
    	echo "Error: package_install: Illegal number of parameters"
		exit 1
	fi

	for i in ${@}; do
		if ! package_is_installed $i; then
			if [ -z "$__packages" ]; then
				__packages="$i"
			else
				__packages="$__packages $i"
			fi
		fi
	done

	if [ -n "$__packages" ]; then
		if ! apt-get -y -qq install "$__packages"; then
			# retry failed packages one at a time
			for i in $__packages; do
				if ! package_is_installed $i; then
					if ! apt-get -y -qq install "$i"; then
						echo "Error installing $i"
						exit 1
					fi
				fi
			done
		fi
	fi
}

function package_is_installed() {
	local __resultvar=0;

	if [ "$#" -lt 1 ]; then
    	echo "Error: package_is_installed: Illegal number of parameters"
		exit 1
	fi

	for i in ${@}; do
		if ! dpkg -l $i > /dev/null 2>&1; then
			__resultvar=1
			break
		fi
	done
	return $__resultvar
}

function package_remove() {
	local __packages=""

	if [ "$#" -lt 1 ]; then
    	echo "Error: package_remove: Illegal number of parameters"
		exit 1
	fi

	for i in ${@}; do
		if package_is_installed $i; then
			if [ -z "$__packages" ]; then
				__packages="$i"
			else
				__packages="$__packages $i"
			fi
		fi
	done

	if [ -n "$__packages" ]; then
		if ! apt-get -y -qq --purge remove "$__packages"; then
			# retry failed packages one at a time
			for i in $__packages; do
				if package_is_installed $i; then
					if ! apt-get -y -qq --purge remove "$i"; then
						echo "Error removing $i"
						exit 1
					fi
				fi
			done
		fi
	fi
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

function system_service() {
	if [ "$#" -lt 2 ]; then
    	echo "Error: system_service: Illegal number of parameters"
		exit 1
	fi

	for i in ${@:2}; do
		/etc/init.d/$i $1
	done
}

# ====================================================================
#                        User Interaction
# ====================================================================

# --------------------------------------------------------------------
#                           SSH settings
# --------------------------------------------------------------------
read -p "New user: [$SSH_USER] " input_var
if [ -n "$input_var" ]; then
	SSH_USER="$input_var";
fi

read_password passwd
id -u "$SSH_USER" &>/dev/null || useradd --create-home --shell=/bin/bash "$SSH_USER" 
echo "$SSH_USER:$passwd" | chpasswd
usermod -a -G sudo "$SSH_USER"

# --------------------------------------------------------------------
#                          e-mail settings
# --------------------------------------------------------------------
read -p "Default domain for emails: [$MAIL_DOMAIN] " input_var
if [ -n "$input_var" ]; then
	MAIL_DOMAIN="$input_var";
fi

read -p "Email username: [$MAIL_USER] " input_var
if [ -n "$input_var" ]; then
	MAIL_USER="$input_var";
fi

read_password MAIL_PASSWD

# ====================================================================
#                       Start automation
# ====================================================================
echo "Updating package list."
apt-get -y -qq update
#apt-get -y -qq upgrade

# --------------------------------------------------------------------
#                          Firewall
# --------------------------------------------------------------------

echo "Setting up initial firewall rules"
iptables -F

# Block null packets
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
# Reject syn-flood attacks
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
# XMAS Pckets
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
# Prevent Denial-Of-Service Attack
iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT

# We tell iptables to add (-A) a rule to the incoming (INPUT) filter
# table any trafic that comes to localhost interface (-i lo) and to
# accept (-j ACCEPT) it. Localhost is often used for, ie. your website
# or email server communicating with a database locally installed.
# That way our VPS can use the database, but the database is closed
# to exploits from the internet.
iptables -A INPUT -i lo -j ACCEPT
# Allow us to use outgoing connections (ie. ping from VPS or run 
# software updates);
iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# Allow ALL Incoming SSH
iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -m state --state ESTABLISHED,RELATED -j ACCEPT
# Default rules
iptables -P OUTPUT ACCEPT
iptables -P INPUT DROP

# --------------------------------------------------------------------
#                         SSH Settings
# --------------------------------------------------------------------
echo "Configuring SSHd"

if [ ! -f /etc/issue.net ]; then
	touch /etc/issue.net
fi
echo "" > /etc/issue.net
echo "This service is restricted to authorized users only. All activities on this system are logged." >> /etc/issue.net
echo "Unauthorized access will be fully investigated and reported to the appropriate law enforcement agencies." >> /etc/issue.net
echo "" >> /etc/issue.net
# Enable banner
sed -i "s/^#Banner /Banner /g" /etc/ssh/sshd_config
#  Disable Root Login (PermitRootLogin)
sed -i 's/^#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

#  Allow Only Specific Users or Groups (AllowUsers AllowGroups)
if ! grep -q -i '^AllowUsers ' /etc/ssh/sshd_config; then
	echo "# AllowUsers controls which users are allowed to log on via ssh" >>  /etc/ssh/sshd_config
	echo "# Include only accounts that need remote log on privileges!" >> /etc/ssh/sshd_config
	echo "AllowUsers $SSH_USER" >> /etc/ssh/sshd_config
fi
if ! grep -q -i '^AllowGroups ' /etc/ssh/sshd_config; then
	echo "# AllowGroups controls which groups are allowed to log on via ssh" >>  /etc/ssh/sshd_config
	echo "# Include only groups that need remote log on privileges!" >> /etc/ssh/sshd_config
	echo "AllowGroups sudo" >> /etc/ssh/sshd_config
fi

# Secure SSHd using DenyHosts
package_install denyhosts

# --------------------------------------------------------------------
#                       Database setup
# --------------------------------------------------------------------
case "$DATABASE_PACKAGE" in
	mysql)
		echo "Installing MySQL"
		package_install mysql-server mysql-client
		package_install libpam-mysql

		mysql -uroot -e "CREATE DATABASE IF NOT EXISTS $DATABASE_DBNAME;"
		mysql -uroot -e "USE $DATABASE_DBNAME;CREATE TABLE IF NOT EXISTS accounts (id int(10) unsigned NOT NULL AUTO_INCREMENT, type varchar(32) CHARACTER SET ascii NOT NULL DEFAULT 'plain', password text CHARACTER SET ascii COLLATE ascii_bin, PRIMARY KEY (id)) ENGINE=InnoDB  DEFAULT CHARSET=utf8;"
		mysql -uroot -e "USE $DATABASE_DBNAME;CREATE TABLE IF NOT EXISTS clients (id int(10) unsigned NOT NULL AUTO_INCREMENT, name varchar(255) NOT NULL, PRIMARY KEY (id)) ENGINE=InnoDB  DEFAULT CHARSET=utf8;"
		mysql -uroot -e "USE $DATABASE_DBNAME;CREATE TABLE IF NOT EXISTS domains (id int(10) unsigned NOT NULL AUTO_INCREMENT, name varchar(255) CHARACTER SET ascii DEFAULT NULL, client_id int(10) unsigned NOT NULL, PRIMARY KEY (id), KEY client_id (client_id), UNIQUE KEY name (name)) ENGINE=InnoDB  DEFAULT CHARSET=utf8;"
		mysql -uroot -e "USE $DATABASE_DBNAME;CREATE TABLE IF NOT EXISTS mail (id int(10) unsigned NOT NULL AUTO_INCREMENT, mail_name varchar(245) CHARACTER SET ascii NOT NULL DEFAULT '', account_id int(10) unsigned NOT NULL, domain_id int(10) unsigned NOT NULL, PRIMARY KEY (id), UNIQUE KEY dom_id (domain_id,mail_name), KEY account_id (account_id)) ENGINE=InnoDB  DEFAULT CHARSET=utf8;"
		mysql -uroot -e "USE $DATABASE_DBNAME;CREATE TABLE IF NOT EXISTS mail_aliases (id int(10) unsigned NOT NULL AUTO_INCREMENT, mail_id int(10) unsigned NOT NULL, alias varchar(245) character set ascii NOT NULL, PRIMARY KEY  (id), UNIQUE KEY mail_id (mail_id,alias)) ENGINE=InnoDB DEFAULT CHARSET=utf8;"

		mysql -uroot -e "USE $DATABASE_DBNAME;CREATE VIEW pam_mail_users AS SELECT CONCAT_WS('@', mail.mail_name, domains.name) AS email, accounts.password AS password FROM accounts, domains, mail WHERE domains.id = mail.domain_id AND mail.account_id = accounts.id;"

		mysql -uroot -e "USE $DATABASE_DBNAME;ALTER TABLE domains ADD CONSTRAINT domains_ibfk_1 FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE ON UPDATE CASCADE;"
		mysql -uroot -e "USE $DATABASE_DBNAME;ALTER TABLE mail ADD CONSTRAINT mail_ibfk_2 FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE ON UPDATE CASCADE, ADD CONSTRAINT mail_ibfk_1 FOREIGN KEY (account_id) REFERENCES $DATABASE_DBNAME.accounts (id) ON DELETE CASCADE ON UPDATE CASCADE;"
		mysql -uroot -e "USE $DATABASE_DBNAME;ALTER TABLE mail_aliases ADD CONSTRAINT mail_aliases_ibfk_1 FOREIGN KEY (mail_id) REFERENCES mail (id) ON DELETE CASCADE ON UPDATE CASCADE;"

		mysql -uroot -e "CREATE USER '$DATABASE_USER'@'localhost' IDENTIFIED BY '$DATABASE_PASSWORD';"
		mysql -uroot -e "GRANT SELECT, INSERT, UPDATE, DELETE ON $DATABASE_DBNAME.* TO '$DATABASE_USER'@'localhost';"
		mysql -uroot -e "FLUSH PRIVILEGES;"

		# Insert data
		case "$PAM_CRYPTO" in
			0)	
				mysql -uroot -e "INSERT INTO $DATABASE_DBNAME.accounts (type, password) VALUES ('plain', '$MAIL_PASSWD');"
				;;
			1)
				mysql -uroot -e "INSERT INTO $DATABASE_DBNAME.accounts (type, password) VALUES ('crypt', '$( mkpasswd $MAIL_PASSWD )');"
				;;
			*)
				PAM_CRYPTO=0
				mysql -uroot -e "INSERT INTO $DATABASE_DBNAME.accounts (type, password) VALUES ('plain', '$MAIL_PASSWD');"
				;;		
		esac
		mysql -uroot -e "INSERT INTO $DATABASE_DBNAME.clients (name) VALUES ('$MAIL_DOMAIN');"
		mysql -uroot -e "INSERT INTO $DATABASE_DBNAME.domains (name, client_id) VALUES ('$MAIL_DOMAIN', 1);"
		mysql -uroot -e "INSERT INTO $DATABASE_DBNAME.mail (mail_name, account_id, domain_id) VALUES ('$MAIL_USER', 1, 1);"

		# NOTE: PAM Modules get overriden by the setup script so we'll take care of them later on
		
		# Add -r options to merge user and realm
		sed -i 's|^OPTIONS="-c -m /var/run/saslauthd"$|OPTIONS="-r -c -m /var/run/saslauthd"|' /etc/default/saslauthd

		;;
	*)
		echo "The selected database is not compatibale with this setup script."
		exit 1
esac

# --------------------------------------------------------------------
#                       IMAP setup
# --------------------------------------------------------------------

echo "Installing Cyrus IMAPd"
package_install libsasl2-2 libsasl2-modules sasl2-bin
package_install cyrus-imapd cyrus-admin cyrus-common cyrus-clients
# Fix
sed -i 's/^proc_path: /#proc_path: /' /etc/imapd.conf
sed -i 's/^mboxname_lockpath: /#mboxname_lockpath: /' /etc/imapd.conf
# Normal config
sed -i 's/^#admins: /admins: /' /etc/imapd.conf
sed -i 's/^#imap_admins: /imap_admins: /' /etc/imapd.conf
sed -i 's/unixhierarchysep: no/unixhierarchysep: yes/' /etc/imapd.conf
sed -i 's/#virtdomains: /virtdomains: /' /etc/imapd.conf
#sed -i 's/^#defaultdomain:/defaultdomain: $MAIL_DOMAIN/' /etc/imapd.conf
sed -i 's/^#sasl_mech_list: PLAIN$/sasl_mech_list: PLAIN LOGIN/' /etc/imapd.conf
sed -i 's/^sasl_pwcheck_method: auxprop/sasl_pwcheck_method: saslauthd/' /etc/imapd.conf
sed -i 's/^altnamespace: no$/altnamespace: yes/' /etc/imapd.conf

if [ -S /var/run/cyrus/socket/lmtp ]; then
	dpkg-statoverride --force --update --add cyrus mail 750 /var/run/cyrus/socket
	chown cyrus:mail /var/run/cyrus/socket
	chown cyrus:mail /var/run/cyrus/socket/lmtp
fi

system_service stop cyrus-imapd
system_service start cyrus-imapd
system_service restart saslauthd

echo "cyrus:$CYRUS_PASSWORD" | chpasswd
echo "$CYRUS_PASSWORD" | saslpasswd2 -p -c cyrus

#echo $( cyradm -u cyrus@$MAIL_DOMAIN -w "$CYRUS_PASSWORD"  127.0.0.1 << EOF
#cm user/$MAIL_USER@$MAIL_DOMAIN
#setaclmailbox user/$MAIL_USER@MAIL_DOMAIN $MAIL_USER@MAIL_DOMAIN lrswipcd
#EOF
#) >> /dev/null 2>&1


# Allow IMAP traffic
iptables -A INPUT -p tcp --dport 143 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 143 -m state --state ESTABLISHED -j ACCEPT

# --------------------------------------------------------------------
#                      Postfix MTA setup
# --------------------------------------------------------------------
echo "Installing Postfix MTA."
# Suggests: postfix-mysql postfix-ldap postfix-pcre libsasl2-modules dovecot-common resolvconf postfix-cdb ufw postfix-doc
package_install postfix postfix-mysql postfix-pcre

# Remove the default sendmail
system_service stop sendmail
package_remove sendmail 
package_remove sendmail-cf sendmail-doc
package_remove sendmail-base
system_service restart postfix

case "$DATABASE_PACKAGE" in
	mysql)
		if [ ! -d /etc/postfix/mysql ]; then
			mkdir -p /etc/postfix/mysql
		fi

		if [ ! -f /etc/postfix/mysql/domains.cf ]; then
			touch /etc/postfix/mysql/domains.cf
		fi

		echo "hosts = 127.0.0.1" > /etc/postfix/mysql/domains.cf
		echo "user = $DATABASE_USER" >> /etc/postfix/mysql/domains.cf
		echo "password = $DATABASE_PASSWORD" >> /etc/postfix/mysql/domains.cf
		echo "dbname = $DATABASE_DBNAME" >> /etc/postfix/mysql/domains.cf
		echo "query = SELECT name AS virtual FROM domains WHERE name='%s'" >> /etc/postfix/mysql/domains.cf

		if [ ! -f /etc/postfix/mysql/mailbox_maps.cf ]; then
			touch /etc/postfix/mysql/mailbox_maps.cf
		fi

		echo "hosts = 127.0.0.1" > /etc/postfix/mysql/mailbox_maps.cf
		echo "user = $DATABASE_USER" >> /etc/postfix/mysql/mailbox_maps.cf
		echo "password = $DATABASE_PASSWORD" >> /etc/postfix/mysql/mailbox_maps.cf
		echo "dbname = $DATABASE_DBNAME" >> /etc/postfix/mysql/mailbox_maps.cf
		echo "query = SELECT CONCAT(domains.name, '/', mail.mail_name, '/') FROM domains, mail WHERE mail.domain_id = domains.id AND mail.mail_name='%u' AND domains.name='%d'" >> /etc/postfix/mysql/mailbox_maps.cf

		if [ ! -f /etc/postfix/mysql/alias_maps.cf ]; then
			touch /etc/postfix/mysql/alias_maps.cf
		fi

		echo "hosts = 127.0.0.1" > /etc/postfix/mysql/alias_maps.cf
		echo "user = $DATABASE_USER" >> /etc/postfix/mysql/alias_maps.cf
		echo "password = $DATABASE_PASSWORD" >> /etc/postfix/mysql/alias_maps.cf
		echo "dbname = $DATABASE_DBNAME" >> /etc/postfix/mysql/alias_maps.cf
		echo "query = SELECT CONCAT_WS('@', mail.mail_name, domains.name) AS destination FROM mail_aliases, mail, domains WHERE mail_aliases.mail_id=mail.id AND mail.domain_id=domains.id AND mail_aliases.alias='%u' AND domains.name='%d'" >> /etc/postfix/mysql/alias_maps.cf


		postconf -e "mydestination = localhost"
		postconf -e "relay_domains ="
		postconf -e "relayhost ="
		postconf -e "virtual_mailbox_domains = mysql:/etc/postfix/mysql/domains.cf"
		postconf -e "virtual_mailbox_maps = mysql:/etc/postfix/mysql/mailbox_maps.cf"
		postconf -e "virtual_mailbox_maps = mysql:/etc/postfix/mysql/mailbox_maps.cf"
		postconf -e "virtual_alias_maps = mysql:/etc/postfix/mysql/alias_maps.cf"
		postconf -e "virtual_mailbox_base = /var/mail/vhosts"
		postconf -e "virtual_transport = lmtp:unix:/var/run/cyrus/socket/lmtp"
		# SASL
		postconf -e "smtpd_sasl_path = smtpd"
		postconf -e "smtpd_sasl_auth_enable = yes"
		postconf -e "broken_sasl_auth_clients = yes"
		postconf -e "smtpd_sasl_security_options = noanonymous"
		# Next line is commeted asit is not supported prior to 2.10
		postconf -e "#smtpd_relay_restrictions = permit_sasl_authenticated reject_unauth_destination"
		# Previous versions
		postconf -e "smtpd_recipient_restrictions = permit_sasl_authenticated reject_unauth_destination"

		if [ ! -f /etc/postfix/sasl/smtpd.conf ]; then
			touch /etc/postfix/sasl/smtpd.conf
		fi
		echo "pwcheck_method: saslauthd" > /etc/postfix/sasl/smtpd.conf
		echo "mech_list: PLAIN LOGIN" >> /etc/postfix/sasl/smtpd.conf



		sed -i 's/^smtp      inet  n       -       -       -       -       smtpd$/smtp      inet  n       -       n       -       -       smtpd/g' /etc/postfix/master.cf
		sed -i 's/^lmtp .* lmtp$/lmtp      unix  -       -       n       -       -       lmtp/g' /etc/postfix/master.cf
		;;
	*)
		echo "The selected database is not compatibale with this setup script."
		exit 1
esac

# On Debian we need to add 'postfix' user to the 'mail' group
adduser postfix mail
adduser postfix sasl

#cat << EOF > /usr/lib/sasl2/smtpd.conf
#pwcheck_method: auxprop
#auxprop_plugin: sql
#sql_engine: mysql
#mech_list: PLAIN LOGIN
#sql_hostnames: 127.0.0.1
#sql_user: $DATABASE_USER
#sql_passwd: $DATABASE_PASSWORD
#sql_database: $DATABASE_DBNAME
#sql_select: SELECT accounts.password FROM accounts, mail, domain WHERE mail.domain_id=domains.id AND mail.account_id=accounts.id AND mail.mail_name='%u' AND domains.name='%r'
#EOF
cat << EOF > /usr/lib/sasl2/smtpd.conf
pwcheck_method: saslauthd
mech_list: PLAIN LOGIN
EOF

chmod a-rwx /usr/lib/sasl2/smtpd.conf
chown root:mail /usr/lib/sasl2/smtpd.conf
chmod ug+rw /usr/lib/sasl2/smtpd.conf

cp /usr/lib/sasl2/smtpd.conf /usr/lib/sasl2/imap.conf


# Allow Postfix Traffic
iptables -A INPUT -p tcp --dport 25 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 25 -m state --state ESTABLISHED -j ACCEPT

# --------------------------------------------------------------------
#                          HTTP setup
# --------------------------------------------------------------------

echo "Installing Apache"
package_install apache2

# Allow Incoming HTTP and HTTPS
iptables -A INPUT -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT

# --------------------------------------------------------------------
#                          PHP setup
# --------------------------------------------------------------------

echo "Installing PHP"
package_install php5 php-pear php5-mysql

# --------------------------------------------------------------------
#                           PAM Modules
# --------------------------------------------------------------------
case "$DATABASE_PACKAGE" in
	mysql)
		if [ ! -f /etc/pam.d/smtp ]; then
			touch /etc/pam.d/smtp
		fi
		echo "auth    sufficient                      pam_mysql.so user=$DATABASE_USER passwd=$DATABASE_PASSWORD host=127.0.0.1 db=$DATABASE_DBNAME table=pam_mail_users usercolumn=email passwdcolumn=password crypt=$PAM_CRYPTO" > /etc/pam.d/smtp
		echo "auth    [success=1 default=ignore]      pam_unix.so nullok_secure" >> /etc/pam.d/smtp
		echo "auth    requisite                       pam_deny.so" >> /etc/pam.d/smtp
		echo "auth    required                        pam_permit.so" >> /etc/pam.d/smtp
		echo "account sufficient pam_mysql.so user=$DATABASE_USER passwd=$DATABASE_PASSWORD host=localhost db=$DATABASE_DBNAME table=pam_mail_users usercolumn=email passwdcolumn=password crypt=$PAM_CRYPTO" >> /etc/pam.d/smtp
		echo "account [success=1 new_authtok_reqd=done default=ignore]        pam_unix.so" >> /etc/pam.d/smtp
		echo "account requisite                       pam_deny.so" >> /etc/pam.d/smtp
		echo "account required                        pam_permit.so" >> /etc/pam.d/smtp

		if [ ! -f /etc/pam.d/imap ]; then
			touch /etc/pam.d/imap
		fi
		echo "auth    sufficient                      pam_mysql.so user=$DATABASE_USER passwd=$DATABASE_PASSWORD host=127.0.0.1 db=$DATABASE_DBNAME table=pam_mail_users usercolumn=email passwdcolumn=password crypt=$PAM_CRYPTO" > /etc/pam.d/imap
		echo "auth    [success=1 default=ignore]      pam_unix.so nullok_secure" >> /etc/pam.d/imap
		echo "auth    requisite                       pam_deny.so" >> /etc/pam.d/imap
		echo "auth    required                        pam_permit.so" >> /etc/pam.d/imap
		echo "account sufficient pam_mysql.so user=$DATABASE_USER passwd=$DATABASE_PASSWORD host=localhost db=$DATABASE_DBNAME table=pam_mail_users usercolumn=email passwdcolumn=password crypt=$PAM_CRYPTO" >> /etc/pam.d/imap
		echo "account [success=1 new_authtok_reqd=done default=ignore]        pam_unix.so" >> /etc/pam.d/imap
		echo "account requisite                       pam_deny.so" >> /etc/pam.d/imap
		echo "account required                        pam_permit.so" >> /etc/pam.d/imap

		# Add -r options to merge user and realm
		sed -i 's|^OPTIONS="-c -m /var/run/saslauthd"$|OPTIONS="-r -c -m /var/run/saslauthd"|' /etc/default/saslauthd

		;;
	*)
		echo "The selected database is not compatibale with this setup script."
		exit 1
esac

# --------------------------------------------------------------------
#                          Final setup
# --------------------------------------------------------------------
echo "Saving firewall rules"
package_install iptables-persistent
if [ ! -f /etc/iptables/rules.v4 ]; then
	touch /etc/iptables/rules.v4
fi
iptables-save > /etc/iptables/rules.v4

if [ ! -f /etc/iptables/rules.v6 ]; then
	touch /etc/iptables/rules.v6
fi
ip6tables-save > /etc/iptables/rules.v6

# --------------------------------------------------------------------
#                         Restart services
# --------------------------------------------------------------------
system_service stop postfix cyrus-imapd apache2 saslauthd mysql denyhosts
system_service restart ssh
system_service start denyhosts mysql saslauthd apache2 cyrus-imapd postfix

echo $( cyradm -u cyrus -w $CYRUS_PASSWORD  127.0.0.1 << EOF
cm user/$MAIL_USER@$MAIL_DOMAIN
EOF
) >> /dev/null 2>&1


echo 
echo "Your system is ready for use!"
echo "Please remember you won't be able to login as 'root' use '$SSH_USER' to login via SSH."
echo
