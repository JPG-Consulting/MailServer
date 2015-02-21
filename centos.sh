#!/bin/bash

if [ "$USER" != "root" ]; then
        echo "Must be root to execute script..."
        exit 1
fi

# ===========================================
#        Get system information
# ===========================================
CENTOS_VERSION_MAJOR=$( rpm -qa \*-release | grep -Ei "oracle|redhat|centos" | cut -d"-" -f3 )
CENTOS_MACHINE=$( uname -m )

VIRTUAL_DOMAINS=false

MAIL_USER="info"
MAIL_PASSWD=""
MAIL_DOMAIN=$( hostname )

while true; do
	read -p "Do you wish to enable virtual domains (y/n)?" choice
	case "$choice" in 
		y|Y ) 
			VIRTUAL_DOMAINS=true
			read -s -p "Default domain for emails: [$MAIL_DOMAIN] " input_var
			if [ ! -z "$input_var" ]; then
				MAIL_DOMAIN="$input_var"
			fi

			break
			;;
		n|N )
			VIRTUAL_DOMAINS=false
			read -s -p "Domain for emails: [$MAIL_DOMAIN] " input_var
			if [ ! -z "$input_var" ]; then
				MAIL_DOMAIN="$input_var"
			fi

			break
			;;
		* ) 
			echo "Invalid option";;
	esac
done

read -s -p "Email user: [$MAIL_USER] " input_var
if [ ! -z "$input_var" ]; then
	MAIL_USER="$input_var"
fi

while true; do
	read -p "Password: " passwd
	read -p "Again (for verification): " vrfy_passwd

	if [ "$passwd" == "$vrfy_passwd" ]; then
		MAIL_PASSWD="$passwd"
		break;
	fi
done


# -------------------------------------------
#             Install Postfix
# -------------------------------------------
if ! rpm -qa | grep -qw postfix; then
	yum -y -q install postfix

	# Default mail service is sendmail
	if [ "$CENTOS_VERSION_MAJOR" -eq "7" ]; then
		systemctl stop sendmail
		systemctl disable sendmail
		alternatives --set mta /usr/sbin/sendmail.postfix
		yum -y -q sendmail
		systemctl enable postfix
		systemctl start postfix
	else
		service sendmail stop
		chkconfig sendmail off
		alternatives --set mta /usr/sbin/sendmail.postfix
		yum -y -q sendmail
		chkconfig postfix on
		service postfix start
	fi
fi

# -------------------------------------------
#           Install Cyrus IMAP
# -------------------------------------------
if ! rpm -qa | grep -qw cyrus-sasl; then
	yum -y -q install cyrus-sasl cyrus-sasl-plain
elif ! rpm -qa | grep -qw cyrus-sasl-plain; then
	yum -y -q install cyrus-sasl-plain
fi

if ! rpm -qa | grep -qw cyrus-imapd; then
	yum -y -q install cyrus-imapd

	if [ "$CENTOS_VERSION_MAJOR" -eq "7" ]; then
		systemctl enable cyrus-imapd 
		systemctl start cyrus-imapd
	else
		chkconfig cyrus-imapd on
		service cyrus-imapd start
	fi
fi

# -------------------------------------------
#          Setup for local users
# -------------------------------------------
if ! "$VIRTUAL_DOMAINS"; then
	echo "myhostname              = $( hostname )" > /etc/postfix/main.cf
	echo "mydomain                = $MAIL_DOMAIN" >> /etc/postfix/main.cf
	echo "myorig                  = \$mydomain" >> /etc/postfix/main.cf
	echo "mydestination           = localhost \$mydomain" >> /etc/postfix/main.cf
	echo "inet_interfaces = all" >> /etc/postfix/main.cf
	echo "mynetworks_style        = host" >> /etc/postfix/main.cf
	echo "mailbox_transport       = lmtp:unix:/var/lib/imap/socket/lmtp" >> /etc/postfix/main.cf
	echo "local_destination_recipient_limit       = 300" >> /etc/postfix/main.cf
	echo "local_destination_concurrency_limit     = 5" >> /etc/postfix/main.cf
	echo "recipient_delimiter=+" >> /etc/postfix/main.cf
	echo "smtpd_banner            = \$myhostname ESMTP" >> /etc/postfix/main.cf
	echo "alias_maps = hash:/etc/postfix/aliases" >> /etc/postfix/main.cf

	touch /etc/postfix/aliases
	echo "# Basic system aliases -- these MUST be present." > /etc/postfix/aliases
	echo "mailer-daemon:  postmaster" >> /etc/postfix/aliases
	echo "postmaster:     root" >> /etc/postfix/aliases

	echo "configdirectory: /var/lib/imap" > /etc/imapd.conf
	echo "partition-default: /var/spool/imap" >> /etc/imapd.conf
	echo "admins: cyrus" >> /etc/imapd.conf
	echo "sievedir: /var/lib/imap/sieve" >> /etc/imapd.conf
	echo "sendmail: /usr/sbin/sendmail.postfix" >> /etc/imapd.conf
	echo "hashimapspool: true" >> /etc/imapd.conf
	echo "sasl_pwcheck_method: saslauthd" >> /etc/imapd.conf
	echo "sasl_mech_list: PLAIN LOGIN" >> /etc/imapd.conf
	echo "allowplaintext: no" >> /etc/imapd.conf
	echo "defaultdomain: $MAIL_DOMAIN" >> /etc/imapd.conf
	echo "tls_cert_file: /etc/pki/cyrus-imapd/cyrus-imapd.pem" >> /etc/imapd.conf
	echo "tls_key_file: /etc/pki/cyrus-imapd/cyrus-imapd.pem" >> /etc/imapd.conf
	echo "tls_ca_file: /etc/pki/tls/certs/ca-bundle.crt" >> /etc/imapd.conf
	echo "# uncomment this if you're operating in a DSCP environment (RFC-4594)" >> /etc/imapd.conf
	echo "# qosmarking: af13" >> /etc/imapd.conf

	echo "pwcheck_method: saslauthd" > /etc/sasl2/smtpd.conf
	echo "mech_list: plain login" >> /etc/sasl2/smtpd.conf
	
	useradd -m -s /usr/sbin/nologin "$MAIL_USER"
	echo -e "$MAIL_PASSWD\n$MAIL_PASSWD" | (passwd --stdin $MAIL_USER)

	if [ "$CENTOS_VERSION_MAJOR" -eq "7" ]; then
		systemctl restart cyrus-imapd
		systemctl restart postfix
		systemctl restart saslauthd
	else
		service cyrus-imapd restart
		service postfix restart
		service saslauthd restart
	fi

	# Nothing more to do
	exit 0
fi
