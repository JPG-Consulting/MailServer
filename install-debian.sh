#!/bin/bash

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
if ! dpkg -l openssh-server > /dev/null 2>&1; then
	if prompt_yesno "Do you wish to install OpenSSH [Y/n]? "; then
		echo "Installing OpenSSH"
		if ! apt-get -y -qq install openssh-server; then
			echo "Error: couldn't install openssh-server"
			exit 1
		fi
	fi
fi

if dpkg -l openssh-server > /dev/null 2>&1; then
	# Ugly nested ifs. Better way?
	if ! dpkg -l denyhosts > /dev/null 2>&1; then
		if ! dpkg -l fail2ban > /dev/null 2>&1; then

			if prompt_yesno "Do you wish to install denyhosts [Y/n]? "; then
				if ! dpkg -l denyhosts > /dev/null 2>&1; then
					if ! apt-get -y -qq install denyhosts; then
						echo "Error: couldn't install denyhosts"
						exit 1
					fi
				fi
			else
				if prompt_yesno "Do you wish to install fail2ban [Y/n]? "; then
					if ! dpkg -l fail2ban > /dev/null 2>&1; then
						if ! apt-get -y -qq install fail2ban; then
							echo "Error: couldn't install fail2ban"
							exit 1
						fi
					fi
				fi
			fi
		fi
	fi
fi

# Database
if ! dpkg -l mariadb-server > /dev/null 2>&1; then
	if ! dpkg -l mysql-server > /dev/null 2>&1; then
		echo "Installing MySQL server"
		if ! DEBIAN_FRONTEND=noninteractive apt-get -y -qq install mysql-server; then
			echo "Error: couldn't install mysql-server"
			exit 1
		fi
	fi

	if ! dpkg -l mysql-client > /dev/null 2>&1; then
		if ! apt-get -y -qq install mysql-client; then
			echo "Error: couldn't install mysql-client"
			exit 1
		fi
	fi

fi

if ! dpkg -l libpam-mysql > /dev/null 2>&1; then
	if ! apt-get -y -qq install libpam-mysql; then
		echo "Error: couldn't install libpam-mysql"
		exit 1
	fi
fi

# SASL
if ! dpkg -l sasl2-bin > /dev/null 2>&1; then
	if ! apt-get -y -qq install sasl2-bin; then
		echo "Error: couldn't install sasl2-bin"
		exit 1
	fi
fi

if ! dpkg -l libsasl2-modules > /dev/null 2>&1; then
	if ! apt-get -y -qq install libsasl2-modules; then
		echo "Error: couldn't install libsasl2-modules"
		exit 1
	fi
fi

# Postfix
if ! dpkg -l postfix > /dev/null 2>&1; then
	echo "Installing postfix MTA"
	if ! DEBIAN_FRONTEND=noninteractive apt-get -y -qq install postfix; then
		echo "Error: couldn't install postfix"
		exit 1
	fi

	if ! dpkg -l postfix-mysql > /dev/null 2>&1; then
		if ! apt-get -y -qq install postfix-mysql; then
			echo "Error: couldn't install postfix-mysql"
			exit 1
		fi
	fi
fi

# Cyrus
if ! dpkg -l cyrus-imapd > /dev/null 2>&1; then
	echo "Installing Cyrus IMAP server"
	if ! DEBIAN_FRONTEND=noninteractive apt-get -y -qq install cyrus-imapd; then
		echo "Error: couldn't install cyrus-imapd"
		exit 1
	fi
fi

if ! dpkg -l cyrus-admin > /dev/null 2>&1; then
	if ! apt-get -y -qq install cyrus-admin; then
		echo "Error: couldn't install cyrus-admin"
		exit 1
	fi
fi

if ! dpkg -l cyrus-pop3d > /dev/null 2>&1; then
	if prompt_yesno "Do you wish to install Pop3 support [y/N]? "; then
		if ! apt-get -y -qq install cyrus-pop3d; then
			echo "Error: couldn't install cyrus-pop3d"
			exit 1
		fi
	fi
fi

# PHP 5
if ! dpkg -l apache2 > /dev/null 2>&1; then
	echo "Installing PHP5"
	if ! apt-get -y -qq install php5; then
		echo "Error: couldn't install php5"
		exit 1
	fi

fi

apt-get -y -qq install php5-mysql php5-curl php5-gd php5-intl php-pear php5-imagick php5-imap php5-mcrypt php5-memcache php5-ming php5-ps php5-pspell php5-recode php5-snmp php5-sqlite php5-tidy php5-xmlrpc php5-xsl

# Apache
if ! dpkg -l apache2 > /dev/null 2>&1; then
	echo "Installing Apache2 HTTP server"
	if ! DEBIAN_FRONTEND=noninteractive apt-get -y -qq install apache2; then
		echo "Error: couldn't install apache2"
		exit 1
	fi
fi

if ! dpkg -l libapache2-mod-php5 > /dev/null 2>&1; then
	if ! apt-get -y -qq install php5 libapache2-mod-php5; then
		echo "Error: couldn't install libapache2-mod-php5"
		exit 1
	fi
fi

# Roundcube
if prompt_yesno "Do you wish to install webmail support [y/N]? "; then
	if ! dpkg -l roundcube > /dev/null 2>&1; then
		echo "Installing Roundcube webmail"
		if ! apt-get -y -qq install roundcube; then
			echo "Error: couldn't install roundcube"
			exit 1
		fi
	fi

	if ! dpkg -l roundcube-mysql > /dev/null 2>&1; then
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


