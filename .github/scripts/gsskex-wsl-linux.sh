#!/bin/sh
set -eu

ACTION=${1:-setup}
REALM=EXAMPLE.COM
USER_NAME=user
USER_PASSWORD=${USER_PASSWORD:-GssproxyUser!2026}
COMPUTER_PASSWORD=${COMPUTER_PASSWORD:-GssproxyHost!2026}
KDC_HOST=kdc1.example.com
LINUX_HOST=linux.example.com
WINDOWS_HOST=win.example.com
WORK=/tmp/openssh-gsskex-interop
LOGDIR=$WORK/logs
SRC=$WORK/src
LINUX_PORT=2222
WINDOWS_PORT=2223

quote_sed()
{
	printf '%s\n' "$1" | sed 's/[.[\*^$()+?{}|]/\\&/g'
}

add_host()
{
	ip=$1
	shift
	names="$*"
	pattern=$(quote_sed "$names")
	if ! grep -Eq "[[:space:]]$pattern([[:space:]]|\$)" /etc/hosts; then
		printf '%s %s\n' "$ip" "$names" >> /etc/hosts
	fi
}

write_krb5_conf()
{
	kdc_addr=$1

	cat > /etc/krb5.conf <<EOF
[libdefaults]
	default_realm = $REALM
	dns_lookup_kdc = false
	dns_lookup_realm = false
	udp_preference_limit = 1
	forwardable = true
	default_cc_name = FILE:/tmp/krb5cc_%{uid}

[realms]
	$REALM = {
		kdc = $kdc_addr
		admin_server = $kdc_addr
	}

[domain_realm]
	.example.com = $REALM
	example.com = $REALM
EOF
}

init_heimdal()
{
	wsl_ip=$1
	win_ip=$2
	win_computer=$3

	echo "Setting up Debian Heimdal KDC"
	mkdir -p "$WORK" "$LOGDIR" /etc/heimdal-kdc /var/lib/heimdal-kdc
	add_host "$wsl_ip" "$KDC_HOST $LINUX_HOST"
	add_host "$win_ip" "$WINDOWS_HOST"
	write_krb5_conf "$KDC_HOST"
	cat > /etc/heimdal-kdc/kdc.conf <<EOF
[logging]
	kdc = FILE:$LOGDIR/heimdal-kdc.log
	kadmin = FILE:$LOGDIR/heimdal-kadmin.log

[kdc]
	database = {
		dbname = /var/lib/heimdal-kdc/heimdal
		realm = $REALM
		acl_file = /etc/heimdal-kdc/kadmind.acl
	}
EOF
	printf '*/admin@%s all\n' "$REALM" > /etc/heimdal-kdc/kadmind.acl

	pkill -f '/usr/lib/heimdal-servers/kdc' >/dev/null 2>&1 || true
	rm -f /var/lib/heimdal-kdc/heimdal*
	kadmin -l init \
		--realm-max-ticket-life=1day \
		--realm-max-renewable-life=1week "$REALM"
	kadmin -l add --use-defaults --password="$USER_PASSWORD" "$USER_NAME"
	kadmin -l add --use-defaults --random-key "host/$LINUX_HOST"
	kadmin -l add --use-defaults --password="$COMPUTER_PASSWORD" \
		"host/$WINDOWS_HOST"
	if [ -n "$win_computer" ]; then
		kadmin -l add --use-defaults --password="$COMPUTER_PASSWORD" \
			"host/$win_computer" || true
	fi
	kadmin -l ext_keytab --keytab="$WORK/linux.keytab" "host/$LINUX_HOST"

	/usr/lib/heimdal-servers/kdc --addresses=0.0.0.0 --ports=88 \
		>"$LOGDIR/kdc.stdout.log" 2>"$LOGDIR/kdc.stderr.log" &
	echo $! > "$WORK/kdc.pid"
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		if printf '%s\n' "$USER_PASSWORD" |
		    kinit "$USER_NAME@$REALM" >/dev/null 2>&1; then
			kdestroy >/dev/null 2>&1 || true
			return
		fi
		sleep 1
	done
	cat "$LOGDIR"/kdc.*.log "$LOGDIR"/heimdal-*.log 2>/dev/null || true
	echo "Heimdal KDC did not become ready" >&2
	exit 1
}

build_linux_openssh()
{
	repo=$1

	echo "Copying source tree into WSL"
	rm -rf "$SRC"
	mkdir -p "$SRC"
	rsync -a --delete \
		--exclude .git \
		--exclude autom4te.cache \
		--exclude /bin \
		--exclude /contrib/win32/openssh/lib \
		--exclude /contrib/win32/openssh/vcpkg_installed \
		--exclude /contrib/win32/openssh/x64 \
		--exclude gsskex-interop-logs \
		"$repo"/ "$SRC"/
	cd "$SRC"
	echo "Running autoreconf for Debian OpenSSH build"
	autoreconf
	echo "Configuring Debian OpenSSH build with Heimdal"
	./configure --with-kerberos5=/usr --with-libedit \
		>"$LOGDIR/configure-linux.log" 2>&1
	echo "Building Debian OpenSSH"
	make -j"$(nproc)" \
		>"$LOGDIR/make-linux.log" 2>&1
	./ssh -V 2>"$LOGDIR/linux-ssh-version.log" || true
}

start_linux_sshd()
{
	echo "Starting Debian sshd test peer"
	mkdir -p "$WORK/linux-etc" "$WORK/empty"
	mkdir -p /var/empty
	chown root:root /var/empty
	chmod 755 /var/empty
	if ! id sshd >/dev/null 2>&1; then
		useradd -r -d /var/empty -s /usr/sbin/nologin sshd
	fi
	if ! id "$USER_NAME" >/dev/null 2>&1; then
		useradd -m -s /bin/sh "$USER_NAME"
	fi
	printf '%s@%s\n' "$USER_NAME" "$REALM" > "/home/$USER_NAME/.k5login"
	chown "$USER_NAME:$USER_NAME" "/home/$USER_NAME/.k5login"
	chmod 600 "/home/$USER_NAME/.k5login"

	"$SRC/ssh-keygen" -q -t ed25519 -N '' \
		-f "$WORK/linux-ssh-host-ed25519" >/dev/null
	cat > "$WORK/linux-sshd_config" <<EOF
Port $LINUX_PORT
ListenAddress 0.0.0.0
PidFile $WORK/linux-sshd.pid
HostKey $WORK/linux-ssh-host-ed25519
LogLevel DEBUG3
GSSAPIAuthentication yes
GSSAPIKeyExchange yes
GSSAPIKexAlgorithms gss-curve25519-sha256-
GSSAPIStrictAcceptorCheck no
PubkeyAuthentication no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
UsePAM no
AllowUsers $USER_NAME
StrictModes no
Subsystem sftp $SRC/sftp-server
EOF
	pkill -f "$SRC/sshd.*$WORK/linux-sshd_config" >/dev/null 2>&1 || true
	env KRB5_KTNAME="$WORK/linux.keytab" \
		"$SRC/sshd" -f "$WORK/linux-sshd_config" \
		-E "$LOGDIR/linux-sshd.log"
}

create_linux_to_windows_key()
{
	rm -f "$WORK/linux-to-windows-ed25519" "$WORK/linux-to-windows-ed25519.pub"
	"$SRC/ssh-keygen" -q -t ed25519 -N '' \
		-f "$WORK/linux-to-windows-ed25519" >/dev/null
}

assert_gss_kex()
{
	name=$1
	log=$2
	if ! grep -q 'kex: algorithm: gss-curve25519-sha256-' "$log"; then
		cat "$log" >&2
		echo "$name did not use gss-curve25519-sha256-" >&2
		exit 1
	fi
}

linux_to_windows()
{
	echo "Running Debian client to Windows sshd GSS KEX test"
	printf '%s\n' "$USER_PASSWORD" | kinit "$USER_NAME@$REALM" >/dev/null
	known=$WORK/linux-known-hosts.empty
	global_known=$WORK/linux-global-known-hosts.empty
	empty_config=$WORK/linux-empty-config
	: > "$known"
	: > "$global_known"
	: > "$empty_config"
	log=$LOGDIR/linux-to-windows-ssh.log
	"$SRC/ssh" -vvv \
		-F "$empty_config" \
		-o BatchMode=yes \
		-o StrictHostKeyChecking=yes \
		-o UserKnownHostsFile="$known" \
		-o GlobalKnownHostsFile="$global_known" \
		-o GSSAPIAuthentication=yes \
		-o GSSAPIKeyExchange=yes \
		-o GSSAPIKexAlgorithms=gss-curve25519-sha256- \
		-o GSSAPIServerIdentity="$WINDOWS_HOST" \
		-o PreferredAuthentications=publickey \
		-o PubkeyAuthentication=yes \
		-o IdentityFile="$WORK/linux-to-windows-ed25519" \
		-o IdentitiesOnly=yes \
		-o PasswordAuthentication=no \
		-o KbdInteractiveAuthentication=no \
		-o NumberOfPasswordPrompts=0 \
		-o ConnectTimeout=30 \
		-o ConnectionAttempts=1 \
		-p "$WINDOWS_PORT" "$USER_NAME@$WINDOWS_HOST" \
		cmd.exe /c echo linux-to-windows-gsskex-ok \
		>"$LOGDIR/linux-to-windows.out" 2>"$log"
	assert_gss_kex linux-to-windows "$log"
	grep -q 'linux-to-windows-gsskex-ok' "$LOGDIR/linux-to-windows.out"
	test ! -s "$known"
	test ! -s "$global_known"
	kdestroy >/dev/null 2>&1 || true
}

case "$ACTION" in
	setup)
		if [ $# -ne 5 ]; then
			echo "usage: $0 setup REPO WSL_IP WIN_IP WIN_COMPUTER" >&2
			exit 2
		fi
		init_heimdal "$3" "$4" "$5"
		build_linux_openssh "$2"
		start_linux_sshd
		create_linux_to_windows_key
		;;
	linux-to-windows)
		linux_to_windows
		;;
	cleanup)
		if [ -f "$WORK/linux-sshd.pid" ]; then
			kill "$(cat "$WORK/linux-sshd.pid")" >/dev/null 2>&1 || true
		fi
		if [ -f "$WORK/kdc.pid" ]; then
			kill "$(cat "$WORK/kdc.pid")" >/dev/null 2>&1 || true
		fi
		;;
	*)
		echo "unknown action: $ACTION" >&2
		exit 2
		;;
esac
