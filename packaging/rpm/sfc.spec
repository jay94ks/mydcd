# SPDX-License-Identifier: Apache-2.0
# sfcli, sfcd and sfc-web-image from binaries build.sh already made
# (rpm/build.sh passes them in). rpmbuild compiles nothing.
%bcond_with web
%global debug_package %{nil}
%global __strip /bin/true
%global _build_id_links none

Name:           sfcli
Version:        %{sfc_version}
Release:        1
Summary:        Seafield Cluster command line interface
License:        Apache-2.0
URL:            https://github.com/jay94ks/seafield
ExclusiveArch:  %{sfc_arch}

%description
sfcli manages a Seafield Cluster: servers, apps, volumes, networks and
users. It talks to sfcd over the management socket or a remote context, and
runs on a cluster server or on an administrator's own Linux machine.

%package -n sfcd
Summary:        Seafield Cluster node daemon and Seafield Engine
Requires:       sfcli = %{version}-%{release}

%description -n sfcd
sfcd runs on every server of a Seafield Cluster. It keeps the cluster state
with Raft, talks to other servers over SFCP and runs containers through
Seafield Engine (sfed), which ships in this package with its own containerd
and runc under /usr/lib/sfc/bin. It does not use or need Docker.

The package installs the sfcd and sfed systemd units but neither enables
nor starts them; write /etc/sfc/node.yaml, run sfcd init or join, then
systemctl enable --now sfed sfcd.

%if %{with web}
%package -n sfc-web-image
Summary:        Seafield Cluster web UI cluster app image
Requires:       sfcd = %{version}-%{release}
BuildArch:      noarch

%description -n sfc-web-image
The signed sfc-web cluster app image bundle under /usr/lib/sfc/images. sfcd
runs it as the cluster's web UI when node.yaml enables cluster_apps.web.
%endif

%prep

%build

%install
cd %{sfc_src}
%{sfc_src}/packaging/layout.sh sfcli /usr %{buildroot} %{sfc_build}
%{sfc_src}/packaging/layout.sh sfcd /usr %{buildroot} %{sfc_build}
%if %{with web}
%{sfc_src}/packaging/layout.sh sfc-web-image /usr %{buildroot} %{sfc_build} %{sfc_web}
%endif

%files
%license /usr/share/doc/sfcli/LICENSE
%doc /usr/share/doc/sfcli/NOTICE
/usr/bin/sfcli
/usr/share/man/man1/sfcli.1*
%dir /usr/share/sfc
/usr/share/sfc/SKILL.md

%files -n sfcd
%license /usr/share/doc/sfcd/LICENSE
%doc /usr/share/doc/sfcd/NOTICE
%doc /usr/share/doc/sfcd/THIRD_PARTY_NOTICES
%doc /usr/share/doc/sfcd/examples
/usr/bin/sfcd
/usr/share/man/man8/sfcd.8*
%dir /usr/lib/sfc
/usr/lib/sfc/bin
/usr/lib/systemd/system/sfcd.service
/usr/lib/systemd/system/sfed.service

%if %{with web}
%files -n sfc-web-image
%license /usr/share/doc/sfc-web-image/LICENSE
%doc /usr/share/doc/sfc-web-image/NOTICE
%doc /usr/share/doc/sfc-web-image/THIRD_PARTY_NOTICES
%dir /usr/lib/sfc/images
/usr/lib/sfc/images/sfc-web
%endif

# Scriptlets never enable or start a unit on first install and never touch
# another package (devel/design/install-packages.md 3, 5). $1 is the number
# of sfcd packages left after the step: 1 on install, 2 during an upgrade,
# 0 on erase.
%post -n sfcd
if [ -d /run/systemd/system ]; then systemctl daemon-reload || :; fi
if [ "$1" -eq 1 ]; then
cat <<'MSG'
sfcd is installed but not enabled. Next steps:
  1. write /etc/sfc/node.yaml (examples in /usr/share/doc/sfcd/examples)
  2. sfcd --config /etc/sfc/node.yaml check
  3. sfcd --config /etc/sfc/node.yaml init ...   (or join ...)
  4. systemctl enable --now sfed sfcd
MSG
fi

%preun -n sfcd
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
	echo "sfcd: stopping sfcd and sfed; this server's containers stop with sfed." >&2
	systemctl stop sfcd.service sfed.service || :
	systemctl disable sfcd.service sfed.service >/dev/null 2>&1 || :
fi

%postun -n sfcd
if [ -d /run/systemd/system ]; then
	systemctl daemon-reload || :
	# Upgrade: restart only what runs (P-c), with the new binaries.
	if [ "$1" -ge 1 ]; then systemctl try-restart sfed.service sfcd.service || :; fi
fi
if [ "$1" -eq 0 ]; then
cat <<'MSG' >&2
sfcd: kept /etc/sfc, /var/lib/sfc, /etc/sfe and /var/lib/sfe (cluster state,
identity and engine data). To delete them for good:
  rm -rf /etc/sfc /var/lib/sfc /etc/sfe /var/lib/sfe
MSG
fi

%changelog
* %{sfc_date} Jay <33371449+jay94ks@users.noreply.github.com> - %{version}-1
- Release %{version}. See https://github.com/jay94ks/seafield/releases
