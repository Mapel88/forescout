Name:           nids-config
Version:        1.0.0
Release:        1%{?dist}
Summary:        Configuration utility for NIDS network setup (IPv4/IPv6).

License:        MIT
URL:            http://example.com
Source0:        nids-config.sh

# A Bash script is architecture independent
BuildArch:      noarch
# Dependencies required for the script to run on the target host
Requires:       bash, procps, coreutils

%description
This package installs the nids-config Bash script, a simple command-line 
utility used to configure essential kernel parameters for a Network Intrusion 
Detection System (NIDS) environment. It handles settings for IPv4 forwarding 
and IPv6 privacy extensions.

%prep
# No preparation required beyond copying the source file, which rpmbuild handles implicitly.

%install
# This section defines where files are placed in the final package structure.

# 1. Create the target directory structure
mkdir -p %{buildroot}/usr/sbin/

# 2. Copy the executable script to the sbin folder
# install -m 755 sets read/write/execute permissions for the owner, and read/execute for others.
install -m 755 %{SOURCE0} %{buildroot}/usr/sbin/nids-config

%files
# This lists all files that belong in the final RPM package.
/usr/sbin/nids-config

%changelog
* Mon Nov 17 2025 Your Name <you@example.com> - 1.0.0-1
- Initial release of the NIDS configuration script.