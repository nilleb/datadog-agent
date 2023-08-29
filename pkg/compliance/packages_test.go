// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package compliance

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

const dpkgStatus = `Package: adduser
Status: install ok installed
Priority: important
Section: admin
Installed-Size: 608
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Version: 3.118ubuntu5
Depends: passwd, debconf (>= 0.5) | debconf-2.0
Suggests: liblocale-gettext-perl, perl, ecryptfs-utils (>= 67-1)
Conffiles:
 /etc/deluser.conf 773fb95e98a27947de4a95abb3d3f2a2
Description: add and remove users and groups
 This package includes the 'adduser' and 'deluser' commands for creating
 and removing users.
 .
  - 'adduser' creates new users and groups and adds existing users to
    existing groups;
  - 'deluser' removes users and groups and removes users from a given
    group.
 .
 Adding users with 'adduser' is much easier than adding them manually.
 Adduser will choose appropriate UID and GID values, create a home
 directory, copy skeletal user configuration, and automate setting
 initial values for the user's password, real name and so on.
 .
 Deluser can back up and remove users' home directories
 and mail spool or all the files they own on the system.
 .
 A custom script can be executed after each of the commands.
Original-Maintainer: Debian Adduser Developers <adduser@packages.debian.org>

Package: apparmor
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 2628
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: arm64
Version: 3.0.4-2ubuntu2.2
Replaces: fcitx-data (<< 1:4.2.9.1-1ubuntu2)
Depends: debconf, lsb-base, debconf (>= 0.5) | debconf-2.0, libc6 (>= 2.34)
Suggests: apparmor-profiles-extra, apparmor-utils
Breaks: apparmor-profiles-extra (<< 1.21), fcitx-data (<< 1:4.2.9.1-1ubuntu2), snapd (<< 2.44.3+20.04~)
Conffiles:
 /etc/apparmor.d/abi/3.0 f97e410509c5def279aa227c7de12e06
 /etc/apparmor.d/abi/kernel-5.4-outoftree-network 57b68acd4e6418fe5a06dc8c04713e3d
 /etc/apparmor.d/abi/kernel-5.4-vanilla 77047e6f0b014fa8bf27681998382044
Description: user-space parser utility for AppArmor
 apparmor provides the system initialization scripts needed to use the
 AppArmor Mandatory Access Control system, including the AppArmor Parser
 which is required to convert AppArmor text profiles into machine-readable
 policies that are loaded into the kernel for use with the AppArmor Linux
 Security Module.
Homepage: https://apparmor.net/
Original-Maintainer: Debian AppArmor Team <pkg-apparmor-team@lists.alioth.debian.org>

Package: apt
Status: install ok installed
Priority: important
Section: admin
Installed-Size: 3956
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: arm64
Version: 2.4.9
Replaces: apt-transport-https (<< 1.5~alpha4~), apt-utils (<< 1.3~exp2~)
Provides: apt-transport-https (= 2.4.9)
Depends: adduser, gpgv | gpgv2 | gpgv1, libapt-pkg6.0 (>= 2.4.9), ubuntu-keyring, libc6 (>= 2.34), libgcc-s1 (>= 3.3.1), libgnutls30 (>= 3.7.0), libseccomp2 (>= 2.4.2), libstdc++6 (>= 11), libsystemd0
Recommends: ca-certificates
Suggests: apt-doc, aptitude | synaptic | wajig, dpkg-dev (>= 1.17.2), gnupg | gnupg2 | gnupg1, powermgmt-base
Breaks: apt-transport-https (<< 1.5~alpha4~), apt-utils (<< 1.3~exp2~), aptitude (<< 0.8.10)
Conffiles:
 /etc/apt/apt.conf.d/01-vendor-ubuntu c69ce53f5f0755e5ac4441702e820505
 /etc/apt/apt.conf.d/01autoremove ab6540f7278a05a4b7f9e58afcaa5f46
 /etc/cron.daily/apt-compat 1400ab07a4a2905b04c33e3e93d42b7b
 /etc/logrotate.d/apt 179f2ed4f85cbaca12fa3d69c2a4a1c3
Description: commandline package manager
 This package provides commandline tools for searching and
 managing as well as querying information about packages
 as a low-level access to all features of the libapt-pkg library.

Package: apt-transport-https
Status: install ok installed
Priority: optional
Section: oldlibs
Installed-Size: 165
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: all
Multi-Arch: foreign
Source: apt
Version: 2.4.9
Depends: apt (>= 1.5~alpha4)
Description: transitional package for https support
 This is a dummy transitional package - https support has been moved into
 the apt package in 1.5. It can be safely removed.
Original-Maintainer: APT Development Team <deity@lists.debian.org>
`

func TestDpkgResolving(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status")
	if err := os.WriteFile(path, []byte(dpkgStatus), 0600); err != nil {
		t.Fatal(err)
	}

	{
		pkg := findDpkgPackage(path, []string{"adduser"})
		assert.NotNil(t, pkg)
		assert.Equal(t, "adduser", pkg.Name)
		assert.NotNil(t, "3.118ubuntu5", pkg.Version)
		assert.NotNil(t, "arch", pkg.Arch)
	}

	{
		pkg := findDpkgPackage(path, []string{"foo"})
		assert.Nil(t, pkg)
	}
}
