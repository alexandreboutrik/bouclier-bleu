#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright 2026 The Bouclier Bleu Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Exit immediately on uninitialized variables or pipe failures
set -uo pipefail

# ==========================================
# DEFAULT VARIABLES & OPTIONS
# ==========================================
: "${APP_NAME:="bouclier-bleu"}"
: "${REPO_OWNER:="alexandreboutrik"}"
: "${BB_VERSION:=""}"
: "${BB_HELP:=0}"

# Toggle variables for release steps
: "${BB_BUILD_DEB:=0}"
: "${BB_BUILD_RPM:=0}"
: "${BB_CREATE_GH_RELEASE:=0}"
: "${BB_UPDATE_AUR:=0}"
: "${BB_UPDATE_GENTOO:=0}"

# Paths
: "${MAIN_DIR:="$(pwd)"}"
: "${DIST_DIR:="${MAIN_DIR}/dist"}"
: "${AUR_REPO_PATH:="../bouclier-bleu-aur"}"
: "${GENTOO_REPO_PATH:="../bouclier-bleu-overlay/app-admin/bouclier-bleu"}"

# Internal variables
HOST_UID=$(id -u)
HOST_GID=$(id -g)
TARBALL_URL=""
TARBALL_SHA=""

# ==========================================
# COMMAND LINE ARGUMENT PARSING
# ==========================================
while [ $# -ne 0 ] ; do
    case "${1}" in
    "-help") ;& "-h") ;& "help")
        BB_HELP=1
        ;;
    "-version") ;& "-v")
        BB_VERSION="${2}"
        shift
        ;;
    "-deb")
        BB_BUILD_DEB=1
        ;;
    "-rpm")
        BB_BUILD_RPM=1
        ;;
    "-gh")
        BB_CREATE_GH_RELEASE=1
        ;;
    "-aur")
        BB_UPDATE_AUR=1
        ;;
    "-gentoo")
        BB_UPDATE_GENTOO=1
        ;;
    esac
    shift
done

# ==========================================
# FUNCTIONS
# ==========================================

function print_help() {
    if [ "${BB_HELP}" != "1" ] ; then return ; fi

    echo "USAGE:"
    echo "  ./scripts/release.sh -v [VERSION] [OPTIONS]"
    echo
    echo "OPTIONS:"
    echo "  -help, -h               Display this help message and exit."
    echo "  -version, -v            Specify the release version (e.g., 1.0.4)."
    echo
    echo "  -deb                    Build the Ubuntu/Debian .deb package."
    echo "  -rpm                    Build the Fedora .rpm package."
    echo "  -gh                     Tag and create the GitHub Release."
    echo "  -aur                    Update the Arch AUR repository."
    echo "  -gentoo                 Update the Gentoo overlay."
    echo
    echo "EXAMPLES:"
    echo "  $ ./scripts/release.sh -v 1.0.4"
    echo "  $ ./scripts/release.sh -v 1.0.4 -deb -rpm"
    exit 0
}

function init_env() {
    if [ -z "${BB_VERSION}" ] ; then
        echo "Error: Version not specified. Use -v <version>. Exiting."
		echo
		BB_HELP=1 print_help
        exit 1
    fi

    TARBALL_URL="https://github.com/${REPO_OWNER}/${APP_NAME}/archive/refs/tags/v${BB_VERSION}.tar.gz"

    echo "Starting release process for ${APP_NAME} v${BB_VERSION}..."
    echo "Cleaning previous builds..."
    rm -rf "${DIST_DIR}" ||
		{ echo "Failed to remove old dist directory. Exiting." ; exit 1 ; }
    mkdir -p "${DIST_DIR}" ||
		{ echo "Failed to create dist directory. Exiting." ; exit 1 ; }
}

function build_deb() {
    if [ "${BB_BUILD_DEB}" != "1" ] ; then return ; fi

    echo -e "\n➤ Building .deb package via Ubuntu Docker..."

    docker run --rm -v "${MAIN_DIR}:/app" -e CARGO_TARGET_DIR=/app/target/ubuntu ubuntu:22.04 bash -c "
        set -e
        apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
            curl build-essential clang llvm libelf-dev zlib1g-dev pkg-config ruby ruby-dev rubygems || exit 1
        
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y || exit 1
        source \$HOME/.cargo/env

        cd /app
        cargo build --release || exit 1

        mkdir -p /tmp/stage/usr/bin
        cp target/ubuntu/release/core /tmp/stage/usr/bin/bouclier-bleu-core || exit 1
        cp target/ubuntu/release/cli /tmp/stage/usr/bin/bouclier-bleu-cli || exit 1

        gem install fpm || exit 1
        fpm -s dir -t deb -n ${APP_NAME} -v ${BB_VERSION} -C /tmp/stage . || exit 1
        mv *.deb /app/dist/ || exit 1
        
        chown -R ${HOST_UID}:${HOST_GID} /app/target/ubuntu /app/dist || exit 1
    " || { echo "Failed to build .deb package in Docker. Exiting." ; exit 1 ; }
}

function build_rpm() {
    if [ "${BB_BUILD_RPM}" != "1" ] ; then return ; fi

    echo -e "\n➤ Building .rpm package via Fedora Docker..."

    docker run --rm -v "${MAIN_DIR}:/app" -e CARGO_TARGET_DIR=/app/target/fedora fedora:40 bash -c "
        set -e
        dnf install -y curl make gcc clang llvm elfutils-libelf-devel zlib-devel pkg-config ruby ruby-devel rpm-build || exit 1
        
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y || exit 1
        source \$HOME/.cargo/env

        cd /app
        cargo build --release || exit 1

        mkdir -p /tmp/stage/usr/bin
        cp target/fedora/release/core /tmp/stage/usr/bin/bouclier-bleu-core || exit 1
        cp target/fedora/release/cli /tmp/stage/usr/bin/bouclier-bleu-cli || exit 1

        gem install fpm || exit 1
        fpm -s dir -t rpm -n ${APP_NAME} -v ${BB_VERSION} -C /tmp/stage . || exit 1
        mv *.rpm /app/dist/ || exit 1

        chown -R ${HOST_UID}:${HOST_GID} /app/target/fedora /app/dist || exit 1
    " || { echo "Failed to build .rpm package in Docker. Exiting." ; exit 1 ; }
}

function create_github_release() {
    if [ "${BB_CREATE_GH_RELEASE}" != "1" ] ; then return ; fi

    echo -e "\n➤ Tagging and creating GitHub Release..."

    git tag "v${BB_VERSION}" ||
		{ echo "Failed to create git tag locally. Exiting." ; exit 1 ; }
    git push origin "v${BB_VERSION}" ||
		{ echo "Failed to push git tag to origin. Exiting." ; exit 1 ; }

    gh release create "v${BB_VERSION}" "${DIST_DIR}"/* \
        --title "Release v${BB_VERSION}" \
        --generate-notes ||
	{ echo "Failed to create GitHub release via gh CLI. Exiting." ; exit 1 ; }
}

function calculate_sha() {
    # We need the SHA for AUR and Gentoo
    if [ "${BB_UPDATE_AUR}" != "1" ] && [ "${BB_UPDATE_GENTOO}" != "1" ] ; then return ; fi
    
    echo -e "\n➤ Downloading source tarball to calculate SHA256 checksum..."
    sleep 3 # Give GitHub a moment to generate the tarball
    
    curl -sL "${TARBALL_URL}" -o "/tmp/${APP_NAME}.tar.gz" ||
		{ echo "Failed to download source tarball. Exiting." ; exit 1 ; }
    TARBALL_SHA=$(sha256sum "/tmp/${APP_NAME}.tar.gz" | awk '{ print $1 }') ||
		{ echo "Failed to calculate SHA256. Exiting." ; exit 1 ; }
    
    if [ -z "${TARBALL_SHA}" ] ; then
        echo "Error: Computed SHA256 is empty. Exiting."
        exit 1
    fi
    
    echo "SHA256: ${TARBALL_SHA}"
}

function update_aur() {
    if [ "${BB_UPDATE_AUR}" != "1" ] ; then return ; fi

    echo -e "\n➤ Updating Arch AUR repository via Docker..."

    if [ ! -d "${AUR_REPO_PATH}" ] ; then
        echo "Error: AUR directory ${AUR_REPO_PATH} not found. Exiting."
        exit 1
    fi

    pushd "${AUR_REPO_PATH}" > /dev/null ||
		{ echo "Failed to enter AUR directory. Exiting." ; exit 1 ; }

    sed -i "s/^pkgver=.*/pkgver=${BB_VERSION}/" PKGBUILD ||
		{ echo "Failed to update pkgver in PKGBUILD. Exiting." ; exit 1 ; }
    sed -i "s/^sha256sums=.*/sha256sums=('${TARBALL_SHA}')/" PKGBUILD ||
		{ echo "Failed to update sha256sums in PKGBUILD. Exiting." ; exit 1 ; }

    docker run --rm -v "$(pwd):/aur" archlinux:base-devel bash -c "
        set -e
        useradd -m builder || exit 1
        chown -R builder:builder /aur || exit 1
        sudo -u builder bash -c 'cd /aur && makepkg --printsrcinfo > .SRCINFO' || exit 1
        chown -R ${HOST_UID}:${HOST_GID} /aur || exit 1
    " || { echo "Failed to generate .SRCINFO via Docker. Exiting." ; exit 1 ; }

    git add PKGBUILD .SRCINFO ||
		{ echo "Failed to git add AUR files. Exiting." ; exit 1 ; }
    git commit -m "Bump to v${BB_VERSION}" ||
		{ echo "Failed to git commit AUR update. Exiting." ; exit 1 ; }
    git push origin main ||
		{ echo "Failed to push to AUR remote. Exiting." ; exit 1 ; }

    popd > /dev/null || exit 1
}

function update_gentoo() {
    if [ "${BB_UPDATE_GENTOO}" != "1" ] ; then return ; fi

    echo -e "\n➤ Updating Gentoo Overlay via Docker..."

    if [ ! -d "${GENTOO_REPO_PATH}" ] ; then
        echo "Error: Gentoo directory ${GENTOO_REPO_PATH} not found. Exiting."
        exit 1
    fi

    pushd "${GENTOO_REPO_PATH}" > /dev/null ||
		{ echo "Failed to enter Gentoo directory. Exiting." ; exit 1 ; }

    OLD_EBUILD=$(ls * | grep \.ebuild | head -n 1)
    if [ -z "${OLD_EBUILD}" ]; then
        echo "Error: Could not find old ebuild file to rename. Exiting."
        exit 1
    fi

    mv "${OLD_EBUILD}" "${APP_NAME}-${BB_VERSION}.ebuild" ||
		{ echo "Failed to rename ebuild file. Exiting." ; exit 1 ; }

    docker run --rm -v "$(pwd):/overlay" gentoo/stage3 bash -c "
        set -e
        cd /overlay || exit 1
        wget ${TARBALL_URL} -O /var/cache/distfiles/${APP_NAME}-${BB_VERSION}.tar.gz || true
        ebuild ${APP_NAME}-${BB_VERSION}.ebuild manifest || exit 1
        chown -R ${HOST_UID}:${HOST_GID} /overlay || exit 1
    " || { echo "Failed to generate Gentoo manifest via Docker. Exiting." ; exit 1 ; }

    git add . ||
		{ echo "Failed to git add Gentoo files. Exiting." ; exit 1 ; }
    git commit -m "${APP_NAME}: Bump to v${BB_VERSION}" ||
		{ echo "Failed to git commit Gentoo update. Exiting." ; exit 1 ; }
    git push origin main ||
		{ echo "Failed to push to Gentoo remote. Exiting." ; exit 1 ; }

    popd > /dev/null || exit 1
}

# ==========================================
# MAIN EXECUTION
# ==========================================

# If -help was passed, print it and exit
print_help

# Standard execution flow
init_env
build_deb
build_rpm
create_github_release
calculate_sha
update_aur
update_gentoo

echo -e "\nRelease v${BB_VERSION} finished !"
