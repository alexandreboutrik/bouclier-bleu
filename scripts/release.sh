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
: "${BB_PREPARE_CARGO:=0}"
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
while [ $# -ne 0 ]; do
	case "${1}" in
	"-help") ;& "-h") ;& "help")
		BB_HELP=1
		;;
	"-version") ;& "-v")
		BB_VERSION="${2}"
		shift
		;;
	"-prepare")
		BB_PREPARE_CARGO=1
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
	if [ "${BB_HELP}" != "1" ]; then return; fi

	echo "USAGE:"
	echo "  ./scripts/release.sh -v [VERSION] [OPTIONS]"
	echo
	echo "OPTIONS:"
	echo "  -help, -h               Display this help message and exit."
	echo "  -version, -v            Specify the release version (e.g., 1.0.4)."
	echo
	echo "  -prepare                Bump versions in Cargo.toml/README, commit, and push."
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
	local spawned_new_agent=0

	if [ -z "${SSH_AUTH_SOCK}" ]; then
		echo "➤ Starting temporary SSH agent..."
		eval "$(ssh-agent -s)" >/dev/null
		export SSH_AGENT_PID
		export SSH_AUTH_SOCK
		spawned_new_agent=1
	fi

	if ! ssh-add -l | grep -q "id_ed25519"; then
		echo "➤ Loading SSH key..."
		ssh-add ~/.ssh/id_ed25519
	fi

	# Only kill the agent on EXIT if THIS script started it
	if [ "$spawned_new_agent" -eq 1 ]; then
		trap "echo '➤ Cleaning up temporary SSH agent...'; kill \$SSH_AGENT_PID > /dev/null 2>&1" EXIT
	fi

	if [ -z "${BB_VERSION}" ]; then
		echo "Error: Version not specified. Use -v <version>. Exiting."
		echo
		BB_HELP=1 print_help
		exit 1
	fi

	TARBALL_URL="https://github.com/${REPO_OWNER}/${APP_NAME}/archive/refs/tags/v${BB_VERSION}.tar.gz"

	echo "Starting release process for ${APP_NAME} v${BB_VERSION}..."
	echo "Cleaning previous builds..."

	# Only delete DIST_DIR if we are actually building new packages
	if [[ "${BB_BUILD_DEB}" == "1" || "${BB_BUILD_RPM}" == "1" ]]; then
		echo "Cleaning previous builds for new package generation..."
		if [ -d "${DIST_DIR}" ]; then
			sudo rm -rf "${DIST_DIR}" || {
				echo "Failed to remove old dist directory. Exiting."
				exit 1
			}
		fi
	fi

	mkdir -p "${DIST_DIR}" ||
		{
			echo "Failed to create dist directory. Exiting."
			exit 1
		}
}

function prepare_cargo_release() {
	if [ "${BB_PREPARE_CARGO}" != "1" ]; then return; fi
	if [ "${BB_HELP}" == "1" ]; then return; fi

	echo -e "\n➤ Checking versions in Cargo.toml files and README.md..."

	local CARGO_FILES=(
		"Cargo.toml"
		"core/Cargo.toml"
		"modules/Cargo.toml"
		"cli/Cargo.toml"
		"xtask/Cargo.toml"
	)

	local CHANGES_MADE=0

	for file in "${CARGO_FILES[@]}"; do
		if [ -f "${file}" ]; then
			# Check if the file already has the correct version
			if grep -q "^version = \"${BB_VERSION}\"" "${file}"; then
				echo "  ${file} is already at v${BB_VERSION}, skipping..."
			else
				# Matches 'version = "..."' at the start of a line
				sed -i "s/^version = \".*\"/version = \"${BB_VERSION}\"/" "${file}" ||
					{
						echo "Failed to update version in ${file}. Exiting."
						exit 1
					}
				echo "  Updated ${file} to v${BB_VERSION}"
				CHANGES_MADE=1
			fi
		else
			echo "  Warning: ${file} not found, skipping..."
		fi
	done

	if [ -f "README.md" ]; then
		if grep -q "badge/version-v${BB_VERSION}--alpha-blue" README.md; then
			echo "  README.md is already at v${BB_VERSION}, skipping..."
		else
			sed -i "s/badge\/version-v.*--alpha-blue/badge\/version-v${BB_VERSION}--alpha-blue/" README.md ||
				{
					echo "Failed to update version in README.md. Exiting."
					exit 1
				}
			echo "  Updated README.md to v${BB_VERSION}"
			CHANGES_MADE=1
		fi
	else
		echo "  Warning: README.md not found, skipping..."
	fi

	if [ "${CHANGES_MADE}" -eq 1 ]; then
		echo -e "\n➤ Updating Cargo.lock dependencies..."
		cargo update ||
			{
				echo "Failed to run 'cargo update'. Make sure cargo is installed on the host. Exiting."
				exit 1
			}

		echo -e "\n➤ Committing release preparation..."
		git add "${CARGO_FILES[@]}" README.md Cargo.lock ||
			{
				echo "Failed to stage release files. Exiting."
				exit 1
			}

		git commit -m "chore(release): prepare v${BB_VERSION}" ||
			{
				echo "Failed to create release commit. Exiting."
				exit 1
			}

		git push origin main ||
			{
				echo "Failed to push. Exiting."
				exit 1
			}
	else
		echo -e "\n➤ All files are already up to date. Skipping cargo update and git commit."
	fi
}

function build_deb() {
	if [ "${BB_BUILD_DEB}" != "1" ]; then return; fi

	echo -e "\n➤ Building .deb package via Ubuntu Docker..."

	docker run --rm -v "${MAIN_DIR}:/app" -e CARGO_TARGET_DIR=/app/target/ubuntu ubuntu:24.04 bash -c "
        set -e
        apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
            curl build-essential clang llvm libelf-dev zlib1g-dev pkg-config ruby ruby-dev rubygems linux-tools-common linux-tools-generic attr || exit 1

		ln -s /usr/lib/linux-tools/*/bpftool /usr/local/bin/bpftool
        
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y || exit 1
        source \$HOME/.cargo/env

        cd /app
        cargo build --release || exit 1

		mkdir -p /tmp/stage/usr/bin
        mkdir -p /tmp/stage/lib/systemd/system
		mkdir -p /tmp/stage/etc/bouclier-bleu
        cp target/ubuntu/release/core /tmp/stage/usr/bin/bouclier-bleu-core || exit 1
        cp target/ubuntu/release/cli /tmp/stage/usr/bin/bouclier-bleu-cli || exit 1
        cp /app/systemd/bouclier-bleu.service /tmp/stage/lib/systemd/system/ || exit 1
		cp /app/config.toml /tmp/stage/etc/bouclier-bleu/config.toml || exit 1

        gem install fpm || exit 1
        fpm -s dir -t deb -n ${APP_NAME} -v ${BB_VERSION} -C /tmp/stage --deb-systemd /app/systemd/bouclier-bleu.service . || exit 1
        mv *.deb /app/dist/ || exit 1
        
        chown -R ${HOST_UID}:${HOST_GID} /app/target/ubuntu /app/dist || exit 1
    " || {
		echo "Failed to build .deb package in Docker. Exiting."
		exit 1
	}
}

function build_rpm() {
	if [ "${BB_BUILD_RPM}" != "1" ]; then return; fi

	echo -e "\n➤ Building .rpm package via Fedora Docker..."

	docker run --rm -v "${MAIN_DIR}:/app" -e CARGO_TARGET_DIR=/app/target/fedora fedora:40 bash -c "
        set -e
        dnf install -y curl make gcc clang llvm elfutils-libelf-devel zlib-devel pkg-config ruby ruby-devel rpm-build bpftool attr || exit 1
        
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y || exit 1
        source \$HOME/.cargo/env

        cd /app
        cargo build --release || exit 1

		mkdir -p /tmp/stage/usr/bin
        mkdir -p /tmp/stage/usr/lib/systemd/system
		mkdir -p /tmp/stage/etc/bouclier-bleu
        cp target/fedora/release/core /tmp/stage/usr/bin/bouclier-bleu-core || exit 1
        cp target/fedora/release/cli /tmp/stage/usr/bin/bouclier-bleu-cli || exit 1
        cp /app/systemd/bouclier-bleu.service /tmp/stage/usr/lib/systemd/system/ || exit 1
		cp /app/config.toml /tmp/stage/etc/bouclier-bleu/config.toml || exit 1

        gem install fpm || exit 1
        fpm -s dir -t rpm -n ${APP_NAME} -v ${BB_VERSION} -C /tmp/stage . || exit 1
        mv *.rpm /app/dist/ || exit 1

        chown -R ${HOST_UID}:${HOST_GID} /app/target/fedora /app/dist || exit 1
    " || {
		echo "Failed to build .rpm package in Docker. Exiting."
		exit 1
	}
}

function create_github_release() {
	if [ "${BB_CREATE_GH_RELEASE}" != "1" ]; then return; fi

	# Check if any other "action" flags were provided
	local TOTAL_ACTIONS=$((BB_BUILD_DEB + BB_BUILD_RPM + BB_UPDATE_AUR + BB_UPDATE_GENTOO))
	local ONLY_GH=0
	if [ "${TOTAL_ACTIONS}" -eq 0 ]; then
		ONLY_GH=1
	fi

	echo -e "\n➤ Tagging and creating GitHub Release..."

	# Handle Local Tag
	if ! git tag "v${BB_VERSION}" 2>/dev/null; then
		if [ "${ONLY_GH}" -eq 1 ]; then
			echo "[INFO] Local tag v${BB_VERSION} already exists. Continuing because only -gh was requested."
		else
			echo "[ERROR] Local tag v${BB_VERSION} already exists or failed. Exiting to prevent inconsistent state."
			exit 1
		fi
	fi

	# Handle Remote Tag Push
	if ! git push origin "v${BB_VERSION}" 2>/dev/null; then
		if [ "${ONLY_GH}" -eq 1 ]; then
			echo "[INFO] Remote tag v${BB_VERSION} already exists on origin. Continuing..."
		else
			echo "[ERROR] Failed to push git tag to origin. Exiting."
			exit 1
		fi
	fi

	# Create Release (checks if release already exists to avoid gh CLI error)
	if gh release view "v${BB_VERSION}" >/dev/null 2>&1; then
		echo "[INFO] GitHub Release v${BB_VERSION} already exists. Skipping creation."
	else
		gh release create "v${BB_VERSION}" "${DIST_DIR}"/* \
			--title "v${BB_VERSION}" \
			--generate-notes || {
			echo "Failed to create GitHub release. Exiting."
			exit 1
		}
	fi
}

function calculate_sha() {
	# We need the SHA for AUR and Gentoo
	if [ "${BB_UPDATE_AUR}" != "1" ] && [ "${BB_UPDATE_GENTOO}" != "1" ]; then return; fi

	echo -e "\n➤ Downloading source tarball to calculate SHA256 checksum..."
	sleep 3 # Give GitHub a moment to generate the tarball

	curl -sL "${TARBALL_URL}" -o "/tmp/${APP_NAME}.tar.gz" ||
		{
			echo "Failed to download source tarball. Exiting."
			exit 1
		}
	TARBALL_SHA=$(sha256sum "/tmp/${APP_NAME}.tar.gz" | awk '{ print $1 }') ||
		{
			echo "Failed to calculate SHA256. Exiting."
			exit 1
		}

	if [ -z "${TARBALL_SHA}" ]; then
		echo "Error: Computed SHA256 is empty. Exiting."
		exit 1
	fi

	echo "SHA256: ${TARBALL_SHA}"
}

function update_aur() {
	if [ "${BB_UPDATE_AUR}" != "1" ]; then return; fi

	echo -e "\n➤ Updating Arch AUR repository via Docker..."

	if [ ! -d "${AUR_REPO_PATH}" ]; then
		echo "Error: AUR directory ${AUR_REPO_PATH} not found. Exiting."
		exit 1
	fi

	pushd "${AUR_REPO_PATH}" >/dev/null ||
		{
			echo "Failed to enter AUR directory. Exiting."
			exit 1
		}

	sed -i "s/^pkgver=.*/pkgver=${BB_VERSION}/" PKGBUILD ||
		{
			echo "Failed to update pkgver in PKGBUILD. Exiting."
			exit 1
		}
	sed -i "s/^sha256sums=.*/sha256sums=('${TARBALL_SHA}')/" PKGBUILD ||
		{
			echo "Failed to update sha256sums in PKGBUILD. Exiting."
			exit 1
		}

	docker run --rm -v "$(pwd):/aur" archlinux:base-devel bash -c "
        set -e
        useradd -m builder || exit 1
        chown -R builder:builder /aur || exit 1
        sudo -u builder bash -c 'cd /aur && makepkg --printsrcinfo > .SRCINFO' || exit 1
        chown -R ${HOST_UID}:${HOST_GID} /aur || exit 1
    " || {
		echo "Failed to generate .SRCINFO via Docker. Exiting."
		exit 1
	}

	git add PKGBUILD .SRCINFO ||
		{
			echo "Failed to git add AUR files. Exiting."
			exit 1
		}
	git commit -m "Bump to v${BB_VERSION}" ||
		{
			echo "Failed to git commit AUR update. Exiting."
			exit 1
		}
	git push origin main ||
		{
			echo "Failed to push to AUR remote. Exiting."
			exit 1
		}

	popd >/dev/null || exit 1
}

function update_gentoo() {
	if [ "${BB_UPDATE_GENTOO}" != "1" ]; then return; fi

	echo -e "\n➤ Updating Gentoo Overlay via Docker..."

	if [ ! -d "${GENTOO_REPO_PATH}" ]; then
		echo "Error: Gentoo directory ${GENTOO_REPO_PATH} not found. Exiting."
		exit 1
	fi

	pushd "${GENTOO_REPO_PATH}" >/dev/null ||
		{
			echo "Failed to enter Gentoo directory. Exiting."
			exit 1
		}

	OLD_EBUILD=$(ls * | grep \.ebuild | head -n 1)
	if [ -z "${OLD_EBUILD}" ]; then
		echo "Error: Could not find old ebuild file to rename. Exiting."
		exit 1
	fi

	mv "${OLD_EBUILD}" "${APP_NAME}-${BB_VERSION}.ebuild" ||
		{
			echo "Failed to rename ebuild file. Exiting."
			exit 1
		}

	docker run --rm -v "$(pwd):/overlay" gentoo/stage3 bash -c "
        set -e
        cd /overlay || exit 1
        wget ${TARBALL_URL} -O /var/cache/distfiles/${APP_NAME}-${BB_VERSION}.tar.gz || true
        ebuild ${APP_NAME}-${BB_VERSION}.ebuild manifest || exit 1
        chown -R ${HOST_UID}:${HOST_GID} /overlay || exit 1
    " || {
		echo "Failed to generate Gentoo manifest via Docker. Exiting."
		exit 1
	}

	git add . ||
		{
			echo "Failed to git add Gentoo files. Exiting."
			exit 1
		}
	git commit -m "${APP_NAME}: Bump to v${BB_VERSION}" ||
		{
			echo "Failed to git commit Gentoo update. Exiting."
			exit 1
		}
	git push origin main ||
		{
			echo "Failed to push to Gentoo remote. Exiting."
			exit 1
		}

	popd >/dev/null || exit 1
}

# ==========================================
# MAIN EXECUTION
# ==========================================

# If -help was passed, print it and exit
print_help

# Standard execution flow
init_env
prepare_cargo_release
build_deb
build_rpm
create_github_release
calculate_sha
update_aur
update_gentoo

echo -e "\nRelease v${BB_VERSION} finished !"
