#!/bin/sh

# This install script is intended to download and install the latest available
# release of jwtinfo (it is based on golang/dep install script).
#
# It attempts to identify the current platform and an error will be thrown if
# the platform is not supported.
#
# Environment variables:
# - INSTALL_DIRECTORY (optional): defaults to /usr/local/bin
# - RELEASE_TAG (optional): defaults to fetching the latest release
# - DEP_OS (optional): use a specific value for OS (mostly for testing)
# - DEP_ARCH (optional): use a specific value for ARCH (mostly for testing)
#
# You can install using this script:
# $ curl https://raw.githubusercontent.com/lmammino/jwtinfo/main/install.sh | sh

set -e

RELEASES_URL="https://github.com/lmammino/jwtinfo/releases"

downloadJSON() {
    url="$2"

    echo "Fetching $url.."
    if test -x "$(command -v curl)"; then
        response=$(curl -s -L -w 'HTTPSTATUS:%{http_code}' -H 'Accept: application/json' "$url")
        body=$(echo "$response" | sed -e 's/HTTPSTATUS\:.*//g')
        code=$(echo "$response" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')
    elif test -x "$(command -v wget)"; then
        temp=$(mktemp)
        body=$(wget -q --header='Accept: application/json' -O - --server-response "$url" 2> "$temp")
        code=$(awk '/^  HTTP/{print $2}' < "$temp" | tail -1)
        rm "$temp"
    else
        echo "Neither curl nor wget was available to perform http requests."
        exit 1
    fi
    if [ "$code" != 200 ]; then
        echo "Request failed with code $code"
        exit 1
    fi

    eval "$1='$body'"
}

downloadFile() {
    url="$1"
    destination="$2"

    echo "Fetching $url.."
    if test -x "$(command -v curl)"; then
        code=$(curl -s -w '%{http_code}' -L "$url" -o "$destination")
    elif test -x "$(command -v wget)"; then
        code=$(wget -q -O "$destination" --server-response "$url" 2>&1 | awk '/^  HTTP/{print $2}' | tail -1)
    else
        echo "Neither curl nor wget was available to perform http requests."
        exit 1
    fi

    if [ "$code" != 200 ]; then
        echo "Request failed with code $code"
        exit 1
    fi
}

findBinDirectory() {
    EFFECTIVE_BINPATH=/usr/local
    # CYGWIN: Convert Windows-style path into sh-compatible path
    if [ "$OS_CYGWIN" = "1" ]; then
	EFFECTIVE_BINPATH=$(cygpath "$EFFECTIVE_BINPATH")
    fi
    if [ -z "$EFFECTIVE_BINPATH" ]; then
        echo "Installation could not determine your \$BINPATH."
        exit 1
    fi
    if [ -z "$GOBIN" ]; then
        GOBIN=$(echo "${EFFECTIVE_BINPATH%%:*}/bin" | sed s#//*#/#g)
    fi
    if [ ! -d "$GOBIN" ]; then
        echo "Installation requires your GOBIN directory $GOBIN to exist. Please create it."
        exit 1
    fi
    eval "$1='$GOBIN'"
}

initArch() {
    ARCH=$(uname -m)
    if [ -n "$DEP_ARCH" ]; then
        echo "Using DEP_ARCH"
        ARCH="$DEP_ARCH"
    fi
    case $ARCH in
        amd64) ARCH="amd64";;
        x86_64) ARCH="amd64";;
        # i386) ARCH="386";;
        # ppc64) ARCH="ppc64";;
        # ppc64le) ARCH="ppc64le";;
        # s390x) ARCH="s390x";;
        # armv6*) ARCH="arm";;
        armv7*) ARCH="arm";;
        # aarch64) ARCH="arm64";;
        *) echo "Architecture ${ARCH} is not supported by this installation script"; exit 1;;
    esac
    echo "ARCH = $ARCH"
}

initOS() {
    OS=$(uname | tr '[:upper:]' '[:lower:]')
    OS_CYGWIN=0
    if [ -n "$DEP_OS" ]; then
        echo "Using DEP_OS"
        OS="$DEP_OS"
    fi
    case "$OS" in
        darwin) OS='darwin';;
        linux) OS='linux';;
        freebsd) OS='freebsd';;
        mingw*) OS='windows';;
        msys*) OS='windows';;
	cygwin*)
	    OS='windows'
	    OS_CYGWIN=1
	    ;;
        *) echo "OS ${OS} is not supported by this installation script"; exit 1;;
    esac
    echo "OS = $OS"
}

# identify platform based on uname output
initArch
initOS

# determine install directory if required
if [ -z "$INSTALL_DIRECTORY" ]; then
    findBinDirectory INSTALL_DIRECTORY
fi
echo "Will install into $INSTALL_DIRECTORY"

# assemble expected release artifact name
# if [ "${OS}" != "linux" ] && { [ "${ARCH}" = "ppc64" ] || [ "${ARCH}" = "ppc64le" ];}; then
#     # ppc64 and ppc64le are only supported on Linux.
#     echo "${OS}-${ARCH} is not supported by this instalation script"
# else
#     # BINARY="jwtinfo-${OS}-${ARCH}"
#     BINARY="jwtinfo-unix64"
# fi

# # add .exe if on windows
# if [ "$OS" = "windows" ]; then
#     # BINARY="$BINARY.exe"
#     BINARY="jwtinfo-win64.exe"
# fi
case "$OS" in
    darwin) BINARY='jwtinfo-macos';;
    linux) BINARY='jwtinfo-unix64';;
    freebsd) BINARY='jwtinfo-unix64';;
    windows) BINARY='jwtinfo-win64.exe';;
    *) echo "OS ${OS} is not supported by this installation script"; exit 1;;
esac

if [ "$ARCH" = "arm" ]; then
    # BINARY="$BINARY.exe"
    BINARY="jwtinfo-armv7"
fi

# Adds .gz suffix
BINARY="${BINARY}.gz"

# if RELEASE_TAG was not provided, assume latest
if [ -z "$RELEASE_TAG" ]; then
    downloadJSON LATEST_RELEASE "$RELEASES_URL/latest"
    RELEASE_TAG=$(echo "${LATEST_RELEASE}" | tr -s '\n' ' ' | sed 's/.*"tag_name":"//' | sed 's/".*//' )
fi
echo "Release Tag = $RELEASE_TAG"

# fetch the real release data to make sure it exists before we attempt a download
downloadJSON RELEASE_DATA "$RELEASES_URL/tag/$RELEASE_TAG"

BINARY_URL="$RELEASES_URL/download/$RELEASE_TAG/$BINARY"
DOWNLOAD_FILE=$(mktemp)
GUNZIPPED_FILE=$(mktemp)

downloadFile "$BINARY_URL" "$DOWNLOAD_FILE"

echo "Decompressing $DOWNLOAD_FILE into $GUNZIPPED_FILE"
gunzip -c "$DOWNLOAD_FILE" > "$GUNZIPPED_FILE"

echo "Setting executable permissions."
chmod +x "$GUNZIPPED_FILE"

INSTALL_NAME="jwtinfo"

if [ "$OS" = "windows" ]; then
    INSTALL_NAME="$INSTALL_NAME.exe"
fi

echo "Moving executable to $INSTALL_DIRECTORY/$INSTALL_NAME"
mv "$GUNZIPPED_FILE" "$INSTALL_DIRECTORY/$INSTALL_NAME"
