#!/bin/bash
set -e
JDK_FILE=openjdk-22.0.2_linux-x64_bin.tar.gz
JDK_FILE_ARM=openjdk-22.0.2_linux-aarch64_bin.tar.gz
WKH_FILE=wkhtmltox_0.12.6.1-3.bookworm_amd64.deb
WKH_FILE_ARM=wkhtmltox_0.12.6.1-3.bookworm_arm64.deb

# For apktool
mkdir -p /home/mobinspect/.local/share/apktool/framework

# $TARGETPLATFORM is only reliably populated by BuildKit when the build is
# invoked with an explicit --platform (e.g. via buildx); a plain `docker
# build` can leave it empty even under BuildKit, which used to silently fall
# through to the amd64 .deb on an arm64 host (dpkg then refused to install
# it — a mismatched-architecture failure with no `set -e` above to catch it,
# so the build "succeeded" with no wkhtmltopdf binary at all: PDF export
# broke at runtime instead of at build time). Fall back to `uname -m` so
# arch detection is correct regardless of how the build was invoked.
ARCH="$TARGETPLATFORM"
if [ -z "$ARCH" ]; then
    case "$(uname -m)" in
        aarch64|arm64) ARCH=linux/arm64 ;;
        *) ARCH=linux/amd64 ;;
    esac
fi

if [ "$ARCH" == "linux/arm64" ]
then
    WKH_FILE=$WKH_FILE_ARM
    JDK_FILE=$JDK_FILE_ARM
fi

echo "Target platform identified as $ARCH (TARGETPLATFORM='$TARGETPLATFORM')"
JDK_URL="https://download.java.net/java/GA/jdk22.0.2/c9ecb94cd31b495da20a27d4581645e8/9/GPL/${JDK_FILE}"
WKH_URL="https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-3/${WKH_FILE}"

# Download and install wkhtmltopdf

echo "Installing $WKH_FILE ..."
wget --quiet -O /tmp/${WKH_FILE} "${WKH_URL}" && \
    dpkg -i /tmp/${WKH_FILE} && \
    apt-get install -f -y --no-install-recommends && \
    ln -s /usr/local/bin/wkhtmltopdf /usr/bin && \
    rm -f /tmp/${WKH_FILE}

# Install OpenJDK
echo "Installing $JDK_FILE ..."
wget --quiet "${JDK_URL}" && \
    tar zxf "${JDK_FILE}" && \
    rm -f "${JDK_FILE}"

# JADX is installed by a later Dockerfile RUN step, after `COPY . .` — this
# script runs before the mobinspect/ package tree exists in the build
# context, so `tools_download.py`'s `from mobinspect.MobInspect.exceptions
# import PathTraversalError` cannot resolve here.

# Delete script
rm $0
