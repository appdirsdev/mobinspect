#!/bin/bash
JDK_FILE=openjdk-22.0.2_linux-x64_bin.tar.gz
JDK_FILE_ARM=openjdk-22.0.2_linux-aarch64_bin.tar.gz
WKH_FILE=wkhtmltox_0.12.6.1-3.bookworm_amd64.deb
WKH_FILE_ARM=wkhtmltox_0.12.6.1-3.bookworm_arm64.deb

# For apktool
mkdir -p /home/mobinspect/.local/share/apktool/framework

if [ "$TARGETPLATFORM" == "linux/arm64" ]
then
    WKH_FILE=$WKH_FILE_ARM
    JDK_FILE=$JDK_FILE_ARM
fi

echo "Target platform identified as $TARGETPLATFORM"
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

# Install JADX into the MobInspect home directory inside the image.
# (mobinspect user keeps its name for backward compatibility with existing
# images and the WORKDIR; the home dir name is the rebranded one.)
python3 tools_download.py /home/mobinspect/.MobInspect
rm tools_download.py

# Delete script
rm $0
