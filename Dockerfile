# Tool for providing link checks against a statically-built website.

# Set the base image to Ubuntu (version 18.04).
# Uses the new "ubuntu-minimal" image.
FROM ubuntu:18.04

LABEL maintainer="it-services@linaro.org"

################################################################################
# Install locale packages from Ubuntu repositories and set locale.
RUN export DEBIAN_FRONTEND=noninteractive && \
 apt-get clean -y && \
 apt-get update && \
 apt-get install apt-utils -y && \
 apt-get upgrade -y && \
 apt-get install -y language-pack-en && \
 locale-gen en_US.UTF-8 && \
 dpkg-reconfigure locales && \
 apt-get --purge autoremove -y && \
 apt-get clean -y \
 && \
 rm -rf \
 /tmp/* \
 /var/cache/* \
 /var/lib/apt/lists/* \
 /var/log/*

# Set the defaults
ENV LC_ALL en_US.UTF-8
ENV LANG en_US.UTF-8

################################################################################
# Install unversioned dependency packages from Ubuntu repositories.

ENV UNVERSIONED_DEPENDENCY_PACKAGES \
 # Needed by the bash script to determine if this is the latest container.
 curl \
 jq
ENV EPHEMERAL_UNVERSIONED_PACKAGES \
 # Needed to install the Python packages
 python3-pip \
 python3-setuptools
# Python packages used by the link checker.
ENV PIP_PACKAGES \
 bs4 \
 aiohttp

RUN export DEBIAN_FRONTEND=noninteractive && \
 apt-get update && \
 apt-get upgrade -y && \
 apt-get install -y --no-install-recommends \
 ${EPHEMERAL_UNVERSIONED_PACKAGES} \
 ${UNVERSIONED_DEPENDENCY_PACKAGES} \
 && \
 pip3 install wheel && \
 pip3 install ${PIP_PACKAGES} \
 && \
 apt-get --purge remove -y \
 ${EPHEMERAL_UNVERSIONED_PACKAGES} \
 && \
 apt-get --purge autoremove -y && \
 apt-get clean -y \
 && \
 rm -rf \
 /tmp/* \
 /var/cache/* \
 /var/lib/apt/lists/* \
 /var/log/*

################################################################################

COPY check-links-3.py check-links.sh /usr/local/bin/
RUN chmod a+rx /usr/local/bin/check-links-3.py /usr/local/bin/check-links.sh

################################################################################
# Record the Bamboo build job (if specified as an argument)
ARG bamboo_build
ENV BAMBOO_BUILD=${bamboo_build}

ENTRYPOINT ["/usr/local/bin/check-links.sh"]
CMD []
