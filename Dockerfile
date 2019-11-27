# Tool for providing link checks against a statically-built website.

# Set the base image to Alpine (version 3.10).
FROM alpine:3.10

LABEL maintainer="it-services@linaro.org"

################################################################################
# Install unversioned dependency packages from Ubuntu repositories.

ENV UNVERSIONED_DEPENDENCY_PACKAGES \
 # Needed by the busybox script to determine if this is the latest container.
 curl \
 jq \
 # Needed to install the Python packages
 python3

RUN apk add --no-cache --update \
 ${UNVERSIONED_DEPENDENCY_PACKAGES} \
 && \
 rm -rf \
 /var/cache/apk/*

################################################################################
# Install Python packages used by the link checker.

ENV PIP_PACKAGES \
 beautifulsoup4 \
 aiohttp \
 wheel

RUN pip3 install \
 ${PIP_PACKAGES}

COPY check-links-3.py check-links.sh /usr/local/bin/
RUN chmod a+rx /usr/local/bin/check-links-3.py /usr/local/bin/check-links.sh

################################################################################
# Record the Bamboo build job (if specified as an argument)
ARG bamboo_build
ENV BAMBOO_BUILD=${bamboo_build}

ENTRYPOINT ["/usr/local/bin/check-links.sh"]
CMD []
