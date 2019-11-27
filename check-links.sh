#!/bin/ash
# shellcheck shell=dash
#
# This script is run inside the Docker container to check that we're running the latest container
# and warn if we aren't, then kick off running the link checker tool.

get_tag_for_latest(){
    LATEST_ALIAS=""
    # From https://stackoverflow.com/a/41830007/1233830
    REPOSITORY="linaroits/linkcheck"
    TARGET_TAG="latest"
    # check that we have Internet access - bail quickly if we don't
    HEAD=$(curl -s "https://auth.docker.io") || return $?
    # get authorization token
    TOKEN=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:$REPOSITORY:pull" | jq -r .token) || return $?
    # find all tags
    ALL_TAGS=$(curl -s -H "Authorization: Bearer $TOKEN" https://index.docker.io/v2/$REPOSITORY/tags/list | jq -r .tags[]) || return $?
    # get image digest for target
    TARGET_DIGEST=$(curl -s -D - -H "Authorization: Bearer $TOKEN" -H "Accept: application/vnd.docker.distribution.manifest.v2+json" https://index.docker.io/v2/$REPOSITORY/manifests/$TARGET_TAG | grep Docker-Content-Digest | cut -d ' ' -f 2) || return $?
    # for each tags
    for tag in ${#ALL_TAGS}; do
        # get image digest
        digest=$(curl -s -D - -H "Authorization: Bearer $TOKEN" -H "Accept: application/vnd.docker.distribution.manifest.v2+json" https://index.docker.io/v2/$REPOSITORY/manifests/$tag | grep Docker-Content-Digest | cut -d ' ' -f 2) || return $?
        # check digest
        if [ "$TARGET_DIGEST" = "$digest" ] && [ "$tag" != "$TARGET_TAG" ]; then
            LATEST_ALIAS="$tag"
        fi
    done
}

#
# If possible, show which container version this is
if [ -z "$BAMBOO_BUILD" ]; then
    echo "Container built by bamboo.linaro.org: ${BAMBOO_BUILD}"
    get_tag_for_latest || LATEST_ALIAS=""
    if [ -n "$LATEST_ALIAS" ] && [ "$LATEST_ALIAS" != "${BAMBOO_BUILD}" ]; then
        echo "************************************************************"
        echo "WARNING! This does not appear to be the latest Docker image:"
        echo "         $LATEST_ALIAS"
        echo "If the build fails, please 'docker pull linaroits/linkcheck'"
        echo "and try again."
        echo "************************************************************"
    fi
fi

#
# The "external" script will mount the source directory under /srv so we check against that.
cd "/srv" || exit
/usr/local/bin/check-links-3.py "$@"
