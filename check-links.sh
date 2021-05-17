#!/bin/bash
#
# This script is run inside the Docker container to check that we're running the latest container
# and warn if we aren't, then kick off running the link checker tool.

function get_tag_for_latest(){
    LATEST_ALIAS=""
    # From https://stackoverflow.com/a/41830007/1233830
    REPOSITORY="linaroits/linkcheck"
    TARGET_TAG="latest"
    # Check that we have Internet access - bail quickly if we don't.
    # We don't care about what curl returns so throw it away.
    _=$(curl -s "https://auth.docker.io") || return $?
    # Get authorization token.
    TOKEN=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:$REPOSITORY:pull" | jq -r .token) || return $?
    # Find all tags.
    ALL_TAGS=$(curl -s -H "Authorization: Bearer $TOKEN" https://index.docker.io/v2/$REPOSITORY/tags/list | jq -r .tags[]) || return $?
    # Get image digest for target.
    TARGET_DIGEST=$(curl -s -D - -H "Authorization: Bearer $TOKEN" -H "Accept: application/vnd.docker.distribution.manifest.v2+json" "https://index.docker.io/v2/$REPOSITORY/manifests/$TARGET_TAG" | grep -i Docker-Content-Digest | cut -d ' ' -f 2) || return $?
    # Iterate through the tags, but we need to use unquoted bash expansion so turn off the shellcheck warning
    # shellcheck disable=SC2068
    for tag in ${ALL_TAGS[@]}; do
        # get image digest
        digest=$(curl -s -D - -H "Authorization: Bearer $TOKEN" -H "Accept: application/vnd.docker.distribution.manifest.v2+json" "https://index.docker.io/v2/$REPOSITORY/manifests/$tag" | grep -i Docker-Content-Digest | cut -d ' ' -f 2) || return $?
        # and check digest.
        if [ "$TARGET_DIGEST" = "$digest" ] && [ "$tag" != "$TARGET_TAG" ]; then
            LATEST_ALIAS="$tag"
        fi
    done
}

#
# If possible, show which container version this is
if [ -n "${BAMBOO_BUILD}" ]; then
    echo "Container built by GitHub. Build reference: ${BAMBOO_BUILD}"
    get_tag_for_latest || LATEST_ALIAS=""
    if [ -n "$LATEST_ALIAS" ] && [ "$LATEST_ALIAS" != "${BAMBOO_BUILD}" ]; then
        echo "************************************************************"
        echo "WARNING! This does not appear to be the latest Docker image:"
        echo "         $LATEST_ALIAS"
        echo "If the build fails, please 'docker pull linaroits/linkcheck'"
        echo "and try again."
        echo "************************************************************"
    fi
    if [ -z "$LATEST_ALIAS" ]; then
        echo "******************************************************************"
        echo "WARNING! It has not been possible to check that this is the latest"
        echo "         Docker image."
        echo "******************************************************************"
    fi
fi

#
# The "external" script will mount the source directory under /srv so we check against that.
cd "/srv" || exit
/usr/local/bin/check_links_3.py "$@"
