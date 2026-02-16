#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2026

# Notes:
# The script checks exclusions listed in the $EXCLUSIONS_FILE file (whitelist.yaml by default).
# The file format supports YAML syntax. Each exclusion rule applies to the specified image only.
# Ensure that only one exclusion criterion (cve, package, malware, misconfig, days, tag) is used per rule to maintain clarity.

# whitelist.yaml file format:

# - image:
#     - "*"
#   cve:
#     - "CVE-2025-1234"
#     - "CVE-2025-5678"
#
# - misconfig:
#     - "*"
#   image:
#     - "docker.io/php:*"
#
# - malware:
#     - "*"
#   image:
#     - "docker.io/pulumi/pulumi-python:*"
#
# - tag:
#     - "[0-9]"
#   image:
#     - "debian:*"

# Usage
#     ./check-exclusions.sh -i image_link [ --cve | --package | --malware | --misconfig | --days | --tag ]

# Options:
#     -i, --image string                Specify the Docker image to check (use `-i "*"` for local tar archive scan).
#     --cve string                      Check exclusions based on CVE ID.
#     --package string                  Check exclusions based on package name.
#     --malware string                  Check exclusions based on a malicious file name or pattern.
#     --misconfig string                Check exclusions based on a Dockerfile misconfig
#     --days number                     Check exclusions based on image creation date (number of days for build date).
#     --tag string                      Check exclusions based on image tag.

# Examples
# ./check-exclusions.sh -i alpine:latest --cve CVE-2025-12345
# ./check-exclusions.sh -i alpine:latest --package linux-libc-dev
# ./check-exclusions.sh -i alpine:latest --malware "*"
# ./check-exclusions.sh -i alpine:latest --misconfig "*"
# ./check-exclusions.sh -i alpine:latest --days 500
# ./check-exclusions.sh -i alpine:latest --tag latest

# Exit Codes:
#     0 - The image does not meet the exclusion criteria
#     1 - The image meets the exclusion criteria
#     2 - Any error

set -Eeo pipefail

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# get exported var with default value if it is empty
: "${OUT_DIR:=/tmp}"
: "${EXCLUSIONS_FILE:=$SCRIPTPATH/whitelist.yaml}"
ERROR_FILE=$OUT_DIR'/check-exclusions.error'
CSV_FILE=$OUT_DIR'/whitelist.csv'

# if whitelist not found then exit 0
if [ ! -f $EXCLUSIONS_FILE ]; then
    exit 0
fi

#var init
IMAGE_LINK=''
SEARCH_KEY=''
SEARCH_VALUE=''

error_exit()
{
    printf "   $1" > $ERROR_FILE
    exit 2
}

# read the options
ARGS=$(getopt -o i: --long cve:,days:,image:,malware:,misconfig:,package:,tag: -n $0 -- "$@")
eval set -- "$ARGS"

# extract options and their arguments into variables
while true ; do
    case "$1" in
        --cve|--days|--malware|--misconfig|--package|--tag)
            case "$2" in
                "") shift 2 ;;
                *) SEARCH_KEY=${1:2} ; SEARCH_VALUE=$2 ; shift 2 ;;
            esac ;;
        -i|--image)
            case "$2" in
                "") shift 2 ;;
                *) IMAGE_LINK=$2 ; shift 2 ;;
            esac ;;
        --) shift ; break ;;
        *) echo "Wrong usage! Try '$0 --help' for more information." ; exit 2 ;;
    esac
done

if [ -z "$IMAGE_LINK" ]; then
    error_exit "check exclusions: set -i argument"
fi
if [ -z "$SEARCH_KEY" ]; then
    error_exit "check exclusions: set cve, package, malware, misconfig, days, tag"
fi
if [ -z "$SEARCH_VALUE" ]; then
    error_exit "check exclusions: set searching value"
fi

# arrays init
declare -a VALUE_LIST
declare -a IMAGE_LIST

# csv cached and removed from parent script
if [ ! -s $CSV_FILE ]; then
    IMAGE_LIST=()
    KEY_LIST=()
    VALUE_LIST=()
    # convert yaml to csv
    yq -o=json '.[]' $EXCLUSIONS_FILE | jq -r '.image[] as $image | to_entries[] | select(.key != "image") | [($image), .key, .value[]] | @csv' | tr -d '"' > $CSV_FILE \
      || error_exit "check exclusions: yaml error"
    # read csv
    while IFS=, read -r image key value; do
        # check format
        if [ -z "$image" ]; then
            error_exit "check exclusions: wrong format - image should be set"
        fi
        if [ -z "$value" ]; then
            error_exit "check exclusions: wrong format - value should be set"
        fi
        if [[ "$key" == "malware" ]] && [[ "$value" != "*" ]]; then
            error_exit "check exclusions: wrong format - malware should be * only"
        fi
        if [[ "$key" == "misconfig" ]] && [[ "$value" != "*" ]]; then
            error_exit "check exclusions: wrong format - misconfig should be * only"
        fi

        IMAGE_LIST+=("$image")
        KEY_LIST+=("$key")
        VALUE_LIST+=("$value")
    done < $CSV_FILE
    > $CSV_FILE
    # write csv extended
    for (( i=0; i<${#IMAGE_LIST[@]}; i++ ));
    do
        IFS=',' read -r -a A <<< "${VALUE_LIST[$i]}"
        for (( j=0; j<${#A[@]}; j++ ));
        do
            echo "${IMAGE_LIST[$i]},${KEY_LIST[$i]},${A[$j]}" >> $CSV_FILE
        done
    done
fi

# reading from cached csv
IMAGE_LIST=()
VALUE_LIST=()
while IFS=',' read -r image key value; do
    # read only SEARCH_KEY needed
    if [[ $SEARCH_KEY == $key ]]; then
        IMAGE_LIST+=("$image")
        VALUE_LIST+=("$value")
    fi
done < $CSV_FILE

# searching
for (( i=0; i<${#IMAGE_LIST[@]}; i++ ));
do
    if [[ $IMAGE_LINK == ${IMAGE_LIST[$i]} ]]; then
        if [[ $SEARCH_KEY == "cve" || $SEARCH_KEY == "package" || $SEARCH_KEY == "malware" || $SEARCH_KEY == "misconfig" ]]; then
            # use * pattern
            if [[ $SEARCH_VALUE == ${VALUE_LIST[$i]} ]]; then
                exit 1
            fi
        elif [[ $SEARCH_KEY == "tag" ]]; then
            # use [0-9] pattern
            if [[ "$SEARCH_VALUE" =~ ${VALUE_LIST[$i]} ]]; then
                exit 1
            fi
        elif [[ $SEARCH_KEY == "days" ]]; then
            if [[ $SEARCH_VALUE =~ ^[0-9]+(\.[0-9]+)?$ && ${VALUE_LIST[$i]} =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
                if awk "BEGIN {exit !($SEARCH_VALUE <= ${VALUE_LIST[$i]})}"; then
                    exit 1
                fi
            else
                error_exit "check exclusions: wrong format - days should be a number"
            fi
        fi
    fi
done

exit 0
