#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2026

# Usage
#     ./scan-epss.sh [--cve cve_id] [--dont-output-result] [-i image_link]
# Available options:
#     --cve string                      specify single cve else script trying to read scan-vulnerabilities.cve
#     --dont-output-result              don't output result into console, only into file
#     -i, --image string                only this image will be checked. Example: -i kapistka/log4shell:0.0.3-nonroot
#     --ignore-errors                   ignore inthewild errors (instead, write to $ERROR_FILE)
#     --offline-feeds                   use a self-contained offline image with pre-downloaded vulnerability feeds (e.g., :latest-feeds)
# Example
#     ./scan-epss.sh --cve CVE-2025-1974
#     ./scan-epss.sh -i kapistka/log4shell:0.0.3-nonroot


set -Eeo pipefail

# var init
CVE=''
DONT_OUTPUT_RESULT=false
IGNORE_ERRORS=false
IMAGE_LINK=''
IS_ERROR=false
OFFLINE_FEEDS=false
URL_BASE='https://epss.empiricalsecurity.com'

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# get exported var with default value if it is empty
: "${OUT_DIR:=/tmp}"
# check debug mode to debug child scripts and external tools
DEBUG_CURL='-sf '
if [[ "$-" == *x* ]]; then
    DEBUG_CURL='-v '
fi

INPUT_FILE=$OUT_DIR'/scan-vulnerabilities.cve'
DB_FILE=$OFFLINE_FEEDS_DIR'/epss.csv'
GZ_FILE=$OUT_DIR'/epss.csv.gz'
RES_FILE=$OUT_DIR'/epss.result'
ERROR_FILE=$OUT_DIR'/epss.error'
eval "rm -f $RES_FILE $ERROR_FILE"
touch $RES_FILE

# exception handling
error_exit()
{
    if  [ "$IS_ERROR" = false ]; then
        IS_ERROR=true
        if [ "$IGNORE_ERRORS" = true ]; then
            printf "   $1" > $ERROR_FILE
            return 0
        else
            echo "  $IMAGE_LINK >>> $1                    "
            exit 2
        fi
    fi
}

# read the options
ARGS=$(getopt -o i: --long cve:,dont-output-result,ignore-errors,image:,offline-feeds -n $0 -- "$@")
eval set -- "$ARGS"

# extract options and their arguments into variables.
while true ; do
    case "$1" in
        --cve)
            case "$2" in
                "") shift 2 ;;
                *) CVE=$2 ; shift 2 ;;
            esac ;;
        --dont-output-result)
            case "$2" in
                "") shift 1 ;;
                *) DONT_OUTPUT_RESULT=true ; shift 1 ;;
            esac ;;
        --ignore-errors)
            case "$2" in
                "") shift 1 ;;
                *) IGNORE_ERRORS=true ; shift 1 ;;
            esac ;;
        -i|--image)
            case "$2" in
                "") shift 2 ;;
                *) IMAGE_LINK=$2 ; shift 2 ;;
            esac ;;
        --offline-feeds)
            case "$2" in
                "") shift 1 ;;
                *) OFFLINE_FEEDS=true ; shift 1 ;;
            esac ;;
        --) shift ; break ;;
        *) echo "Wrong usage! Try '$0 --help' for more information." ; exit 2 ;;
    esac
done

IS_CACHED=false
if [ -s "$DB_FILE" ]; then
    # check date modification
    if [ $(($(date +%s) - $(stat -c %Y "$DB_FILE"))) -le 90000 ]; then
        IS_CACHED=true
    fi
    # check offline mode
    if [ "$OFFLINE_FEEDS" = true ] ; then
        IS_CACHED=true
    fi
fi

if  [ "$IS_CACHED" = false ]; then
    rm -f $DB_FILE
    IS_DOWNLOADED=false
    for i in $(seq 0 9); do
        d=$(date -d "-${i} day" +%F)
        F="epss_scores-${d}.csv.gz"
        URL="${URL_BASE}/${F}"
        echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> downloading EPSS-${d} db\033[0K\r"
        if curl --connect-timeout 10 --max-time 10 -f $DEBUG_CURL -L "$URL" -o $GZ_FILE; then
            IS_DOWNLOADED=true
            break
        fi
    done
    if  [ "$IS_DOWNLOADED" = true ]; then
        zcat "$GZ_FILE" > "$DB_FILE" || error_exit "error epss: bad file"
    else
        error_exit "error epss: please check internet connection and retry"
    fi
    # check db
    if [ ! -f $DB_FILE ]; then
        error_exit "$DB_FILE not found"
    fi
fi

echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> read EPSS db\033[0K\r"

# load EPSS
declare -A EPSS_LIST
while IFS=',' read -r cve epss _; do
    EPSS_LIST["$cve"]="$epss"
done < "$DB_FILE"

# search cve in epss-db
get_cve_info() {
    local CVE="$1"
    local EPSS="${EPSS_LIST[$CVE]:--}"
    # output result
    if [ "$DONT_OUTPUT_RESULT" == "false" ]; then
        echo "$CVE: EPSS=$EPSS"
    fi
    echo "$EPSS" >> "$RES_FILE"
}

# single cve from argument
if [ ! -z "$CVE" ]; then
    get_cve_info $CVE
# cve list from INPUT_FILE
else
    if [ -f $INPUT_FILE ]; then
        LIST_EPSS=(`awk '{print $1}' $INPUT_FILE`)
        for (( i=0; i<${#LIST_EPSS[@]}; i++ ));
        do
           get_cve_info ${LIST_EPSS[$i]}
        done
    else
        error_exit "$INPUT_FILE not found"
    fi
fi

exit 0
