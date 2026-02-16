#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2025

# Usage
#     ./scan-vulners-com.sh [--cve cve_id] [--dont-output-result] [-i image_link] --vulners-key vulners_api_key
# Available options:
#     --cve string                      specify single cve or script trying to read scan-vulnerabilities.cve
#     --dont-output-result              don't output result into console, only into file
#     -i, --image string                only this image will be checked. Example: -i kapistka/log4shell:0.0.3-nonroot
#     --ignore-errors                   ignore vulners errors (instead, write to $ERROR_FILE)
#     --vulners-key string              specify vulners API-key, example: ---vulners-key 0123456789ABCDXYZ
# Example
#     ./scan-vulners-com.sh --cve CVE-2021-44228 --vulners-key 0123456789ABCDXYZ
#     ./scan-vulners-com.sh --vulners-key 0123456789ABCDXYZ -i kapistka/log4shell:0.0.3-nonroot


set -Eeo pipefail

# var init (don't change)
CVE=''
DONT_OUTPUT_RESULT=false
IGNORE_ERRORS=false
IMAGE_LINK=''
IS_ERROR=false
VULNERS_API_KEY=''

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# check debug mode to debug child scripts and external tools
# get exported var with default value if it is empty
: "${OUT_DIR:=/tmp}"
DEBUG=''
DEBUG_CURL='-s '
if [[ "$-" == *x* ]]; then
    DEBUG='-x '
    DEBUG_CURL='-v '
fi
# turn on/off debugging for hide sensetive data
debug_set() {
    if [ "$1" = false ] ; then
        set +x
    else
        if [ "$DEBUG" != "" ]; then
            set -x
        fi
    fi
}

INPUT_FILE=$OUT_DIR'/scan-vulnerabilities.cve'
JSON_FILE=$OUT_DIR'/scan-vulners-com.json'
RES_FILE=$OUT_DIR'/scan-vulners-com.result'
ERROR_FILE=$OUT_DIR'/scan-vulners-com.error'
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
debug_set false
ARGS=$(getopt -o i: --long cve:,dont-output-result,ignore-errors,image:,vulners-key: -n $0 -- "$@")
eval set -- "$ARGS"
debug_set true

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
        --vulners-key)
            case "$2" in
                "") shift 2 ;;
                *) debug_set false ; VULNERS_API_KEY=$2 ; debug_set true ; shift 2 ;;
            esac ;;
        --) shift ; break ;;
        *) echo "Wrong usage! Try '$0 --help' for more information." ; exit 2 ;;
    esac
done

get_cve_info()
{
    eval "rm -f $JSON_FILE"
    debug_set false
    curl --connect-timeout 10 $DEBUG_CURL -XPOST --compressed -L https://vulners.com/api/v3/search/id \
          -o $JSON_FILE \
          -H 'Content-Type: application/json' --data-binary @- <<EOF || error_exit "error vulners.com: please check internet connection and retry"
        {
        "id": "$1",
        "fields": ["*"],
        "apiKey": "$VULNERS_API_KEY"
        }
EOF
    debug_set true
    EXPL=null
    EPSS=null
    CVSS=null
    RESPONSE_ERROR=''
    if [ -f $JSON_FILE ]; then
        RESPONSE_ERROR=`jq '.data.error' $JSON_FILE`
        EXPL=`jq '.data.documents."'$1'".enchantments.exploitation.wildExploited' $JSON_FILE`
        EPSS=`jq '.data.documents."'$1'".epss[0].epss' $JSON_FILE`
        CVSS=`jq '.data.documents."'$1'".cvss.score' $JSON_FILE`
    else
        error_exit "error vulners.com: please check api-key, internet connection and retry"
    fi
    if [ $? -ne 0 ]; then
        error_exit "error vulners.com: please check api-key, internet connection and retry"
    fi
    if [ ! -z "$RESPONSE_ERROR" ]; then
        error_exit "error vulners.com: $RESPONSE_ERROR"
    fi

    # output result
    if [ "$DONT_OUTPUT_RESULT" == "false" ]; then
        echo "$1: EXPL=$EXPL, EPSS=$EPSS, CVSS=$CVSS"
    fi
    echo "$EXPL" >> $RES_FILE
}

echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> check vulners.com\033[0K\r"

# single cve from argument
if [ ! -z "$CVE" ]; then
    get_cve_info $CVE
# cve list from INPUT_FILE
else
    if [ -f $INPUT_FILE ]; then
        LIST_CVE=(`awk '{print $1}' $INPUT_FILE`)
        for (( i=0; i<${#LIST_CVE[@]}; i++ ));
        do
           get_cve_info ${LIST_CVE[$i]}
        done
    else
        error_exit "$INPUT_FILE not found"
    fi
fi

exit 0
