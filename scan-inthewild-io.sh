#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2025

# Usage
#     ./scan-inthewild-io.sh [--cve cve_id] [--dont-output-result] [-i image_link]
# Available options:
#     --cve string                      specify single cve else script trying to read scan-vulnerabilities.cve
#     --dont-output-result              don't output result into console, only into file
#     -i, --image string                only this image will be checked. Example: -i kapistka/log4shell:0.0.3-nonroot
#     --ignore-errors                   ignore inthewild errors (instead, write to $ERROR_FILE)
#     --offline-feeds                   use a self-contained offline image with pre-downloaded vulnerability feeds (e.g., :latest-feeds)
# Example
#     ./scan-inthewild-io.sh --cve CVE-2021-44228
#     ./scan-inthewild-io.sh -i kapistka/log4shell:0.0.3-nonroot


set -Eeo pipefail

# var init
CVE=''
DONT_OUTPUT_RESULT=false
EMOJI_EXPLOITATION='\U1F480' # SKULL
IGNORE_ERRORS=false
IMAGE_LINK=''
IS_ERROR=false
OFFLINE_FEEDS=false

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# check debug mode to debug child scripts and external tools
DEBUG_CURL='-sf '
if [[ "$-" == *x* ]]; then
    DEBUG_CURL='-v '
fi

INPUT_FILE=$OUT_DIR'/scan-vulnerabilities.cve'
JSON_FILE=$OUT_DIR'/scan-inthewild-io.json'
DB_FILE=$OFFLINE_FEEDS_DIR'/inthewild.db'
RES_FILE=$OUT_DIR'/scan-inthewild-io.result'
ERROR_FILE=$OUT_DIR'/scan-inthewild-io.error'
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

get_cve_info()
{
    EXPL='false'
    if  [ "$IS_ERROR" = false ]; then
        mapfile -t EXPLOITS < <(sqlite3 -column "file:$DB_FILE?mode=ro&immutable=1" "SELECT type,timeStamp,referenceURL FROM exploits WHERE id = '$1';")
        if [[ ${#EXPLOITS[@]} -gt 0 ]]; then
            EXPL=true
            rm -rf "$OUT_DIR/$1.expl"
            for ((ii=0; ii<${#EXPLOITS[@]}; ii+=1)); do
                TYPE=$(echo "${EXPLOITS[$ii]}" | awk '{print $1}')
                EXPLOITS[$ii]=$(echo "${EXPLOITS[$ii]}" | sed -E 's/^[^ ]+ +//')
                IS_EXPLOITATION=false
                if [[ "$TYPE" == "exploitation" ]]; then
                    IS_EXPLOITATION=true
                fi
                EXPLOITS[$ii]="${EXPLOITS[$ii]:0:10}${EXPLOITS[$ii]:24}"
                if [ "$IS_EXPLOITATION" == "true" ]; then
                    EXPLOITS[$ii]="    $EMOJI_EXPLOITATION ${EXPLOITS[$ii]}"
                else
                    EXPLOITS[$ii]="       ${EXPLOITS[$ii]}"
                fi
                echo "${EXPLOITS[$ii]}" >> "$OUT_DIR/$1.expl"
            done
        fi
    fi

    # output result
    if [ "$DONT_OUTPUT_RESULT" == "false" ]; then
        echo "$1: EXPL=$EXPL"
    fi
    echo "$EXPL" >> $RES_FILE
}

echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> read inthewild db\033[0K\r"
IS_CACHED=false
if [ -f "$DB_FILE" ]; then
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
    echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> downloading inthewild db\033[0K\r"
    rm -f $DB_FILE
    curl $DEBUG_CURL -L https://pub-4c1eae2a180542b19ea7c88f1e4ccf07.r2.dev/inthewild.db \
            -o $DB_FILE \
            || error_exit "error r2.dev: please check internet connection and retry"

    # check db
    if [ ! -f $DB_FILE ]; then
        error_exit "$DB_FILE not found"
    fi
fi

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
