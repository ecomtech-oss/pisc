#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2024

# Usage
#     ./scan-inthewild-io.sh [--cve cve_id] [--dont-output-result] [-i image_link]
# Available options:
#     --cve string                      specify single cve or script trying to read scan-trivy.cve 
#     --dont-output-result              don't output result into console, only into file
#     -i, --image string                only this image will be checked. Example: -i kapistka/log4shell:0.0.3-nonroot
# Example
#     ./scan-inthewild-io.sh --cve CVE-2021-44228
#     ./scan-inthewild-io.sh -i kapistka/log4shell:0.0.3-nonroot


set -Eeo pipefail

# exception handling
error_exit()
{
    echo "$1"
    exit 1
}

# var init
CVE=''
DONT_OUTPUT_RESULT=false
IMAGE_LINK=''

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

INPUT_FILE=$SCRIPTPATH'/scan-trivy.cve'
JSON_FILE=$SCRIPTPATH'/scan-inthewild-io.json'
RES_FILE=$SCRIPTPATH'/scan-inthewild-io.result'
rm -f $RES_FILE
touch $RES_FILE

# read the options
ARGS=$(getopt -o i: --long cve:,dont-output-result,image: -n $0 -- "$@")
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
        -i|--image)
            case "$2" in
                "") shift 2 ;;
                *) IMAGE_LINK=$2 ; shift 2 ;;
            esac ;;
        --) shift ; break ;;
        *) echo "Wrong usage! Try '$0 --help' for more information." ; exit 2 ;;
    esac
done

get_cve_info()
{
    EXPL=''
    if [ -f $JSON_FILE ]; then
        EXPL='false'
        if grep -q $1 $JSON_FILE; then
            EXPL='true'
        fi
    else 
        error_exit "$IMAGE_LINK >>> error inthewild.io: please check internet connection and retry"
    fi
    
    # output result
    if [ "$DONT_OUTPUT_RESULT" == "false" ]; then
        echo "$1: EXPL=$EXPL"
    fi    
    echo "$EXPL" >> $RES_FILE
}

echo -ne "  $IMAGE_LINK >>> check inthewild.io\033[0K\r"
rm -f $JSON_FILE &>/dev/null
curl -s -XPOST --compressed -L https://inthewild.io/api/exploited \
        -o $JSON_FILE \
        -H 'Content-Type: application/json'
if [ $? -ne 0 ]; then
    error_exit "$IMAGE_LINK >>> error inthewild.io: please check internet connection and retry"
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
        error_exit "$IMAGE_LINK >>> $INPUT_FILE not found"
    fi      
fi

exit 0
