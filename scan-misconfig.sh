#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2024

# Usage
#     ./scan-misconfig.sh [--dont-output-result] -i image_link
# Available options:
#     --dont-output-result              don't output result into console, only into file
#     -i, --image string                only this image will be checked. Example: -i r0binak/cve-2024-21626:v4

# Examples
# https://www.docker.com/blog/docker-security-advisory-multiple-vulnerabilities-in-runc-buildkit-and-moby/
# https://github.com/snyk/leaky-vessels-static-detector/blob/main/internal/rules/rules.go
# ./scan-misconfig.sh -i r0binak/cve-2024-21626:v4
# ./scan-misconfig.sh -i withsecurelabs/cve-2024-21626:latest
# ./scan-misconfig.sh -i skybound/cve-2024-21626:9
# ./scan-misconfig.sh -i clausa/cve-2024-21626:latest
# ./scan-misconfig.sh -i sshayb/cve-2024-21626:npd
# ./scan-misconfig.sh -i dvkunion/cve-2024-21626:latest
# ./scan-misconfig.sh -i estragonthecat/cve-2024-21626:latest

set -Eeo pipefail

MISCONFIG_REGEX=(
    "/proc/(1|self)/fd/"
    "\--mount=type=cache"
    "\--mount"
    "#*syntax=*docker*"
)
MISCONFIG_MESSAGE=(
    "CVE-2024-21626 leaky-vessels "
    "CVE-2024-23651 leaky-vessels "
    "CVE-2024-23652 leaky-vessels "
    "CVE-2024-23653 leaky-vessels "
)

# var init
DONT_OUTPUT_RESULT=false
IMAGE_LINK=''
MISCONFIG_RESULT_MESSAGE=''
MISCONFIG_RESULT=false

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

RES_FILE=$SCRIPTPATH'/scan-misconfig.result'
rm -f $RES_FILE
touch $RES_FILE

# read the options
ARGS=$(getopt -o i: --long dont-output-result,image: -n $0 -- "$@")
eval set -- "$ARGS"

# extract options and their arguments into variables.
while true ; do
    case "$1" in
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

# download and unpack image or use cache 
/bin/bash $SCRIPTPATH/scan-download-unpack.sh -i $IMAGE_LINK

echo -ne "  $IMAGE_LINK >>> scan misconfiguration\033[0K\r"

for f in "$SCRIPTPATH/image"/*.json
do
    for (( i=0; i<${#MISCONFIG_REGEX[@]}; i++ ));
    do
        if grep -Eqi ${MISCONFIG_REGEX[$i]} $f; then
            MISCONFIG_RESULT=true
            MISCONFIG_RESULT_MESSAGE=$MISCONFIG_RESULT_MESSAGE$'\n  '${MISCONFIG_MESSAGE[$i]}
        fi
    done
done

# result: output to console and write to file
if [ "$MISCONFIG_RESULT" = true ]; then
    MISCONFIG_RESULT_MESSAGE="$IMAGE_LINK >>> detected dangerous misconfiguration"$MISCONFIG_RESULT_MESSAGE 
    if [ "$DONT_OUTPUT_RESULT" == "false" ]; then  
        echo "$MISCONFIG_RESULT_MESSAGE"
    fi    
    echo "$MISCONFIG_RESULT_MESSAGE" > $RES_FILE
else
    if [ "$DONT_OUTPUT_RESULT" == "false" ]; then 
        echo "$IMAGE_LINK >>> OK                        "
    fi    
    echo "OK" > $RES_FILE
fi

exit 0
