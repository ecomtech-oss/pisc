#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2026

# Usage
#     ./scan-misconfig.sh [--dont-output-result] [-i image_link | --tar /path/to/private-image.tar]
# Available options:
#     --dont-output-result              don't output result into console, only into file
#     -i, --image string                only this image will be checked. Example: -i r0binak/cve-2024-21626:v4
#     --tar string                      check local image-tar. Example: --tar /path/to/private-image.tar

# Examples
# https://www.docker.com/blog/docker-security-advisory-multiple-vulnerabilities-in-runc-buildkit-and-moby/
# https://github.com/snyk/leaky-vessels-static-detector/blob/main/internal/rules/rules.go
# ./scan-misconfig.sh -i r0binak/cve-2024-21626:v4

# https://github.com/bgeesaman/malicious-compliance
# ./scan-misconfig.sh -i megabreit/maliciouscompliance:1-os

set -Eeo pipefail

MISCONFIG_REGEX=(
    "/proc/(1|self)/fd/"
    "\--mount=type=cache"
    "\--mount"
    "#*syntax=*docker*"
    "/etc/*-release"
    "ln\S+\.json|\S+\.lock|ln\S+\.txt"
    "\supx\s"
    "ln .*libnvidia"
    "ln .*libdxcore.so"
)
MISCONFIG_MESSAGE=(
    "CVE-2024-21626 runC Escape"
    "CVE-2024-23651 BuildKit cache mounts"
    "CVE-2024-23652 BuildKit mount stub cleaner"
    "CVE-2024-23653 Buildkit's API does not validate entitlements check"
    "malicious-compliance - attempt to avoid OS detection"
    "malicious-compliance - hide language dependency files"
    "malicious-compliance - UPX detected"
    "CVE-2024-0132 nvidia container toolkit escape"
    "CVE-2024-0132 nvidia container toolkit escape"
)
MISCONFIG_URL=(
    "https://nitroc.org/en/posts/cve-2024-21626-illustrated/"
    "https://github.com/advisories/GHSA-m3r6-h7wv-7xxv"
    "https://github.com/advisories/GHSA-4v98-7qmw-rqr8"
    "https://github.com/advisories/GHSA-wr6v-9f75-vh2g"
    "https://github.com/bgeesaman/malicious-compliance/blob/main/docker/Dockerfile-1-os"
    "https://github.com/bgeesaman/malicious-compliance/blob/main/docker/Dockerfile-3-lang"
    "https://github.com/bgeesaman/malicious-compliance/blob/main/docker/Dockerfile-4-bin"
    "https://github.com/ctrsploit/ctrsploit/tree/public/vul/cve-2024-0132"
    "https://github.com/r0binak/CVE-2024-0132"
)

# var init
DONT_OUTPUT_RESULT=false
IMAGE_LINK=''
LOCAL_FILE=''
MISCONFIG_RESULT_MESSAGE=''
MISCONFIG_RESULT=false

C_RED='\033[0;31m'
C_NIL='\033[0m'

EMOJI_DOCKER='\U1F433' # whale

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# get exported var with default value if it is empty
: "${OUT_DIR:=/tmp}"
# check debug mode to debug child scripts
DEBUG=''
if [[ "$-" == *x* ]]; then
    DEBUG='-x '
fi

RES_FILE=$OUT_DIR'/scan-misconfig.result'
rm -f $RES_FILE
touch $RES_FILE

# read the options
ARGS=$(getopt -o i: --long dont-output-result,image:,tar: -n $0 -- "$@")
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
        --tar)
            case "$2" in
                "") shift 2 ;;
                *) LOCAL_FILE=$2 ; shift 2 ;;
            esac ;;     
        --) shift ; break ;;
        *) echo "Wrong usage! Try '$0 --help' for more information." ; exit 2 ;;
    esac
done

# download and unpack image or use cache 
if [ ! -z "$LOCAL_FILE" ]; then
    IMAGE_LINK=$LOCAL_FILE
    /bin/bash $DEBUG$SCRIPTPATH/scan-download-unpack.sh --tar $LOCAL_FILE
else
    /bin/bash $DEBUG$SCRIPTPATH/scan-download-unpack.sh -i $IMAGE_LINK
fi


echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> scan misconfiguration\033[0K\r"

for f in "$OUT_DIR/image"/*.json
do
    for (( i=0; i<${#MISCONFIG_REGEX[@]}; i++ ));
    do
        if grep -Eqi "${MISCONFIG_REGEX[$i]}" $f; then
            # check exclusions
            set +e
            /bin/bash $DEBUG$SCRIPTPATH/check-exclusions.sh -i $IMAGE_LINK --misconfig 12345abcd
            if [[ $? -eq 1 ]] ; then
                if [ "$DONT_OUTPUT_RESULT" == "false" ]; then
                    echo -e "$IMAGE_LINK >>> OK (whitelisted)                      "
                fi    
                echo "OK (whitelisted)" > $RES_FILE
                exit 0
            else    
                MISCONFIG_RESULT=true
                MISCONFIG_RESULT_MESSAGE=$MISCONFIG_RESULT_MESSAGE$'\n   '${MISCONFIG_MESSAGE[$i]}$'\n     '${MISCONFIG_URL[$i]}
            fi
            set -e
        fi
    done
done

# result: output to console and write to file
if [ "$MISCONFIG_RESULT" = true ]; then
    MISCONFIG_RESULT_MESSAGE="$EMOJI_DOCKER $C_RED$IMAGE_LINK$C_NIL >>> detected dangerous misconfiguration"$MISCONFIG_RESULT_MESSAGE 
    if [ "$DONT_OUTPUT_RESULT" == "false" ]; then  
        echo -e "$MISCONFIG_RESULT_MESSAGE"
    fi    
    echo "$MISCONFIG_RESULT_MESSAGE" > $RES_FILE
else
    if [ "$DONT_OUTPUT_RESULT" == "false" ]; then 
        echo "$IMAGE_LINK >>> OK                        "
    fi    
    echo "OK" > $RES_FILE
fi

exit 0
