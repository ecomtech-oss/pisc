#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2025

# Usage
#     ./scan-trivy.sh [--dont-output-result] [-i image_link | --tar /path/to/private-image.tar]
# Available options:
#     --dont-output-result              don't output result into console, only into file
#     --ignore-errors                   ignore trivy errors (instead, write to $ERROR_FILE)
#     -i, --image string                only this image will be checked. Example: -i kapistka/log4shell:0.0.3-nonroot
#     --severity                        severities of vulnerabilities (UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL) default [HIGH,CRITICAL]
#     --tar string                      check local image-tar. Example: --tar /path/to/private-image.tar
#     --trivy-server string             use trivy server if you can. Specify trivy URL, example: --trivy-server http://trivy.something.io:8080
#     --trivy-token string              use trivy server if you can. Specify trivy token, example: --trivy-token 0123456789abZ
#     --vulners-key string              check exploitable vulnerabilities by vulners.com instead of inthewild.io. Specify vulners API-key, example: --vulners-key 0123456789ABCDXYZ
# Example
#     ./scan-trivy.sh -i kapistka/log4shell:0.0.3-nonroot


set -Eeo pipefail

# var init
DONT_OUTPUT_RESULT=false
IGNORE_ERRORS=false
IGNORE_ERRORS_FLAG=''
IMAGE_LINK=''
IS_ERROR=false
LOCAL_FILE=''
IS_EXPLOITABLE=false
IS_EXLUDED=false
SEVERITY='HIGH,CRITICAL'
TRIVY_INPUT=''
TRIVY_RESULT_MESSAGE=''
TRIVY_SERVER=''
TRIVY_TOKEN=''
VULNERS_API_KEY=''

C_RED='\033[0;31m'
C_NIL='\033[0m'
EMOJI_VULN='\U1F41E' # lady beetle
EMOJI_EXCLUDE='\U1F648' # see-no-evil monkey

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# check debug mode to debug child scripts
DEBUG=''
DEBUG_TRIVY='2>/dev/null'
if [[ "$-" == *x* ]]; then
    DEBUG='-x '
    DEBUG_TRIVY='--debug'
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

# cve list for exploit analysis
CVE_FILE=$SCRIPTPATH'/scan-trivy.cve'
# trivy output
JSON_FILE=$SCRIPTPATH'/scan-trivy.json'
# result this script for main output
RES_FILE=$SCRIPTPATH'/scan-trivy.result'
# temp cve file after sorting
SORT_FILE=$SCRIPTPATH'/scan-trivy.sort'
# temp cve file before sorting
TMP_FILE=$SCRIPTPATH'/scan-trivy.tmp'
# error file
ERROR_FILE=$SCRIPTPATH'/scan-trivy.error'
eval "rm -f $CVE_FILE $JSON_FILE $RES_FILE $SORT_FILE $TMP_FILE $ERROR_FILE"
touch $CVE_FILE
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
            exit 1
        fi
    fi
}

# read the options
debug_set false
ARGS=$(getopt -o i: --long dont-output-result,ignore-errors,image:,severity:,tar:,trivy-server:,trivy-token:,vulners-key: -n $0 -- "$@")
eval set -- "$ARGS"
debug_set true

# extract options and their arguments into variables.
while true ; do
    case "$1" in
        --dont-output-result)
            case "$2" in
                "") shift 1 ;;
                *) DONT_OUTPUT_RESULT=true ; shift 1 ;;
            esac ;;
        --ignore-errors)
            case "$2" in
                "") shift 1 ;;
                *) IGNORE_ERRORS=true ; IGNORE_ERRORS_FLAG='--ignore-errors' ; shift 1 ;;
            esac ;; 
        -i|--image)
            case "$2" in
                "") shift 2 ;;
                *) IMAGE_LINK=$2 ; shift 2 ;;
            esac ;;
        --severity)
            case "$2" in
                "") shift 2 ;;
                *) SEVERITY=$2 ; shift 2 ;;
            esac ;; 
        --tar)
            case "$2" in
                "") shift 2 ;;
                *) LOCAL_FILE=$2 ; shift 2 ;;
            esac ;;    
        --trivy-server)
            case "$2" in
                "") shift 2 ;;
                *) TRIVY_SERVER=$2 ; shift 2 ;;
            esac ;;  
        --trivy-token)
            case "$2" in
                "") shift 2 ;;
                *) debug_set false ; TRIVY_TOKEN=$2 ; debug_set true ; shift 2 ;;
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

# download and unpack image or use cache 
if [ ! -z "$LOCAL_FILE" ]; then
    IMAGE_LINK=$LOCAL_FILE
    TRIVY_INPUT=$LOCAL_FILE
    /bin/bash $DEBUG$SCRIPTPATH/scan-download-unpack.sh --tar $LOCAL_FILE
else
    TRIVY_INPUT=$SCRIPTPATH/image.tar
    /bin/bash $DEBUG$SCRIPTPATH/scan-download-unpack.sh -i $IMAGE_LINK
fi

echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> scan vulnerabilities by trivy\033[0K\r"
# if trivy-token is not specified, then use the local database (slow, if the script is in a OCI-image, the CI/CD speed suffers)
debug_set false
if [ -z "$TRIVY_TOKEN" ]; then
    debug_set true
    eval "trivy image --timeout 15m  --scanners vuln -f json -o $JSON_FILE --severity $SEVERITY --input $TRIVY_INPUT $DEBUG_TRIVY" \
    || error_exit "error trivy client"
# if trivy-token is specified, then we use the trivy-server
else
    eval "trivy image --timeout 15m  --scanners vuln --server $TRIVY_SERVER --token $TRIVY_TOKEN -f json -o $JSON_FILE --severity $SEVERITY --input $TRIVY_INPUT $DEBUG_TRIVY" \
    || eval "trivy image --timeout 15m  --scanners vuln -f json -o $JSON_FILE --severity CRITICAL,HIGH --input $TRIVY_INPUT $DEBUG_TRIVY" \
    || error_exit "error trivy server/client"
fi
debug_set true

# get vars
LIST_VULN=()
if [ "$IS_ERROR" = false ]; then
    LIST_VULN=(`jq '.Results[]?.Vulnerabilities[]?.VulnerabilityID' $JSON_FILE 2>/dev/null | cut -c2- | rev | cut -c2- | rev`) \
    || error_exit "error parsing VulnerabilityID $JSON_FILE"
    LIST_SVR=(`jq '.Results[]?.Vulnerabilities[]?.Severity' $JSON_FILE 2>/dev/null | cut -c2- | rev | cut -c2- | rev`) \
    || error_exit "error parsing Severity $JSON_FILE"
    LIST_FIXED=(`jq '.Results[]?.Vulnerabilities[]?.FixedVersion' $JSON_FILE 2>/dev/null | cut -c2- | rev | cut -c2- | rev | sed 's/, /,/g'`) \
    || error_exit "error parsing FixedVersion $JSON_FILE"
    LIST_PKG=(`jq '.Results[]?.Vulnerabilities[]?.PkgName' $JSON_FILE 2>/dev/null | cut -c2- | rev | cut -c2- | rev`) \
    || error_exit "error parsing PkgName $JSON_FILE"
fi    
LIST_length=${#LIST_VULN[@]}

#Sorting the array and removing duplicates CVE+PKG
echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> CVE sorting\033[0K\r"
for (( i=0; i<$LIST_length; i++ ));
do
    if [ "${LIST_FIXED[$i]}" = "ul" ]; then
        LIST_FIXED[$i]='-'
    fi
    echo "${LIST_VULN[$i]} ${LIST_SVR[$i]} ${LIST_FIXED[$i]} ${LIST_PKG[$i]}" >> $TMP_FILE
done
LIST_VULN_SORT=()
LIST_SVR_SORT=()
LIST_FIXED_SORT=()
LIST_PKG_SORT=()
if [ -f $TMP_FILE ]; then
    sort -u $TMP_FILE > $SORT_FILE
    LIST_VULN_SORT=(`awk '{print $1}' $SORT_FILE`)
    LIST_SVR_SORT=(`awk '{print $2}' $SORT_FILE`)
    LIST_FIXED_SORT=(`awk '{print $3}' $SORT_FILE`)
    LIST_PKG_SORT=(`awk '{print $4}' $SORT_FILE`)
    LIST_length=${#LIST_VULN_SORT[@]}
    # removing the remaining duplicate CVE with different PKG
    LIST_VULN=()
    LIST_SVR=()
    LIST_FIXED=()
    LIST_PKG=()
    for (( i=0; i<${LIST_length}; i++ ));
    do
        if [ $i -eq 0 ]; then
            LIST_VULN+=(${LIST_VULN_SORT[0]})
            LIST_SVR+=(${LIST_SVR_SORT[0]})
            LIST_FIXED+=(${LIST_FIXED_SORT[0]})
            LIST_PKG+=(${LIST_PKG_SORT[0]})
        elif [ "${LIST_VULN_SORT[$i]}" != "${LIST_VULN_SORT[$i-1]}" ]; then
            LIST_VULN+=(${LIST_VULN_SORT[$i]})
            LIST_SVR+=(${LIST_SVR_SORT[$i]})
            LIST_FIXED+=(${LIST_FIXED_SORT[$i]})
            LIST_PKG+=(${LIST_PKG_SORT[$i]})	    
        fi	  
    done
    LIST_length=${#LIST_VULN[@]}
fi  

# save result to CVE_FILE for exploit analysis
for (( i=0; i<$LIST_length; i++ ));
do
    echo "${LIST_VULN[$i]}" >> $CVE_FILE
done

LIST_SCORE=()
for (( i=0; i<$LIST_length; i++ ));
do
    L=()
    L=$(jq -r --arg CVE "${LIST_VULN[$i]}" '.Results[]?.Vulnerabilities[]? | select(.VulnerabilityID == $CVE) | .CVSS? // {} | to_entries[]? | .value.V3Score? // empty' "$JSON_FILE") \
    || error_exit "error parsing Score $JSON_FILE"
    [[ -z "$L" ]] && L="-"
    LIST_SCORE+=($(echo "$L" | sort -nr | head -n1))
done

LIST_EXPL=()
if [ "$IS_ERROR" = false ]; then
    # exploit analysis by vulners.com
    if [ ! -z "$VULNERS_API_KEY" ]; then
        debug_set false
        /bin/bash $DEBUG$SCRIPTPATH/scan-vulners-com.sh --dont-output-result -i $IMAGE_LINK --vulners-key $VULNERS_API_KEY $IGNORE_ERRORS_FLAG
        debug_set true
        LIST_EXPL+=($(<$SCRIPTPATH/scan-vulners-com.result))
    # exploit analysis by inthewild.io    
    else
        /bin/bash $DEBUG$SCRIPTPATH/scan-inthewild-io.sh --dont-output-result -i $IMAGE_LINK $IGNORE_ERRORS_FLAG
        LIST_EXPL+=($(<$SCRIPTPATH/scan-inthewild-io.result))
    fi
fi

# the presence of exploit
set +e
for (( i=0; i<${LIST_length}; i++ ));
do
    if [ "${LIST_EXPL[$i]}" == "true" ]; then
        # check exclusions
        /bin/bash $DEBUG$SCRIPTPATH/check-exclusions.sh -i $IMAGE_LINK --cve ${LIST_VULN[$i]}
        EXCL_CVE_RESULT=$?
        /bin/bash $DEBUG$SCRIPTPATH/check-exclusions.sh -i $IMAGE_LINK --package ${LIST_PKG[$i]}
        EXCL_PKG_RESULT=$?
        if [[ $EXCL_CVE_RESULT -eq 1 ]] || [[ $EXCL_PKG_RESULT -eq 1 ]]; then
            IS_EXLUDED=true
        else
            IS_EXPLOITABLE=true
            TRIVY_RESULT_MESSAGE=$TRIVY_RESULT_MESSAGE$'\n '${LIST_VULN[$i]}' '${LIST_SVR[$i]}' '${LIST_SCORE[$i]}' '${LIST_FIXED[$i]}' '${LIST_PKG[$i]}
        fi
    fi	  
done
set -e

# result: output to console and write to file
if [ "$IS_EXPLOITABLE" = true ]; then
    # begin draw beauty table
    TRIVY_RESULT_MESSAGE=" CVE SEVERITY SCORE FIXED PACKAGE"$TRIVY_RESULT_MESSAGE
    echo "$TRIVY_RESULT_MESSAGE" > $TMP_FILE
    column -t -s' ' $TMP_FILE > $RES_FILE
    sed -i 's/^/ /' $RES_FILE
    TRIVY_RESULT_MESSAGE=$(<$RES_FILE)
    # end draw beauty table
    TRIVY_RESULT_MESSAGE="$EMOJI_VULN $C_RED$IMAGE_LINK$C_NIL >>> detected exploitable vulnerabilities"$'\n'$TRIVY_RESULT_MESSAGE 
    # insert info about exploits
    TRIVY_RESULT_MESSAGE_WITH_EXPL=""
    mapfile -t LINES <<< "$TRIVY_RESULT_MESSAGE"
    for (( i=0; i<${#LINES[@]}; i++ )); do
        TRIVY_RESULT_MESSAGE_WITH_EXPL+="${LINES[$i]}"$'\n'
        # ignore 1 and 2 lines
        if [[ $i -gt 1 ]]; then
            CVE_ID=$(echo "${LINES[$i]}" | awk '{print $1}')
            if [[ "$CVE_ID" == CVE-* ]]; then
                F="$SCRIPTPATH/$CVE_ID.expl"
                if [[ -f "$F" ]]; then
                    TRIVY_RESULT_MESSAGE_WITH_EXPL+="$(cat "$F")"$'\n'
                fi
            fi
        fi
    done
    # whitelist
    if [ "$IS_EXLUDED" == "true" ]; then
        TRIVY_RESULT_MESSAGE_WITH_EXPL=$TRIVY_RESULT_MESSAGE_WITH_EXPL'\n'"$EMOJI_EXCLUDE Some CVEs or packages are whitelisted"
    fi
    echo "$TRIVY_RESULT_MESSAGE_WITH_EXPL" > $RES_FILE
    if [ "$DONT_OUTPUT_RESULT" == "false" ]; then  
        echo -e "$TRIVY_RESULT_MESSAGE_WITH_EXPL"
    fi 
else
    if [ "$IS_EXLUDED" == "false" ]; then 
        R="OK"
    else
        R="OK (whitelisted)"
    fi
    if [ "$DONT_OUTPUT_RESULT" == "false" ]; then 
        echo "$IMAGE_LINK >>> $R                 "
    fi    
    echo "$R" > $RES_FILE
fi

exit 0
