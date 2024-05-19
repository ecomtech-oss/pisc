#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2024

# Usage
#     ./scan-trivy.sh [--dont-output-result] [-i image_link]
# Available options:
#     --dont-output-result              don't output result into console, only into file
#     -i, --image string                only this image will be checked. Example: -i kapistka/log4shell:0.0.3-nonroot
#     --trivy-server string             use trivy server if you can. Specify trivy URL, example: --trivy-server http://trivy.something.io:8080
#     --trivy-token string              use trivy server if you can. Specify trivy token, example: --trivy-token 0123456789abZ
#     --vulners-key string              check exploitable vulnerabilities by vulners.com instead of inthewild.io. Specify vulners API-key, example: --vulners-key 0123456789ABCDXYZ
# Example
#     ./scan-trivy.sh -i kapistka/log4shell:0.0.3-nonroot


set -Eeo pipefail

# exception handling
error_exit()
{
    echo "$1"
    exit 1
}

# var init
DONT_OUTPUT_RESULT=false
IMAGE_LINK=''
IS_EXPLOITABLE=false
TRIVY_RESULT_MESSAGE=''
TRIVY_SERVER=''
TRIVY_TOKEN=''
VULNERS_API_KEY=''

C_RED='\033[0;31m'
C_NIL='\033[0m'
EMOJI_EXPLOIT='\U1F41E' # lady beetle

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# check debug mode to debug child scripts
DEBUG=''
if [[ "$-" == *x* ]]; then
    DEBUG='-x '
fi

#cve list for exploit analysis
CVE_FILE=$SCRIPTPATH'/scan-trivy.cve'
#trivy output
JSON_FILE=$SCRIPTPATH'/scan-trivy.json'
#result this script for main output
RES_FILE=$SCRIPTPATH'/scan-trivy.result'
#temp cve file after sorting
SORT_FILE=$SCRIPTPATH'/scan-trivy.sort'
#temp cve file before sorting
TMP_FILE=$SCRIPTPATH'/scan-trivy.tmp'
rm -f $CVE_FILE $JSON_FILE $RES_FILE $SORT_FILE $TMP_FILE
touch $CVE_FILE
touch $RES_FILE

# read the options
ARGS=$(getopt -o i: --long dont-output-result,image:,trivy-server:,trivy-token:,--vulners-key -n $0 -- "$@")
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
        --trivy-server)
            case "$2" in
                "") shift 2 ;;
                *) TRIVY_SERVER=$2 ; shift 2 ;;
            esac ;;  
        --trivy-token)
            case "$2" in
                "") shift 2 ;;
                *) TRIVY_TOKEN=$2 ; shift 2 ;;
            esac ;;     
        --vulners-key)
            case "$2" in
                "") shift 2 ;;
                *) VULNERS_API_KEY=$2 ; shift 2 ;;
            esac ;;              
        --) shift ; break ;;
        *) echo "Wrong usage! Try '$0 --help' for more information." ; exit 2 ;;
    esac
done

# download and unpack image or use cache 
/bin/bash $DEBUG$SCRIPTPATH/scan-download-unpack.sh -i $IMAGE_LINK

echo -ne "  $IMAGE_LINK >>> scan vulnerabilities by trivy\033[0K\r"
# if trivy-token is not specified, then use the local database (slow, if the script is in a OCI-image, the CI/CD speed suffers)
if [ -z "$TRIVY_TOKEN" ]; then
    trivy image -f json -o $JSON_FILE --severity CRITICAL --input $SCRIPTPATH/image.tar &>/dev/null \
    || error_exit "$IMAGE_LINK >>> error trivy: please check connection to internet and retry"
# if trivy-token is specified, then we use the trivy-server
else
    trivy image --server $TRIVY_SERVER --timeout 15m --token $TRIVY_TOKEN -f json -o $JSON_FILE --severity CRITICAL --input $SCRIPTPATH/image.tar &>/dev/null \
    || error_exit "$IMAGE_LINK >>> error trivy server"
fi

# get vars
LIST_VULN=(`jq '.Results[]?.Vulnerabilities[]?.VulnerabilityID' $JSON_FILE | cut -c2- | rev | cut -c2- | rev`) \
|| error_exit "$IMAGE_LINK >>> error parsing $JSON_FILE"
LIST_FIXED=(`jq '.Results[]?.Vulnerabilities[]?.FixedVersion' $JSON_FILE | cut -c2- | rev | cut -c2- | rev`) \
|| error_exit "$IMAGE_LINK >>> error parsing $JSON_FILE"
LIST_PKG=(`jq '.Results[]?.Vulnerabilities[]?.PkgName' $JSON_FILE | cut -c2- | rev | cut -c2- | rev`) \
|| error_exit "$IMAGE_LINK >>> error parsing $JSON_FILE"
LIST_length=${#LIST_VULN[@]}

#Sorting the array and removing duplicates CVE+PKG
echo -ne "  $IMAGE_LINK >>> CVE sorting\033[0K\r"
for (( i=0; i<$LIST_length; i++ ));
do
    echo "${LIST_VULN[$i]} ${LIST_FIXED[$i]} ${LIST_PKG[$i]}" >> $TMP_FILE
done
LIST_VULN_SORT=()
LIST_FIXED_SORT=()
LIST_PKG_SORT=()
if [ -f $TMP_FILE ]; then
    sort -u $TMP_FILE > $SORT_FILE
    LIST_VULN_SORT=(`awk '{print $1}' $SORT_FILE`)
    LIST_FIXED_SORT=(`awk '{print $2}' $SORT_FILE`)
    LIST_PKG_SORT=(`awk '{print $3}' $SORT_FILE`)
    LIST_length=${#LIST_VULN_SORT[@]}
    # removing the remaining duplicate CVE with different PKG
    LIST_VULN=()
    LIST_FIXED=()
    LIST_PKG=()
    for (( i=0; i<${LIST_length}; i++ ));
    do
        if [ $i -eq 0 ]; then
            LIST_VULN+=(${LIST_VULN_SORT[0]})
            LIST_FIXED+=(${LIST_FIXED_SORT[0]})
            LIST_PKG+=(${LIST_PKG_SORT[0]})
        elif [ "${LIST_VULN_SORT[$i]}" != "${LIST_VULN_SORT[$i-1]}" ]; then
            LIST_VULN+=(${LIST_VULN_SORT[$i]})
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

LIST_EXPL=()
# exploit analysis by vulners.com
if [ ! -z "$VULNERS_API_KEY" ]; then
    /bin/bash $DEBUG$SCRIPTPATH/scan-vulners-com.sh --dont-output-result -i $IMAGE_LINK --vulners-key $VULNERS_API_KEY
    LIST_EXPL+=($(<$SCRIPTPATH/scan-vulners-com.result))
# exploit analysis by inthewild.io    
else
    /bin/bash $DEBUG$SCRIPTPATH/scan-inthewild-io.sh --dont-output-result -i $IMAGE_LINK
    LIST_EXPL+=($(<$SCRIPTPATH/scan-inthewild-io.result))
fi

# the presence of exploit
for (( i=0; i<${LIST_length}; i++ ));
do
    if [ "${LIST_EXPL[$i]}" == "true" ]; then
        IS_EXPLOITABLE=true
        TRIVY_RESULT_MESSAGE=$TRIVY_RESULT_MESSAGE$'\n '${LIST_VULN[$i]}' '${LIST_FIXED[$i]}' '${LIST_PKG[$i]}
    fi	  
done

# result: output to console and write to file
if [ "$IS_EXPLOITABLE" = true ]; then
    # begin draw beauty table
    TRIVY_RESULT_MESSAGE=" CVE FIX PKG"$TRIVY_RESULT_MESSAGE
    echo "$TRIVY_RESULT_MESSAGE" > $TMP_FILE
    column -t -s' ' $TMP_FILE > $RES_FILE
    TRIVY_RESULT_MESSAGE=$(<$RES_FILE)
    # end draw beauty table
    TRIVY_RESULT_MESSAGE="$EMOJI_EXPLOIT $C_RED$IMAGE_LINK$C_NIL >>> detected exploitable vulnerabilities"$'\n'$TRIVY_RESULT_MESSAGE 
    echo "$TRIVY_RESULT_MESSAGE" > $RES_FILE
    if [ "$DONT_OUTPUT_RESULT" == "false" ]; then  
        echo -e "$TRIVY_RESULT_MESSAGE"
    fi 
else
    if [ "$DONT_OUTPUT_RESULT" == "false" ]; then 
        echo "$IMAGE_LINK >>> OK                        "
    fi    
    echo "OK" > $RES_FILE
fi

exit 0
