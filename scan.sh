#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2024

set -Eeo pipefail

# exception handling
error_exit()
{
    echo "$1"
    exit 1
}

version() {
    echo v0.0.11
}

usage() {
    cat <<EOF

Public OCI-Image Security Checker
Author: @kapistka, 2024

                    ##         .
              ## ## ##        ==
           ## ## #P WN       ===
       /""""""""""""""""\___/ ===
      {        /              /
       \______ o          __/
         |||||\        __/
          |||||\______/

Gives a result = 1 if any:
 - image older then N days
 - has exploitable vulnerabilities
 - contains malware
 - has a dangerous misconfigurations
 - use non-version tag (:latest)

Usage: $(basename "${BASH_SOURCE[0]}") [flags] [image_link or image_list]

Flags:
  -d, --date                      check old build date (365 by default)
  -e, --exploits                  check exploitable vulnerabilities by trivy and inthewild.io
  --d-days int                    check old build date. Specify the number of days for old build date, example: --d-days 180
  -f, --file string               all images from file will be checked. Example: -f images.txt
  -h, --help                      print this help
  -i, --image string              only this image will be checked. Example: -i r0binak/mtkpi:v1.3
  -l, --latest                    check non-version tag (:latest and the same)
  -m, --misconfig                 check dangerous misconfigurations
  --trivy-server string           use trivy server if you can. Specify trivy URL, example: --trivy-server http://trivy.something.io:8080
  --trivy-token string            use trivy server if you can. Specify trivy token, example: --trivy-token 0123456789abZ
  -v, --version                   show version
  --virustotal-key string         check malware by virustotal.com. Specify virustotal API-key, example: --virustotal-key 0123456789abcdef
  --vulners-key string            check exploitable vulnerabilities by vulners.com instead of inthewild.io. Specify vulners API-key, example: --vulners-key 0123456789ABCDXYZ

Examples:
  ./scan.sh --virustotal-key 0123456789abcdef -i r0binak/mtkpi:v1.3
  ./scan.sh -delm -i kapistka/log4shell:0.0.3-nonroot --virustotal-key 0123456789abcdef
  ./scan.sh -delm --trivy-server http://trivy.something.io:8080 --trivy-token 0123abZ --virustotal-key 0123456789abcdef -f images.txt
EOF
}

# var init
CHECK_DATE=false
CHECK_EXPLOITS=false
CHECK_LATEST=false
CHECK_MISCONFIG=false
IMAGE_LINK=''
OLD_BUILD_DAYS=365
SCAN_RETURN_CODE=0
TRIVY_SERVER=''
TRIVY_TOKEN=''
VIRUSTOTAL_API_KEY=''
VULNERS_API_KEY=''
FILE_SCAN=''
IS_LIST_IMAGES=false

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

# read the options
ARGS=$(getopt -o dehf:i:lmv --long date,exploits,d-days:,help,file:,image:,latest,misconfig,trivy-server:,trivy-token:,version,virustotal-key:,vulners-key: -n $0 -- "$@")
eval set -- "$ARGS"

# extract options and their arguments into variables.
while true ; do
    case "$1" in
        -d|--date)
            case "$2" in
                "") shift 1 ;;
                *) CHECK_DATE=true ; shift 1 ;;
            esac ;; 
        --d-days)
            case "$2" in
                "") shift 2 ;;
                *) CHECK_DATE=true ; OLD_BUILD_DAYS=$2 ; shift 2 ;;
            esac ;;
        -e|--exploits)
            case "$2" in
                "") shift 1 ;;
                *) CHECK_EXPLOITS=true ; shift 1 ;;
            esac ;;    
        -h|--help) usage ; exit 0;;
        -f|--file)
            case "$2" in
                "") shift 2 ;;
                *) FILE_SCAN=$2 ; shift 2 ;;
            esac ;;
        -i|--image)
            case "$2" in
                "") shift 2 ;;
                *) IMAGE_LINK=$2 ; shift 2 ;;
            esac ;;   
        -l|--latest )
            case "$2" in
                "") shift 1 ;;
                *) CHECK_LATEST=true ; shift 1 ;;
            esac ;;     
        -m|--misconfig)
            case "$2" in
                "") shift 1 ;;
                *) CHECK_MISCONFIG=true ; shift 1 ;;
            esac ;;  
        --trivy-server)
            case "$2" in
                "") shift 2 ;;
                *) TRIVY_SERVER=$2 ; CHECK_EXPLOITS=true ; shift 2 ;;
            esac ;;  
        --trivy-token)
            case "$2" in
                "") shift 2 ;;
                *) TRIVY_TOKEN=$2 ; CHECK_EXPLOITS=true ; shift 2 ;;
            esac ;; 
        -v|--version) version ; exit 0;;    
        --virustotal-key)
            case "$2" in
                "") shift 2 ;;
                *) VIRUSTOTAL_API_KEY=$2 ; shift 2 ;;
            esac ;;   
        --vulners-key)
            case "$2" in
                "") shift 2 ;;
                *) VULNERS_API_KEY=$2 ; CHECK_EXPLOITS=true ; shift 2 ;;
            esac ;;                           
        --) shift ; break ;;
        *) echo "Wrong usage! Try '$0 --help' for more information." ; exit 2 ;;
    esac
done

# arguments check
if [ ! -z "$FILE_SCAN" ]; then
    if [ -f $FILE_SCAN ]; then
        IS_LIST_IMAGES=true
        LIST_IMAGES=()
        LIST_IMAGES=(`awk '{print $1}' $FILE_SCAN`)
    elif [ -f $SCRIPTPATH'/'$FILE_SCAN ]; then  
        IS_LIST_IMAGES=true
        LIST_IMAGES=()
        LIST_IMAGES=(`awk '{print $1}' $SCRIPTPATH'/'$FILE_SCAN`)   
    else
        echo "$FILE_SCAN >>> File -f not found. Try '$0 --help' for more information."
        exit 2
    fi
else
    if [ -z "$IMAGE_LINK" ]; then 
        echo "Please specify image or file -f. Try '$0 --help' for more information."
        exit 2
    fi  
fi
if [ -z "$TRIVY_SERVER" ] && [ ! -z "$TRIVY_TOKEN" ]; then
    echo "Trivy URL was specified but trivy token not. Try '$0 --help' for more information."
    exit 2
fi
if [ ! -z "$TRIVY_SERVER" ] && [ -z "$TRIVY_TOKEN" ]; then
    echo "Trivy token was specified but trivy URL not. Try '$0 --help' for more information."
    exit 2
fi
if [ "$CHECK_EXPLOITS" = false ] && [ "$CHECK_DATE" = false ] &&  [ "$CHECK_LATEST" = false ] && [ "$CHECK_MISCONFIG" = false ] && [ -z "$VIRUSTOTAL_API_KEY" ]; then
    echo "Nothing check.  Try '$0 --help' for more information."
    exit 2
fi

# single image verification
scan_image() {
    CREATED_DATE='01.01.1970'
    CREATED_DATE_LAST='01.01.1970'
    IS_EXPLOITABLE=false
    IS_HIGH_EPSS=false
    IS_LATEST=false
    IS_MISCONFIG=false
    IS_OLD=false
    IS_MALWARE=false

    # redefine image link (function execute from file-list too)
    IMAGE_LINK=$1
    echo "____________________"

    # non-version tag checking (evolution of "latest")
    if [ "$CHECK_LATEST" = true ]; then
        echo -ne "  $IMAGE_LINK >>> check non version tag\033[0K\r"
        IMAGE_DIGEST=${IMAGE_LINK#*@}
        if [[ $IMAGE_DIGEST != *"@"* ]]; then
            IMAGE_TAG=${IMAGE_LINK#*:}
            if [[ ! $IMAGE_TAG =~ [0-9] ]]; then
                IS_LATEST=true
            fi
        fi
    fi  

    # old build date checking
    if [ "$CHECK_DATE" = true ]; then
        /bin/bash $SCRIPTPATH/scan-date.sh --dont-output-result -i $IMAGE_LINK
        CREATED_DATE=$(<$SCRIPTPATH/scan-date.result)
        CREATED_DATE_LAST=$CREATED_DATE
        # was built more than N days ago
        if [ "$CREATED_DATE" != "0001-01-01" ] && [ "$CREATED_DATE" != "1970-01-01" ]; then
            AGE_DAYS=$(( ($(date +%s) - $(date -d $CREATED_DATE +%s)) / 86400 ))
            if awk "BEGIN {exit !($AGE_DAYS >= $OLD_BUILD_DAYS)}"; then
                IS_OLD=true
            fi
        fi
    fi  

    # misconfigurations scanning
    if [ "$CHECK_MISCONFIG" = true ]; then
        /bin/bash $SCRIPTPATH/scan-misconfig.sh --dont-output-result -i $IMAGE_LINK
        MISCONFIG_RESULT_MESSAGE=$(<$SCRIPTPATH/scan-misconfig.result)
        if [ "$MISCONFIG_RESULT_MESSAGE" != "OK" ]; then
            IS_MISCONFIG=true
        fi
    fi  
    
    # virustotal scanning
    if [ ! -z "$VIRUSTOTAL_API_KEY" ]; then
        /bin/bash $SCRIPTPATH/scan-virustotal.sh --dont-output-result --virustotal-key $VIRUSTOTAL_API_KEY -i $IMAGE_LINK
        VIRUSTOTAL_RESULT_MESSAGE=$(<$SCRIPTPATH/scan-virustotal.result)
        if [ "$VIRUSTOTAL_RESULT_MESSAGE" != "OK" ]; then
            IS_MALWARE=true
        fi
    fi  

    # exploitable vulnerabilities scanning
    if [ "$CHECK_EXPLOITS" = true ]; then
        if [ ! -z "$VULNERS_API_KEY" ]; then
            /bin/bash $SCRIPTPATH/scan-trivy.sh --dont-output-result -i $IMAGE_LINK ----vulners-key $VULNERS_API_KEY
        else
            /bin/bash $SCRIPTPATH/scan-trivy.sh --dont-output-result -i $IMAGE_LINK
        fi    
        TRIVY_RESULT_MESSAGE=$(<$SCRIPTPATH/scan-trivy.result)
        if [ "$TRIVY_RESULT_MESSAGE" != "OK" ]; then
            IS_EXPLOITABLE=true
        fi  
    fi

    # candidates for a new image if it is outdated or there are exploits
    if [ "$IS_OLD" = true ] ||  [ "$IS_EXPLOITABLE" = true ]; then
        /bin/bash $SCRIPTPATH/scan-new-tags.sh --dont-output-result -i $IMAGE_LINK
        CREATED_DATE_LAST=`awk 'NR==1 {print; exit}' $SCRIPTPATH/scan-new-tags.result`
        NEW_TAGS_RESULT_MESSAGE=`awk 'NR>1 {print}' $SCRIPTPATH/scan-new-tags.result`
    fi 


    # result output
    # separating strip for CI
    echo -ne "__________                  \033[0K\r"
    # output of the result by the non-version tag
    if [ "$IS_LATEST" = true ]; then
        echo "$IMAGE_LINK >>> non-version tag                      "
    fi
    # echo misconfig result
    if [ "$IS_MISCONFIG" = true ]; then
        echo "$MISCONFIG_RESULT_MESSAGE"
    fi  
    # echo virustotal result
    if [ "$IS_MALWARE" = true ]; then
        echo "$VIRUSTOTAL_RESULT_MESSAGE"
    fi
    # echo trivy + inthewild (or vulners) result
    if [ "$IS_EXPLOITABLE" = true ]; then
        echo "$TRIVY_RESULT_MESSAGE"
    fi
    # additional output of newest date and newest tags
    if [ "$IS_OLD" = true ] || [ "$IS_EXPLOITABLE" = true ] ; then
        DIFF_DAYS=$(( ($(date -d $CREATED_DATE_LAST +%s) - $(date -d $CREATED_DATE +%s)) / 86400 ))
        if (( $DIFF_DAYS > 0 )); then
            echo "$IMAGE_LINK >>> created: $CREATED_DATE. Last update: $CREATED_DATE_LAST"
            echo "$NEW_TAGS_RESULT_MESSAGE"
        else
            echo "$IMAGE_LINK >>> created: $CREATED_DATE. Find another image"
        fi
    fi 

    # decision logic
    if [ "$IS_OLD" = true ] ||  [ "$IS_EXPLOITABLE" = true ] ||  [ "$IS_MALWARE" = true ] ||  [ "$IS_LATEST" = true ] || [ "$IS_MISCONFIG" = true ]; then
        SCAN_RETURN_CODE=1
    else
        echo "$IMAGE_LINK >>> OK                              "
    fi    
}

# scan list from file
if [ "$IS_LIST_IMAGES" = true ]; then
    for (( j=0; j<${#LIST_IMAGES[@]}; j++ ));
    do
        scan_image "${LIST_IMAGES[j]}"
    done
# scan image from argument
else
    scan_image "$IMAGE_LINK"
fi

exit $SCAN_RETURN_CODE
