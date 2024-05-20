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
    echo v0.0.15
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
 - image contains malware
 - image has exploitable vulnerabilities
 - image has a dangerous build misconfiguration
 - image older then N days
 - use non-version tag (:latest)

Usage: $(basename "${BASH_SOURCE[0]}") [flags] [image_link]

Flags:
  -d, --date                      check old build date (365 by default)
  --d-days int                    check old build date. Specify the number of days for old build date, example: --d-days 180
  -e, --exploits                  check exploitable vulnerabilities by trivy and inthewild.io
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

C_BLU='\033[1;34m'
C_GRN='\033[1;32m'
C_NIL='\033[0m'
C_RED='\033[0;31m'
#EMOJI_ON='\U2705' # white heavy check mark
#EMOJI_OFF='\U274C' # cross mark 
EMOJI_ON='\U2795' # plus
EMOJI_OFF='\U2796' # minus
EMOJI_OK='\U1F44D' # thumbs up
EMOJI_LATEST='\U1F504' # anticlockwise downwards and upwards open circle arrows
EMOJI_OLD='\U1F4C6' # tear-off calendar

U_LINE2='\U02550\U02550\U02550\U02550\U02550\U02550\U02550\U02550'
U_LINE=$U_LINE2$U_LINE2$U_LINE2$U_LINE2$U_LINE2

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# check debug mode to debug child scripts
DEBUG=''
if [[ "$-" == *x* ]]; then
    DEBUG='-x '
fi

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

# check tools exist
IS_TOOLS_NOT_EXIST=false
TOOLS_NOT_EXIST_STR=''
LIST_TOOLS=(column curl file find jq sha256sum skopeo tar trivy)
for (( i=0; i<${#LIST_TOOLS[@]}; i++ ));
do
    if ! command -v ${LIST_TOOLS[$i]} &> /dev/null
    then
        IS_TOOLS_NOT_EXIST=true
        TOOLS_NOT_EXIST_STR=$TOOLS_NOT_EXIST_STR$'\n  '${LIST_TOOLS[$i]}
    fi
done
if [ "$IS_TOOLS_NOT_EXIST" = true ] ; then
    echo "First you need to install these tools:$TOOLS_NOT_EXIST_STR"
    exit 3
fi   

# check GNU-version of tar
if ! `tar --version | grep -q "GNU"`; then
    echo "You need to install GNU-version of tar"
    exit 3
fi

# show enable/disable options
echo -e "$U_LINE"
EMOJI_OPT=$EMOJI_OFF
if [ ! -z "$VIRUSTOTAL_API_KEY" ]; then
    EMOJI_OPT=$EMOJI_ON
fi
echo -e "$EMOJI_OPT scan malware"
EMOJI_OPT=$EMOJI_OFF
if [ "$CHECK_EXPLOITS" = true ] ; then
    EMOJI_OPT=$EMOJI_ON
fi
echo -e "$EMOJI_OPT scan exploitable vulnerabilities"
EMOJI_OPT=$EMOJI_OFF
if [ "$CHECK_MISCONFIG" = true ] ; then
    EMOJI_OPT=$EMOJI_ON
fi
echo -e "$EMOJI_OPT scan building misconfig"
EMOJI_OPT=$EMOJI_OFF
if [ "$CHECK_DATE" = true ] ; then
    EMOJI_OPT=$EMOJI_ON
fi
echo -e "$EMOJI_OPT check image older then $OLD_BUILD_DAYS days"
EMOJI_OPT=$EMOJI_OFF
if [ "$CHECK_LATEST" = true ] ; then
    EMOJI_OPT=$EMOJI_ON
fi
echo -e "$EMOJI_OPT check used non-version tag (:latest)"

# single image verification
scan_image() {
    CREATED_DATE='1970-01-01'
    CREATED_DATE_LAST='1970-01-01'
    IS_EXPLOITABLE=false
    IS_HIGH_EPSS=false
    IS_LATEST=false
    IS_MISCONFIG=false
    IS_OLD=false
    IS_MALWARE=false

    # redefine image link (function execute from file-list too)
    IMAGE_LINK=$1
    echo -e "$U_LINE"

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

    # misconfigurations scanning
    if [ "$CHECK_MISCONFIG" = true ]; then
        /bin/bash $DEBUG$SCRIPTPATH/scan-misconfig.sh --dont-output-result -i $IMAGE_LINK
        MISCONFIG_RESULT_MESSAGE=$(<$SCRIPTPATH/scan-misconfig.result)
        if [ "$MISCONFIG_RESULT_MESSAGE" != "OK" ]; then
            IS_MISCONFIG=true
        fi
    fi  
    
    # virustotal scanning
    if [ ! -z "$VIRUSTOTAL_API_KEY" ]; then
        /bin/bash $DEBUG$SCRIPTPATH/scan-virustotal.sh --dont-output-result --virustotal-key $VIRUSTOTAL_API_KEY -i $IMAGE_LINK
        VIRUSTOTAL_RESULT_MESSAGE=$(<$SCRIPTPATH/scan-virustotal.result)
        if [ "$VIRUSTOTAL_RESULT_MESSAGE" != "OK" ]; then
            IS_MALWARE=true
        fi
    fi  

    # exploitable vulnerabilities scanning
    if [ "$CHECK_EXPLOITS" = true ]; then
        PARAMS=''
        if [ ! -z "$VULNERS_API_KEY" ]; then
            PARAMS=$PARAMS" --vulners-key $VULNERS_API_KEY"
        fi
        if [ ! -z "$TRIVY_SERVER" ]; then
            PARAMS=$PARAMS" --trivy-server $TRIVY_SERVER --trivy-token $TRIVY_TOKEN"
        fi
        /bin/bash $DEBUG$SCRIPTPATH/scan-trivy.sh --dont-output-result -i $IMAGE_LINK $PARAMS
        TRIVY_RESULT_MESSAGE=$(<$SCRIPTPATH/scan-trivy.result)
        if [ "$TRIVY_RESULT_MESSAGE" != "OK" ]; then
            IS_EXPLOITABLE=true
            # force check date if it exploitable
            CHECK_DATE=true
        fi  
    fi

    # old build date checking
    # after exploits checking - force CHECK_DATE = true
    if [ "$CHECK_DATE" = true ]; then
        /bin/bash $DEBUG$SCRIPTPATH/scan-date.sh --dont-output-result -i $IMAGE_LINK
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

    # candidates for a new image if it is outdated or there are exploits
    if [ "$IS_OLD" = true ] ||  [ "$IS_EXPLOITABLE" = true ]; then
        /bin/bash $DEBUG$SCRIPTPATH/scan-new-tags.sh --dont-output-result -i $IMAGE_LINK
        CREATED_DATE_LAST=`awk 'NR==1 {print; exit}' $SCRIPTPATH/scan-new-tags.result`
        NEW_TAGS_RESULT_MESSAGE=`awk 'NR>1 {print}' $SCRIPTPATH/scan-new-tags.result`
    fi 


    # result output
    # separating strip for CI
    echo -ne "$U_LINE\033[0K\r"
    # output of the result by the non-version tag
    if [ "$IS_LATEST" = true ]; then
        echo -e "$C_RED$IMAGE_LINK$C_NIL >>> $EMOJI_LATEST non-version tag                      "
    fi
    # echo misconfig result
    if [ "$IS_MISCONFIG" = true ]; then
        echo -e "$MISCONFIG_RESULT_MESSAGE"
    fi  
    # echo virustotal result
    if [ "$IS_MALWARE" = true ]; then
        echo -e "$VIRUSTOTAL_RESULT_MESSAGE"
    fi
    # echo trivy + inthewild (or vulners) result
    if [ "$IS_EXPLOITABLE" = true ]; then
        echo -e "$TRIVY_RESULT_MESSAGE"
    fi
    # additional output of newest date and newest tags
    if [ "$IS_OLD" = true ] || [ "$IS_EXPLOITABLE" = true ] ; then
        DIFF_DAYS=$(( ($(date -d $CREATED_DATE_LAST +%s) - $(date -d $CREATED_DATE +%s)) / 86400 ))
        if (( $DIFF_DAYS > 0 )); then
            echo -e "$EMOJI_OLD $C_RED$IMAGE_LINK$C_NIL >>> created: $CREATED_DATE. Last update: $CREATED_DATE_LAST"
            echo -e "$NEW_TAGS_RESULT_MESSAGE"
        else
            echo -e "$EMOJI_OLD $C_RED$IMAGE_LINK$C_NIL >>> created: $CREATED_DATE. Find another image"
        fi
    fi 

    # decision logic
    if [ "$IS_OLD" = true ] ||  [ "$IS_EXPLOITABLE" = true ] ||  [ "$IS_MALWARE" = true ] ||  [ "$IS_LATEST" = true ] || [ "$IS_MISCONFIG" = true ]; then
        SCAN_RETURN_CODE=1
    else
        echo -e "$EMOJI_OK $C_GRN$IMAGE_LINK$C_NIL >>> OK                              "
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