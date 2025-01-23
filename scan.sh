#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2025

set -Eeo pipefail

version() {
    echo v0.16.0
}

usage() {
    cat <<EOF

Public OCI-Image Security Checker
Author: @kapistka, 2025

                    ##         .
              ## ## ##        ==
           ## ## #P WN       ===
       /""""""""""""""""\___/ ===
      {        /              /
       \______ o          __/
         |||||\        __/
          |||||\______/

A command-line tool to assess the security of OCI container images.  
Exits with code `1` if any of the following conditions are met:  
  - The image contains malware.  
  - The image has exploitable vulnerabilities.  
  - The image has dangerous build misconfigurations.  
  - The image is older than a specified number of days.  
  - The image uses a non-versioned tag (e.g., `:latest`).  

Usage:
  $(basename "${BASH_SOURCE[0]}") [flags] [-i IMAGE | -f FILE | --tar TARFILE]  

Flags:
  -d, --date                      Check old build date (default: 365 days).
  --d-days <int>                  Specify the number of days for build date check. Example: `--d-days 180`.
  -e, --exploits                  Check for exploitable vulnerabilities using Trivy and inthewild.io.
  -f, --file <string>             Check all images listed in a file. Example: `-f images.txt`.
  -h, --help                      Display this help message.
  --ignore-errors                 Ignore errors from external tools and continue execution.
  -i, --image <string>            Check a specific image. Example: `-i r0binak/mtkpi:v1.4`.
  -l, --latest                    Check for usage of non-versioned tags (e.g., `:latest`).
  -m, --misconfig                 Check for dangerous image misconfigurations.
  --tar <string>                  Check a local TAR file containing image layers.
                                  Example: `--tar /path/to/private-image.tar`.
  --trivy-server <string>         Specify a Trivy-server URL for vulnerability scanning.  
                                  Example: `--trivy-server http://trivy.something.io:8080`. 
  --trivy-token <string>          Provide a Trivy-server API token. Example: `--trivy-token 0123456789abZ`.
  -v, --version                   Display version.
  --virustotal-key <string        Use VirusTotal API to scan for malware.
                                  Example: `--virustotal-key 0123456789abcdef`.
  --vulners-key <string>          Use Vulners.com API instead of inthewild.io for vulnerability scanning.  
                                  Example: `--vulners-key 0123456789ABCDXYZ`.

Examples:
  ./scan.sh --virustotal-key 0123456789abcdef -i r0binak/mtkpi:v1.3
  ./scan.sh -delm -i kapistka/log4shell:0.0.3-nonroot --virustotal-key 0123456789abcdef
  ./scan.sh -delm --trivy-server http://trivy.something.io:8080 --trivy-token 0123abZ --virustotal-key 0123456789abcdef -f images.txt

Additional Notes:
- To authenticate with a registry, refer to `scan-download-unpack.sh#L14`.  
- To configure exclusions for specific CVEs or other criteria, see `check-exclusion.sh#L5`.
EOF
}

# var init
CHECK_DATE=false
CHECK_EXPLOITS=false
CHECK_LATEST=false
CHECK_MISCONFIG=false
FLAG_IMAGE='-i'
IGNORE_ERRORS_FLAG=''
IMAGE_LINK=''
LOCAL_FILE=''
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
C_YLW='\033[0;33m'
C_NIL='\033[0m'
C_RED='\033[0;31m'
EMOJI_ON='\U2795'      # plus
EMOJI_OFF='\U2796'     # minus
EMOJI_OK='\U1F44D'     # thumbs up
EMOJI_NOT_OK='\U1F648' # see-no-evil monkey
EMOJI_LATEST='\U2693'  # anchor
EMOJI_OLD='\U1F4C6'    # tear-off calendar
EMOJI_TAR='\U1F4E6'    # package
EMOJI_LIST='\U1F5D2'   # spiral notepad
EMOJI_DOCKER='\U1F433' # whale

U_LINE2='\U02550\U02550\U02550\U02550\U02550\U02550\U02550\U02550'
U_LINE=$U_LINE2$U_LINE2$U_LINE2$U_LINE2$U_LINE2$U_LINE2

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# remove exclusions cache csv
EXCLUSIONS_FILE=$SCRIPTPATH'/whitelist.yaml'
eval "rm -f $EXCLUSIONS_FILE.csv"

# check debug mode to debug child scripts and external tools
DEBUG=''
if [[ "$-" == *x* ]]; then
    DEBUG='-x '
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

# read the options
debug_set false
ARGS=$(getopt -o dehf:i:lmv --long date,exploits,d-days:,help,file:,ignore-errors,image:,latest,misconfig,tar:,trivy-server:,trivy-token:,version,virustotal-key:,vulners-key: -n $0 -- "$@")
eval set -- "$ARGS"
debug_set true

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
                *) FILE_SCAN=$2 ; CHECK_LOCAL=false ; shift 2 ;;
            esac ;;
        --ignore-errors)
            case "$2" in
                "") shift 1 ;;
                *) IGNORE_ERRORS_FLAG='--ignore-errors' ; shift 1 ;;
            esac ;; 
        -i|--image)
            case "$2" in
                "") shift 2 ;;
                *) IMAGE_LINK=$2 ; CHECK_LOCAL=false ; shift 2 ;;
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
        --tar)
            case "$2" in
                "") shift 2 ;;
                *) LOCAL_FILE=$2 ; shift 2 ;;
            esac ;;   
        --trivy-server)
            case "$2" in
                "") shift 2 ;;
                *) TRIVY_SERVER=$2 ; CHECK_EXPLOITS=true ; shift 2 ;;
            esac ;;  
        --trivy-token)
            case "$2" in
                "") shift 2 ;;
                *)  debug_set false ; TRIVY_TOKEN=$2 ; debug_set true ; CHECK_EXPLOITS=true ; shift 2 ;;
            esac ;; 
        -v|--version) version ; exit 0;;    
        --virustotal-key)
            case "$2" in
                "") shift 2 ;;
                *) debug_set false ; VIRUSTOTAL_API_KEY=$2 ; debug_set true ; shift 2 ;;
            esac ;;   
        --vulners-key)
            case "$2" in
                "") shift 2 ;;
                *) debug_set false ; VULNERS_API_KEY=$2 ; debug_set true ; CHECK_EXPLOITS=true ; shift 2 ;;
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
elif [ ! -z "$LOCAL_FILE" ]; then
    if [ -f $SCRIPTPATH'/'$LOCAL_FILE ]; then
        LOCAL_FILE=$SCRIPTPATH'/'$LOCAL_FILE
    fi
    if [ ! -f $LOCAL_FILE ]; then
        echo "$LOCAL_FILE >>> File --tar not found. Try '$0 --help' for more information."
        exit 2
    else
        # disable check latest tag for local-tar
        CHECK_LATEST=false
        FLAG_IMAGE='--tar'
    fi
else
    if [ -z "$IMAGE_LINK" ]; then
        echo "Please specify image or file -f. Try '$0 --help' for more information."
        exit 2
    fi
fi
# debug exclusions - sensitive data
debug_set false
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
debug_set true

# check tools exist
IS_TOOLS_NOT_EXIST=false
TOOLS_NOT_EXIST_STR=''
LIST_TOOLS=(column curl file find jq sha256sum skopeo tar tr trivy yq)
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
if [ ! -z "$LOCAL_FILE" ]; then
    echo -e "$EMOJI_TAR local file: $LOCAL_FILE"  
elif [ "$IS_LIST_IMAGES" = true ]; then
    echo -e "$EMOJI_LIST images from list: $FILE_SCAN"
elif [ ! -z "$IMAGE_LINK" ]; then
    echo -e "$EMOJI_DOCKER image: $IMAGE_LINK"
fi
EMOJI_OPT=$EMOJI_OFF
debug_set false
if [ ! -z "$VIRUSTOTAL_API_KEY" ]; then
    EMOJI_OPT=$EMOJI_ON
fi
debug_set true
echo -e "   $EMOJI_OPT scan malware"
EMOJI_OPT=$EMOJI_OFF
if [ "$CHECK_EXPLOITS" = true ] ; then
    EMOJI_OPT=$EMOJI_ON
fi
echo -e "   $EMOJI_OPT scan exploitable vulnerabilities"
EMOJI_OPT=$EMOJI_OFF
if [ "$CHECK_MISCONFIG" = true ] ; then
    EMOJI_OPT=$EMOJI_ON
fi
echo -e "   $EMOJI_OPT scan building misconfig"
EMOJI_OPT=$EMOJI_OFF
if [ "$CHECK_DATE" = true ] ; then
    EMOJI_OPT=$EMOJI_ON
fi
echo -e "   $EMOJI_OPT check image is older than a $OLD_BUILD_DAYS days"
EMOJI_OPT=$EMOJI_OFF
if [ "$CHECK_LATEST" = true ] ; then
    EMOJI_OPT=$EMOJI_ON
fi
echo -e "   $EMOJI_OPT check used non-version tag (:latest)"

# single image scan
scan_image() {
    eval "rm -f $SCRIPTPATH/*.error"
    
    CREATED_DATE='1970-01-01'
    CREATED_DATE_LAST='1970-01-01'
    IS_EXCLUDED=false
    IS_EXPLOITABLE=false
    IS_HIGH_EPSS=false
    IS_LATEST=false
    IS_MISCONFIG=false
    IS_OLD=false
    IS_MALWARE=false
    EXCLUDED_STR=''
    LIST_ERRORS=()

    # redefine image link (function execute from file-list too)
    IMAGE_LINK=$1
    echo -e "$U_LINE"

    # non-version tag checking (evolution of "latest")
    if [ "$CHECK_LATEST" = true ]; then
        echo -ne $(date +"%H:%M:%S") "  $IMAGE_LINK >>> check non version tag\033[0K\r"
        IMAGE_DIGEST=${IMAGE_LINK#*@}
        if [[ $IMAGE_DIGEST != *"@"* ]]; then
            IMAGE_TAG=${IMAGE_LINK#*:}
            if [[ ! $IMAGE_TAG =~ [0-9]*[0-9]\.[0-9]*[0-9] ]]; then
                # check exclusions
                set +e
                /bin/bash $DEBUG$SCRIPTPATH/check-exclusions.sh -i $IMAGE_LINK --tag $IMAGE_TAG
                if [[ $? -eq 1 ]] ; then
                    IS_EXCLUDED=true
                    EXCLUDED_STR="${EXCLUDED_STR:+$EXCLUDED_STR$'\n'}   tag whitelisted"
                else
                    IS_LATEST=true
                fi
                set -e
            fi
        fi
    fi

    # misconfigurations scanning
    if [ "$CHECK_MISCONFIG" = true ]; then
        /bin/bash $DEBUG$SCRIPTPATH/scan-misconfig.sh --dont-output-result $FLAG_IMAGE $IMAGE_LINK
        MISCONFIG_RESULT_MESSAGE=$(<$SCRIPTPATH/scan-misconfig.result)
        if [ "$MISCONFIG_RESULT_MESSAGE" != "OK" ] && [ "$MISCONFIG_RESULT_MESSAGE" != "OK (whitelisted)" ]; then
            IS_MISCONFIG=true
        elif [ "$MISCONFIG_RESULT_MESSAGE" == "OK (whitelisted)" ] ; then
            IS_EXCLUDED=true
            EXCLUDED_STR="${EXCLUDED_STR:+$EXCLUDED_STR$'\n'}   misconfig whitelisted" 
        fi
    fi  
    
    # virustotal scanning
    debug_set false
    if [ ! -z "$VIRUSTOTAL_API_KEY" ]; then
        /bin/bash $DEBUG$SCRIPTPATH/scan-virustotal.sh --dont-output-result --virustotal-key $VIRUSTOTAL_API_KEY $FLAG_IMAGE $IMAGE_LINK $IGNORE_ERRORS_FLAG
        VIRUSTOTAL_RESULT_MESSAGE=$(<$SCRIPTPATH/scan-virustotal.result)
        if [ "$VIRUSTOTAL_RESULT_MESSAGE" != "OK" ] && [ "$VIRUSTOTAL_RESULT_MESSAGE" != "OK (whitelisted)" ]; then
            IS_MALWARE=true
        elif [ "$VIRUSTOTAL_RESULT_MESSAGE" == "OK (whitelisted)" ] ; then
            IS_EXCLUDED=true
            EXCLUDED_STR="${EXCLUDED_STR:+$EXCLUDED_STR$'\n'}   malware whitelisted" 
        fi
    fi
    debug_set true  

    # exploitable vulnerabilities scanning
    if [ "$CHECK_EXPLOITS" = true ]; then
        debug_set false
        PARAMS=''
        if [ ! -z "$VULNERS_API_KEY" ]; then
            PARAMS=$PARAMS" --vulners-key $VULNERS_API_KEY"
        fi
        if [ ! -z "$TRIVY_SERVER" ]; then
            PARAMS=$PARAMS" --trivy-server $TRIVY_SERVER --trivy-token $TRIVY_TOKEN"
        fi
        /bin/bash $DEBUG$SCRIPTPATH/scan-trivy.sh --dont-output-result $FLAG_IMAGE $IMAGE_LINK $PARAMS $IGNORE_ERRORS_FLAG
        debug_set true
        TRIVY_RESULT_MESSAGE=$(<$SCRIPTPATH/scan-trivy.result)
        if [ "$TRIVY_RESULT_MESSAGE" != "OK" ] && [ "$TRIVY_RESULT_MESSAGE" != "OK (whitelisted)" ] ; then
            IS_EXPLOITABLE=true
            # force check date if it exploitable
            CHECK_DATE=true
        elif [ "$TRIVY_RESULT_MESSAGE" == "OK (whitelisted)" ] ; then
            IS_EXCLUDED=true
            EXCLUDED_STR="${EXCLUDED_STR:+$EXCLUDED_STR$'\n'}   exploitable vulnerabilities whitelisted" 
        fi  
    fi

    # old build date checking
    # after exploits checking - force CHECK_DATE = true
    if [ "$CHECK_DATE" = true ]; then
        /bin/bash $DEBUG$SCRIPTPATH/scan-date.sh --dont-output-result $FLAG_IMAGE $IMAGE_LINK
        CREATED_DATE=$(<$SCRIPTPATH/scan-date.result)
        CREATED_DATE_LAST=$CREATED_DATE
        # was built more than N days ago
        if [ "$CREATED_DATE" != "0001-01-01" ] && [ "$CREATED_DATE" != "1970-01-01" ]; then
            AGE_DAYS=$(( ($(date +%s) - $(date -d $CREATED_DATE +%s)) / 86400 ))
            # check exclusions
            set +e
            /bin/bash $DEBUG$SCRIPTPATH/check-exclusions.sh -i $IMAGE_LINK --days $AGE_DAYS
            if [[ $? -eq 1 ]] ; then
                IS_EXCLUDED=true
                EXCLUDED_STR="${EXCLUDED_STR:+$EXCLUDED_STR$'\n'}   date whitelisted"
            else
                if awk "BEGIN {exit !($AGE_DAYS >= $OLD_BUILD_DAYS)}"; then
                    IS_OLD=true
                fi
            fi
            set -e
        fi
    fi 

    # candidates for a new image if it is outdated or there are exploits
    if [ -z "$LOCAL_FILE" ]; then
        if [ "$IS_OLD" = true ] ||  [ "$IS_EXPLOITABLE" = true ]; then
            /bin/bash $DEBUG$SCRIPTPATH/scan-new-tags.sh --dont-output-result -i $IMAGE_LINK
            CREATED_DATE_LAST=`awk 'NR==1 {print; exit}' $SCRIPTPATH/scan-new-tags.result`
            NEW_TAGS_RESULT_MESSAGE=`awk 'NR>1 {print}' $SCRIPTPATH/scan-new-tags.result`
        fi 
    fi

    # result output
    # separating strip for CI
    echo -ne "$U_LINE\033[0K\r"
    # output of the result by the non-version tag
    if [ "$IS_LATEST" = true ]; then
        echo -e "$EMOJI_LATEST $C_RED$IMAGE_LINK$C_NIL >>> non-version tag                      "
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

    # show ignored errors
    LIST_ERRORS=($(find "$SCRIPTPATH" -name '*.error' -type f 2>/dev/null))
    if (( ${#LIST_ERRORS[@]} > 0 )); then
        STR_ERRORS=''
        for (( i=0; i<${#LIST_ERRORS[@]}; i++ ));
        do
            STR_ERRORS+=$(<"${LIST_ERRORS[$i]}")$'\n'
        done
        STR_ERRORS="${STR_ERRORS%$'\n'*}"
    fi

    # decision logic
    if [ "$IS_OLD" = true ] ||  [ "$IS_EXPLOITABLE" = true ] ||  [ "$IS_MALWARE" = true ] ||  [ "$IS_LATEST" = true ] || [ "$IS_MISCONFIG" = true ]; then
        SCAN_RETURN_CODE=1
        # show ignored errors
        if (( ${#LIST_ERRORS[@]} > 0 )); then
            echo -e "$EMOJI_NOT_OK $C_YLW$IMAGE_LINK$C_NIL >>> ignored errors:                  "
            echo -e "$STR_ERRORS"
        fi
        # show whitelisted reason
        if [ ! -z "$EXCLUDED_STR" ]; then
            echo -e "$EXCLUDED_STR"
        fi
    else
        if (( ${#LIST_ERRORS[@]} > 0 )) || [ "$IS_EXCLUDED" = true ]; then
            echo -e "$EMOJI_NOT_OK $C_YLW$IMAGE_LINK$C_NIL >>> OK, but                             "
            if [ ! -z "$EXCLUDED_STR" ]; then
                echo -e "$EXCLUDED_STR"
            fi
            if (( ${#LIST_ERRORS[@]} > 0 )); then
                echo -e "$STR_ERRORS"
            fi
        else
            echo -e "$EMOJI_OK $C_GRN$IMAGE_LINK$C_NIL >>> OK                              "
        fi
    fi
}

# scan local-tar
if [ ! -z "$LOCAL_FILE" ]; then
    scan_image "$LOCAL_FILE"
# scan list from file
elif [ "$IS_LIST_IMAGES" = true ]; then
    for (( j=0; j<${#LIST_IMAGES[@]}; j++ ));
    do
        scan_image "${LIST_IMAGES[j]}"
    done
# scan image from argument
else
    scan_image "$IMAGE_LINK"
fi

exit $SCAN_RETURN_CODE
