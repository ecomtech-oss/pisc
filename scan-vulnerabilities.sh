#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2026

# Usage
#     ./scan-vulnerabilities.sh [--dont-output-result] [-i image_link | --tar /path/to/private-image.tar]
# Available options:
#     --dont-output-result              don't output result into console, only into file
#     --epss-and                        use AND logic to combine EPSS score and exploit presence. If disabled, OR logic is applied (default: OR)
#     --epss-min                        minimum EPSS score threshold used for filtering vulnerabilities (default: 0.5)
#     --ignore-errors                   ignore errors (instead, write to $ERROR_FILE)
#     -i, --image string                only this image will be checked. Example: -i kapistka/log4shell:0.0.3-nonroot
#     --offline-feeds                   use a self-contained offline image with pre-downloaded vulnerability feeds (e.g., :latest-feeds)
#     --severity-min                    minimal severity of vulnerabilities (UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL) default [HIGH]
#     --show-exploits                   show information about exploits
#     --tar string                      check local image-tar. Example: --tar /path/to/private-image.tar
#     --trivy-server string             use trivy server if you can. Specify trivy URL, example: --trivy-server http://trivy.something.io:8080
#     --trivy-token string              use trivy server if you can. Specify trivy token, example: --trivy-token 0123456789abZ
#     --vulners-key string              check exploitable vulnerabilities by vulners.com instead of inthewild.io. Specify vulners API-key, example: --vulners-key 0123456789ABCDXYZ
# Example
#     ./scan-vulnerabilities.sh -i kapistka/log4shell:0.0.3-nonroot


set -Eeo pipefail

# var init
DONT_OUTPUT_RESULT=false
EPSS_AND=false
EPSS_MIN="0.5"
IGNORE_ERRORS_FLAG=''
IMAGE_LINK=''
IS_ERROR=false
LOCAL_FILE=''
IS_EXPLOITABLE=false
IS_EXLUDED=false
OFFLINE_FEEDS_FLAG=''
PARAMS_TRIVY=''
PARAMS_GRYPE=''
RESULT_MESSAGE=''
SCANNER='all'
SEVERITY='HIGH'
SHOW_EXPLOITS=false
VULNERS_API_KEY=''

C_RED='\033[0;31m'
C_NIL='\033[0m'
EMOJI_VULN='\U1F41E' # lady beetle
EMOJI_EXCLUDE='\U1F648' # see-no-evil monkey
EMOJI_EXPLOITATION='\U1F480' # SKULL

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# get exported var with default value if it is empty
: "${OUT_DIR:=/tmp}"
# check debug mode to debug child scripts
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

# cve list for exploit analysis
CVE_FILE=$OUT_DIR'/scan-vulnerabilities.cve'
# result this script for main output
RES_FILE=$OUT_DIR'/scan-vulnerabilities.result'
# results of trivy and grype
RES_FILE_TRIVY=$OUT_DIR'/scan-trivy.result'
RES_FILE_GRYPE=$OUT_DIR'/scan-grype.result'
# temp cve file after sorting
SORT_FILE=$OUT_DIR'/scan-vulnerabilities.sort'
# temp cve file before sorting
TMP_FILE=$OUT_DIR'/scan-vulnerabilities.tmp'
# error file
ERROR_FILE=$OUT_DIR'/scan-vulnerabilities.error'
eval "rm -f $RES_FILE $SORT_FILE $TMP_FILE $ERROR_FILE $RES_FILE_TRIVY $RES_FILE_GRYPE"
touch $RES_FILE $RES_FILE_TRIVY $RES_FILE_GRYPE

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
ARGS=$(getopt -o i: --long dont-output-result,epss-and,epss-min:,ignore-errors,image:,scanner:,offline-feeds,severity-min:,show-exploits,tar:,trivy-server:,trivy-token:,vulners-key: -n $0 -- "$@")
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
        --epss-and)
            case "$2" in
                "") shift 1 ;;
                *) EPSS_AND=true ; shift 1 ;;
            esac ;;
        --epss-min)
            case "$2" in
                "") shift 2 ;;
                *) EPSS_MIN=$2 ; shift 2 ;;
            esac ;; 
        --ignore-errors)
            case "$2" in
                "") shift 1 ;;
                *) PARAMS_TRIVY=$PARAMS_TRIVY' --ignore-errors' ; PARAMS_GRYPE=$PARAMS_GRYPE' --ignore-errors' ; IGNORE_ERRORS_FLAG='--ignore-errors' ; shift 1 ;;
            esac ;; 
        -i|--image)
            case "$2" in
                "") shift 2 ;;
                *) PARAMS_TRIVY=$PARAMS_TRIVY' -i '$2 ; PARAMS_GRYPE=$PARAMS_GRYPE' -i '$2 ; IMAGE_LINK=$2 ; shift 2 ;;
            esac ;;
        --offline-feeds)
            case "$2" in
                "") shift 1 ;;
                *) OFFLINE_FEEDS_FLAG='--offline-feeds' ; shift 1 ;;
            esac ;;
        --scanner)
            case "$2" in
                "") shift 2 ;;
                *) SCANNER=$2 ; shift 2 ;;
            esac ;; 
        --severity-min)
            case "$2" in
                "") shift 2 ;;
                *) SEVERITY=$2 ; shift 2 ;;
            esac ;; 
        --show-exploits)
            case "$2" in
                "") shift 1 ;;
                *) SHOW_EXPLOITS=true ; shift 1 ;;
            esac ;;    
        --tar)
            case "$2" in
                "") shift 2 ;;
                *) PARAMS_TRIVY=$PARAMS_TRIVY' --tar '$2 ; PARAMS_GRYPE=$PARAMS_GRYPE' --tar '$2 ; LOCAL_FILE=$2 ; shift 2 ;;
            esac ;;    
        --trivy-server)
            case "$2" in
                "") shift 2 ;;
                *) PARAMS_TRIVY=$PARAMS_TRIVY' --trivy-server '$2 ; shift 2 ;;
            esac ;;  
        --trivy-token)
            case "$2" in
                "") shift 2 ;;
                *) debug_set false ; PARAMS_TRIVY=$PARAMS_TRIVY' --trivy-token '$2 ; debug_set true ; shift 2 ;;
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

# scan
if [ ! -z "$LOCAL_FILE" ]; then
    IMAGE_LINK=$LOCAL_FILE
    /bin/bash $DEBUG$SCRIPTPATH/scan-download-unpack.sh --tar $LOCAL_FILE
else
    /bin/bash $DEBUG$SCRIPTPATH/scan-download-unpack.sh -i $IMAGE_LINK
fi
if [[ "$SCANNER" == "trivy" || "$SCANNER" == "all" ]]; then
    /bin/bash $DEBUG$SCRIPTPATH/scan-trivy.sh $OFFLINE_FEEDS_FLAG $PARAMS_TRIVY
fi
if [[ "$SCANNER" == "grype" || "$SCANNER" == "all" ]]; then
    /bin/bash $DEBUG$SCRIPTPATH/scan-grype.sh $OFFLINE_FEEDS_FLAG $PARAMS_GRYPE
fi

# merge trivy and grype results by awk magic
echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> sort vulnerabilities\033[0K\r"
awk '
{
  cve = $2
  pkg = $1
  sev = $3
  score = $4
  fix = $5

  if (!seen[cve]++) cve_list[++n] = cve

  # uniq PKG
  if (index(pkg_map[cve], pkg) == 0) {
    pkg_map[cve] = (pkg_map[cve] ? pkg_map[cve] "," pkg : pkg)
  }

  # uniq SEVERITY
  if (index(sev_map[cve], sev) == 0) {
    sev_map[cve] = (sev_map[cve] ? sev_map[cve] "/" sev : sev)
  }

  # uniq SCORE
  if (index(score_map[cve], score) == 0) {
    score_map[cve] = (score_map[cve] ? score_map[cve] "/" score : score)
  }

  # uniq FIX
  if (index(fix_map[cve], fix) == 0) {
    fix_map[cve] = (fix_map[cve] ? fix_map[cve] "/" fix : fix)
  }
}
END {
  for (i = 1; i <= n; i++) {
    cve = cve_list[i]
    printf "%s|%s|%s|%s|%s\n", cve, sev_map[cve], score_map[cve], fix_map[cve], pkg_map[cve]
  }
}
' $RES_FILE_TRIVY $RES_FILE_GRYPE > $SORT_FILE

# filtering by severity
if [ "$SEVERITY" = "CRITICAL" ]; then
    awk -F '|' '$2 ~ /CRITICAL/' $SORT_FILE > $TMP_FILE
elif [ "$SEVERITY" = "HIGH" ]; then
    awk -F '|' '$2 ~ /HIGH|CRITICAL/' $SORT_FILE > $TMP_FILE
elif [ "$SEVERITY" = "MEDIUM" ]; then
    awk -F '|' '$2 ~ /MEDIUM|HIGH|CRITICAL/' $SORT_FILE > $TMP_FILE
elif [ "$SEVERITY" = "LOW" ]; then
    awk -F '|' '$2 ~ /LOW|MEDIUM|HIGH|CRITICAL/' $SORT_FILE > $TMP_FILE
elif [ "$SEVERITY" = "UNKNOWN" ]; then
    awk -F '|' '$2 ~ /UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL/' $SORT_FILE > $TMP_FILE
fi

# get result values
LIST_CVE=()
LIST_SEVERITY=()
LIST_SCORE=()
LIST_FIXED=()
LIST_PKG=()
while IFS='|' read -r cve severity score fix package; do
    LIST_CVE+=("$cve")
    LIST_SEVERITY+=("$severity")
    LIST_SCORE+=("$score")
    LIST_FIXED+=("$fix")
    LIST_PKG+=("$package")
done < "$TMP_FILE"
LIST_length=${#LIST_CVE[@]}

# cve file for exploit and epss
cut -d'|' -f1 $TMP_FILE > $CVE_FILE

# exploits
LIST_EXPL=()
if [ "$IS_ERROR" = false ]; then
    # exploit analysis by vulners.com
    if [ ! -z "$VULNERS_API_KEY" ]; then
        debug_set false
        /bin/bash $DEBUG$SCRIPTPATH/scan-vulners-com.sh --dont-output-result -i $IMAGE_LINK --vulners-key $VULNERS_API_KEY $IGNORE_ERRORS_FLAG
        debug_set true
        LIST_EXPL+=($(<$OUT_DIR/scan-vulners-com.result))
    # exploit analysis by inthewild.io
    else
        /bin/bash $DEBUG$SCRIPTPATH/scan-inthewild-io.sh --dont-output-result -i $IMAGE_LINK $OFFLINE_FEEDS_FLAG $IGNORE_ERRORS_FLAG
        LIST_EXPL+=($(<$OUT_DIR/scan-inthewild-io.result))
    fi
fi

# epss
LIST_EPSS=()
if [ "$IS_ERROR" = false ]; then
    /bin/bash $DEBUG$SCRIPTPATH/scan-epss.sh --dont-output-result -i $IMAGE_LINK $OFFLINE_FEEDS_FLAG $IGNORE_ERRORS_FLAG
    while IFS= read -r l; do
        if [[ "$l" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
            l=$(printf "%.2f" "$l")
        else
            l="-"
        fi
        LIST_EPSS+=("$l")
    done < "$OUT_DIR/epss.result"
fi

# filtering by epss, exploit, exlusions
set +e
for (( i=0; i<${LIST_length}; i++ ));
do
    # check epss is valid
    EPSS_VALID=false
    if [[ "${LIST_EPSS[$i]}" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        EPSS_VALID=true
    fi
    # check epss is pass
    EPSS_PASS=false
    if $EPSS_VALID && awk -v a="${LIST_EPSS[$i]}" -v b="$EPSS_MIN" 'BEGIN {exit !(a > b)}'; then
        EPSS_PASS=true
    fi

    if { [ "$EPSS_AND" = true ] && ( [ "${LIST_EXPL[$i]}" == "true" ] && $EPSS_PASS ); } || \
       { [ "$EPSS_AND" != true ] && ( [ "${LIST_EXPL[$i]}" == "true" ] || $EPSS_PASS ); }; then
        # check exclusions
        /bin/bash $DEBUG$SCRIPTPATH/check-exclusions.sh -i $IMAGE_LINK --cve ${LIST_CVE[$i]}
        EXCL_CVE_RESULT=$?
        /bin/bash $DEBUG$SCRIPTPATH/check-exclusions.sh -i $IMAGE_LINK --package ${LIST_PKG[$i]}
        EXCL_PKG_RESULT=$?
        if [[ $EXCL_CVE_RESULT -eq 1 ]] || [[ $EXCL_PKG_RESULT -eq 1 ]]; then
            IS_EXLUDED=true
        else
            IS_EXPLOITABLE=true
            F=$OUT_DIR/${LIST_CVE[$i]}.expl
            if [ -s "$F" ]; then
                EXPL_A_COUNT=$(wc -l < $F)
                EXPL_B_COUNT=$(grep -c '^[[:space:]]*\\U1F480' $F)
            else
                EXPL_A_COUNT=0
                EXPL_B_COUNT=0
            fi
            if [[ $EXPL_B_COUNT -gt 0 ]]; then
                EXPL_A_COUNT=$((EXPL_A_COUNT-EXPL_B_COUNT))
                EXPL_COUNT=$EXPL_A_COUNT"+"$EXPL_B_COUNT
            else
                EXPL_COUNT=$EXPL_A_COUNT
            fi
            RESULT_MESSAGE=$RESULT_MESSAGE$'\n '${LIST_CVE[$i]}' '${LIST_SEVERITY[$i]}' '${LIST_SCORE[$i]}' '${LIST_EPSS[$i]}' '$EXPL_COUNT' '${LIST_FIXED[$i]}' '${LIST_PKG[$i]}
        fi  
    fi	  
done
set -e

# result: output to console and write to file
if [ "$IS_EXPLOITABLE" = true ]; then
    # begin draw beauty table
    RESULT_MESSAGE=" CVE SEVERITY SCORE EPSS EXPL FIX PACKAGE"$RESULT_MESSAGE
    echo "$RESULT_MESSAGE" > $TMP_FILE
    column -t -s' ' $TMP_FILE > $RES_FILE
    sed -i 's/^/ /' $RES_FILE
    RESULT_MESSAGE=$(<$RES_FILE)
    # end draw beauty table
    RESULT_MESSAGE="$EMOJI_VULN $C_RED$IMAGE_LINK$C_NIL >>> detected exploitable vulnerabilities"$'\n'$RESULT_MESSAGE 
    # insert info about exploits
    RESULT_MESSAGE_WITH_EXPL=""
    mapfile -t LINES <<< "$RESULT_MESSAGE"
    for (( i=0; i<${#LINES[@]}; i++ )); do
        RESULT_MESSAGE_WITH_EXPL+="${LINES[$i]}"$'\n'
        if [ "$SHOW_EXPLOITS" = true ]; then
            # ignore 1 and 2 lines
            if [[ $i -gt 1 ]]; then
                CVE_ID=$(echo "${LINES[$i]}" | awk '{print $1}')
                if [[ "$CVE_ID" == CVE-* ]]; then
                    F="$OUT_DIR/$CVE_ID.expl"
                    if [[ -f "$F" ]]; then
                        RESULT_MESSAGE_WITH_EXPL+="$(cat "$F")"$'\n'
                    fi
                fi
            fi
        fi    
    done  
    # whitelist
    if [ "$IS_EXLUDED" == "true" ]; then
        RESULT_MESSAGE_WITH_EXPL=$RESULT_MESSAGE_WITH_EXPL'\n'"$EMOJI_EXCLUDE Some CVEs or packages are whitelisted"
    fi
    echo "$RESULT_MESSAGE_WITH_EXPL" > $RES_FILE
    if [ "$DONT_OUTPUT_RESULT" == "false" ]; then  
        echo -e "$RESULT_MESSAGE_WITH_EXPL"
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
