#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2026

# Usage
#     ./scan-virustotal.sh [--dont-adv-search] [--dont-output-result] [-i image_link | --tar /path/to/private-image.tar] --virustotal-key API_KEY
# Available options:
#     --dont-adv-search                 don't use advanced malware search inside layer
#     --dont-output-result              don't output result into console, only into file
#     --ignore-errors                   ignore virustotal errors (instead, write to $ERROR_FILE)
#     -i, --image string                only this image will be checked. Example: -i r0binak/mtkpi:v1.3
#     --tar string                      check local image-tar. Example: --tar /path/to/private-image.tar
#     --virustotal-key string           specify virustotal API-key, example: ---virustotal-key 0123456789abcdef
# Example
#     ./scan-virustotal.sh --virustotal-key 0123456789abcdef -i r0binak/mtkpi:v1.3


set -Eeo pipefail

#popular linux MIME-types exclude from malware analysis
EXCLUDE_MIMES=(
    "application/x-gettext-translation"
    "application/x-terminfo"
    "application/x-terminfo2"
    "application/x-tex-tfm"
    "text/x-asm"
    "text/x-c"
    "text/x-c++"
    "text/x-java"
    "text/x-makefile"
    "text/x-tex"
)
# var init (can be changed)
# list of false positive vendors
FALSE_POSITIVE_VENDOR=(
    "TrendMicro-HouseCall"
)
# waiting between requests
REQUEST_LIMIT=false
# wait while virustotal analyzes the image (seconds)
MAX_ANALYSIS_TIME=900
# if a limited account is used, then after 4 requests, wait as many seconds
SLEEP_TIME_AFTER_LIMIT=60

# var init
DONT_ADV_SEARCH=false
DONT_OUTPUT_RESULT=false
IGNORE_ERRORS=false
IMAGE_LINK=''
LOCAL_FILE=''
IS_BIG_LAYER_REDUCE=false
IS_ERROR=false
IS_OK=true
API_KEY=''
REQUEST_COUNT=0

C_RED='\033[0;31m'
C_BLU='\033[1;34m'
C_NIL='\033[0m'

EMOJI_SLEEP='\U1F4A4' # zzz
EMOJI_MALWARE='\U1F344' # mushroom
EMOJI_DEFAULT='\U1F4A9' # shit
EMOJI_OK='\U1F44D' # thumbs up
EMOJI_NAMES=(
    'vulnerabil'
    'ploit'
    'meter'
    'crypto'
    'miner'
    'hack'
    'tool'
    'backdoor'
    'trojan'
    'worm'
    'virus'
)
EMOJI_CODES=(
    '\U1F41E' # bug
    '\U1F419' # octopus
    '\U1F419' # octopus
    '\U1F511' # key
    '\U1F4B0' # money
    '\U1F47E' # alien
    '\U1F47E' # alien
    '\U1F434' # horse
    '\U1F434' # horse
    '\U1F41B' # worm
    '\U1F9EC' # dna
)

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# get exported var with default value if it is empty
: "${OUT_DIR:=/tmp}"
# check debug mode to debug child scripts and external tools
DEBUG=''
DEBUG_CURL='-sf '
DEBUG_TAR='2>/dev/null'
if [[ "$-" == *x* ]]; then
    DEBUG='-x '
    DEBUG_CURL=''
    DEBUG_TAR=''
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
# silent mode for external tools if not debug
debug_null() {
    if [[ "$-" != *x* ]]; then 
        eval &>/dev/null
    fi    
}


IMAGE_DIR=$OUT_DIR'/image'
ADVANCED_DIR=$OUT_DIR'/advanced'

JSON_RELATIONSHIP_FILE=$OUT_DIR'/virustotal-rel.json'
JSON_SEARCH_FILE=$OUT_DIR'/virustotal.json'
URL_FILE=$OUT_DIR'/virustotal-url.json'
UPLOAD_JSON_FILE=$OUT_DIR'/virustotal-upload.json'
RES_FILE=$OUT_DIR'/scan-virustotal.result'
TMP_FILE=$OUT_DIR'/virustotal.tmp'
SORT_FILE=$OUT_DIR'/virustotal.sort'
ERROR_FILE=$OUT_DIR'/scan-virustotal.error'
eval "rm -f $RES_FILE $ERROR_FILE"

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
ARGS=$(getopt -o i: --long dont-adv-search,dont-output-result,ignore-errors,image:,virustotal-key:,tar: -n $0 -- "$@")
eval set -- "$ARGS"
debug_set true

# extract options and their arguments into variables.
while true ; do
    case "$1" in
        --dont-adv-search)
            case "$2" in
                "") shift 1 ;;
                *) DONT_ADV_SEARCH=true ; shift 1 ;;
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
        --tar)
            case "$2" in
                "") shift 2 ;;
                *) LOCAL_FILE=$2 ; shift 2 ;;
            esac ;;  
        --virustotal-key)
            case "$2" in
                "") shift 2 ;;
                *) debug_set false ; API_KEY=$2 ; debug_set true ; shift 2 ;;
            esac ;; 
        --) shift ; break ;;
        *) echo "Wrong usage! Try '$0 --help' for more information." ; exit 2 ;;
    esac
done

# waiting between requests on virustotal - limit on some free account methods.
# Enabled by REQUEST_LIMIT=true
# 1 minute delay after 4 requests
quota_sleep() {
    # if there is no limit of 4 requests per minute during testing
    # or there is a premium-API-key
    # by default there will be no waiting.
    # if restrictions are observed, change REQUEST_LIMIT=true
    if [ "$REQUEST_LIMIT" = true ]; then 
        if [ $(( $REQUEST_COUNT % 4 )) -eq 0 ] && (( $REQUEST_COUNT > 0 )); then
            for (( ii=0; ii<$SLEEP_TIME_AFTER_LIMIT; ii++ ));
            do
                echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> virustotal - wait $(($SLEEP_TIME_AFTER_LIMIT-$ii)) sec (account limit) $EMOJI_SLEEP\033[0K\r" 
                sleep 1
            done
        fi  
    fi
}  

false_positive_vendors_remove() {
    # begin remove elements from a bash array
    for DEL in "${FALSE_POSITIVE_VENDOR[@]}"; do
        for iii in "${!VENDORS[@]}"; do
            if [[ ${VENDORS[iii]} = $DEL ]]; then
                unset 'VENDORS[iii]'
            fi
        done
    done
    for iii in "${!VENDORS[@]}"; do
        VENDORS_TEMP+=( "${VENDORS[iii]}" )
    done
    VENDORS=("${VENDORS_TEMP[@]}")
    unset VENDORS_TEMP
    # end remove elements from a bash array
}

# hash searching at virustotal function
# use before upload files to virustotal
# hash_search SHA256
hash_search() {
    SEARCH_RESULT='unknown'
    # 1 minute delay after 4 requests is the limit of the free virustotal account
    quota_sleep
    # increasing the request counter (this method is limited by the number per minute/day/month)
    REQUEST_COUNT=$((REQUEST_COUNT+1)) 
    debug_set false
    curl --connect-timeout 10 $DEBUG_CURL --request GET \
        --url "https://www.virustotal.com/api/v3/search?query=$1" \
        --header "x-apikey: $API_KEY" \
        -o "$JSON_SEARCH_FILE" \
        || error_exit "error virustotal.com: please check api-key, internet connection and retry"            
    debug_set true

    # check that the scan is completed by last_analysis_date
    LAST_ANALYSIS_DATE=`jq -r '.data[]?.attributes?.last_analysis_date?' $JSON_SEARCH_FILE` \
        || error_exit "error virustotal.com: please check api-key"
    if [ ! -z "$LAST_ANALYSIS_DATE" ]; then
        
        # get vendors detected malware
        VENDORS=()
        VENDORS+=(`jq -r '.data[]?.attributes?.last_analysis_results?[]? | (select(.category == "malicious")) | .engine_name' $JSON_SEARCH_FILE`) \
            || error_exit "error virustotal.com: please check api-key"
        false_positive_vendors_remove
        # if vendors count (after false positive vendors remove) > 0 then result is bad
        if [ ${#VENDORS[@]} -gt 0 ] ; then  
            SEARCH_RESULT='bad'
        else 
            SEARCH_RESULT='good'   
        fi
    fi    
} 

# analysis searching at virustotal function
# use after upload files to virustotal (not consuming quota of free public API)
# analysis_search UPLOAD_ID
analysis_search() {
    SEARCH_RESULT='upload'
    debug_set false
    curl --connect-timeout 10 $DEBUG_CURL --request GET \
        --url "https://www.virustotal.com/api/v3/analyses/$1" \
        --header "x-apikey: $API_KEY" \
        -o "$JSON_SEARCH_FILE" \
        || error_exit "error virustotal.com: please check api-key, internet connection and retry"            
    debug_set true
    # check that the scan is completed by status
    ANALYSIS_STATUS=`jq -r '.data?.attributes?.status?' $JSON_SEARCH_FILE` \
        || error_exit "error virustotal.com: please check api-key" 
    if [ "$ANALYSIS_STATUS" == "completed" ]; then 
        # get vendors detected malware
        VENDORS=()
        VENDORS+=(`jq -r '.data?.attributes?.results?[]? | (select(.category == "malicious")) | .engine_name' $JSON_SEARCH_FILE`) || error_exit "error virustotal.com: please check api-key"
        false_positive_vendors_remove
        # if vendors count (after false positive vendors remove) > 0 then result is bad
        if [ ${#VENDORS[@]} -gt 0 ] ; then  
            SEARCH_RESULT='bad'
        else 
            SEARCH_RESULT='good'   
        fi
    else
        # analysis in progress
        IS_ANALYSIS_COMPLETE=false    
    fi    
}

# relationship searching at virustotal
# use after advanced upload files to virustotal
# relationship_search SHA256
relationship_search() {
    SEARCH_RELATIONS_RESULT=()
    # 1 minute delay after 4 requests is the limit of the free virustotal account
    quota_sleep
    # increasing the request counter (this method is limited by the number per minute/day/month)
    REQUEST_COUNT=$((REQUEST_COUNT+1)) 
    debug_set false
    curl --connect-timeout 10 $DEBUG_CURL --request GET \
        --url "https://www.virustotal.com/api/v3/files/$1/bundled_files?limit=40" \
        --header "x-apikey: $API_KEY" \
        -o "$JSON_RELATIONSHIP_FILE" \
        || error_exit "error virustotal.com: please check api-key, internet connection and retry"
    debug_set true    
    REL_STAT=()
    REL_PATH=()
    REL_PATH+=(`jq -r '.data[]? | (select(.attributes?.last_analysis_stats?.malicious? != 0)) | .context_attributes?.filename?' $JSON_RELATIONSHIP_FILE`) || error_exit "error virustotal.com: please check api-key"
    REL_ID=()
    REL_ID+=(`jq -r '.data[]? | (select(.attributes?.last_analysis_stats?.malicious? != 0)) | .id' $JSON_RELATIONSHIP_FILE`) || error_exit "error virustotal.com: please check api-key"
    REL_LABEL=()
    REL_LABEL+=(`jq -r '.data[]? | (select(.attributes?.last_analysis_stats?.malicious? != 0)) | .attributes?.popular_threat_classification?.suggested_threat_label?' $JSON_RELATIONSHIP_FILE`) || error_exit "error virustotal.com: please check api-key"
    REL_MALICIOUS=()  
    REL_MALICIOUS+=(`jq -r '.data[]? | (select(.attributes?.last_analysis_stats?.malicious? != 0)) | .attributes?.last_analysis_stats?.malicious?' $JSON_RELATIONSHIP_FILE`) || error_exit "error virustotal.com: please check api-key"
    REL_SUSPICIOUS=()  
    REL_SUSPICIOUS+=(`jq -r '.data[]? | (select(.attributes?.last_analysis_stats?.malicious? != 0)) | .attributes?.last_analysis_stats?.suspicious?' $JSON_RELATIONSHIP_FILE`) || error_exit "error virustotal.com: please check api-key"
    REL_UNDETECTED=()  
    REL_UNDETECTED+=(`jq -r '.data[]? | (select(.attributes?.last_analysis_stats?.malicious? != 0)) | .attributes?.last_analysis_stats?.undetected?' $JSON_RELATIONSHIP_FILE`) || error_exit "error virustotal.com: please check api-key"
    REL_HARMLESS=()  
    REL_HARMLESS+=(`jq -r '.data[]? | (select(.attributes?.last_analysis_stats?.malicious? != 0)) | .attributes?.last_analysis_stats?.harmless?' $JSON_RELATIONSHIP_FILE`) || error_exit "error virustotal.com: please check api-key"
    for (( ii=0; ii<${#REL_ID[@]}; ii++ ));
    do
        # get vendors detected malware
        VENDORS=()
        VENDORS+=(`jq -r '.data[]? | (select(.id == "'${REL_ID[$ii]}'")) | .attributes?.last_analysis_results?[]? | (select(.category == "malicious")) | .engine_name?' $JSON_RELATIONSHIP_FILE`) || error_exit "error virustotal.com: please check api-key"
        false_positive_vendors_remove
       
        # if vendors count (after false positive vendors remove) > 0 then result is bad
        if [ ${#VENDORS[@]} -gt 0 ] ; then  
            # get name if path empty
            if [ "${REL_PATH[$ii]}" == 'null' ]; then
                REL_PATH[$ii]=`jq -r '.data[]? | (select(.id == "'${REL_ID[$ii]}'")) | .attributes?.meaningful_name?' $JSON_RELATIONSHIP_FILE` || error_exit "error virustotal.com: please check api-key"
            fi
            # if path very long then cut it
            if [ ${#REL_PATH[$ii]} -gt 70 ] ; then 
                c=${#REL_PATH[$ii]}-70
                REL_PATH[$ii]=".."${REL_PATH[$ii]:$c} 
            fi

            REL_COUNT=0
            REL_COUNT=$(( $REL_COUNT + ${REL_MALICIOUS[$ii]} ))
            REL_COUNT=$(( $REL_COUNT + ${REL_SUSPICIOUS[$ii]} )) 
            REL_COUNT=$(( $REL_COUNT + ${REL_UNDETECTED[$ii]} )) 
            REL_COUNT=$(( $REL_COUNT + ${REL_HARMLESS[$ii]} )) 
            REL_STAT[$ii]="${REL_MALICIOUS[$ii]}/$REL_COUNT"

            # search malware name if label is null
            if [ "${REL_LABEL[$ii]}" == 'null' ]; then
                REL_LABEL[$ii]='?'
                REL_MALWARE_NAME_LIST=()
                REL_MALWARE_NAME_LIST+=(`jq -r '.data[]? | (select(.id == "'${REL_ID[$ii]}'")) | .attributes?.last_analysis_results?[]? | (select(.category == "malicious")) | .result?' $JSON_RELATIONSHIP_FILE`) || error_exit "error virustotal.com: please check api-key"
                # set the longest malware name for label =)
                for (( jj=0; jj<${#REL_MALWARE_NAME_LIST[@]}; jj++ ));
                do
                if (( ${#REL_MALWARE_NAME_LIST[$jj]} > ${#REL_LABEL[$ii]} )); then
                    REL_LABEL[$ii]=${REL_MALWARE_NAME_LIST[$jj]}
                fi
                done
            fi

            # check known_distributors - false positive
            REL_KNOWN_DISTRIBUTORS=`jq -r '.data[]? | (select(.id == "'${REL_ID[$ii]}'")) | .attributes?.known_distributors?.distributors?[]?' $JSON_RELATIONSHIP_FILE` || error_exit "error virustotal.com: please check api-key"
            # malicious count must be less than 2
            if [[ ! -z "$REL_KNOWN_DISTRIBUTORS" ]] && [[  "${REL_MALICIOUS[$ii]}" -lt 2 ]]; then 
                REL_LABEL[$ii]='file-distributed-by-'$REL_KNOWN_DISTRIBUTORS
                REL_LABEL[$ii]=$C_BLU${REL_LABEL[$ii]}$C_NIL
                # add OK-emoji to label
                REL_LABEL[$ii]=$EMOJI_OK' '${REL_LABEL[$ii]}
            else
                # add emoji to label
                shopt -s nocasematch
                IS_EMOJI=false
                for (( jj=0; jj<${#EMOJI_NAMES[@]}; jj++ ));
                do
                    if [[ ${REL_LABEL[$ii]} =~ ${EMOJI_NAMES[$jj]} ]]; then
                        REL_LABEL[$ii]=${EMOJI_CODES[$jj]}' '${REL_LABEL[$ii]}
                        IS_EMOJI=true
                        break
                    fi
                done
                if [ "$IS_EMOJI" = false ]; then
                    REL_LABEL[$ii]=$EMOJI_DEFAULT' '${REL_LABEL[$ii]}
                fi
            fi
            SEARCH_RELATIONS_RESULT+=("${REL_PATH[$ii]} ${REL_STAT[$ii]} ${REL_LABEL[$ii]}")
        fi    
    done
} 

# upload to virustotal function
# use after hash searching
# upload file_path
upload() {
    UPLOAD_RESULT=''
    # if file size is too big to download (>650 MB) - we do not upload it
    if [[ $(stat -c%s "$1") -gt 629145600 ]]; then
        UPLOAD_RESULT='big'
    else  
        # show human readable size of file
        echo -ne "  $(date +"%H:%M:%S") $ECHO_MESSAGE (`stat -c%s "$1" | numfmt --to=iec`)\033[0K\r"
        # if file size is less than 32 MB, then we use the usual url for uploading
        if [[ $(stat -c%s "$1") -lt 33554432 ]]; then
            UPLOAD_URL='https://www.virustotal.com/api/v3/files'
        # if file size is more than 32 MB, but less than 650 MB, request a special url for uploading
        else
            # this method is not limited to a free account, so we do not include waiting
            debug_set false
            curl --connect-timeout 10 $DEBUG_CURL --request GET \
                --url https://www.virustotal.com/api/v3/files/upload_url \
                --header "x-apikey: $API_KEY" \
                -o "$URL_FILE" \
                || error_exit "error virustotal.com: please check api-key, internet connection and retry"
            debug_set true    
            UPLOAD_URL=`jq -r '.data' $URL_FILE` \
                || error_exit "error virustotal.com: please check api-key"
        fi
        # 1 minute delay after 4 requests is the limit of the free virustotal account
        quota_sleep
        # increasing the request counter (this method is limited by the number per minute/day/month)
        REQUEST_COUNT=$((REQUEST_COUNT+1))    
        # upload the file to the desired url
        # method returns the id of the uploaded file

        debug_set false
        curl --connect-timeout 10 $DEBUG_CURL --request POST \
            --url "$UPLOAD_URL" \
            --header "accept: application/json" \
            --header "content-type: multipart/form-data" \
            --header "x-apikey: $API_KEY" \
            -o "$UPLOAD_JSON_FILE" \
            --form file="@$1" \
            || error_exit "error virustotal.com: please check api-key, internet connection and retry"
        debug_set true    
        UPLOAD_RESULT=`jq -r '.data?.id' $UPLOAD_JSON_FILE` \
            || error_exit "error virustotal.com: please check api-key"    
    fi
}

# unpack tar to image/0 and get list of files
unpack() {
    echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> unpack layer $FILES_COUNTER/$FILES_TOTAL\033[0K\r"
    # unpack the layer into a folder
    # sometimes rm and tar occurs an error
    # therefore disable error checking
    set +Eeo pipefail
    `rm -rf "$IMAGE_DIR/0"` debug_null
    `mkdir "$IMAGE_DIR/0"` debug_null
    # if you run tar embedded in alpine (OCI-image based on alpine)
    # then there is a tar of a different version (busybox) and occurs errors when unpacking
    # unreadable files, (in this place unreadable files may occur)
    # which causes the script to stop.
    # Therefore, it is necessary to additionally install GNU-tar in the alpine-OCI-image
    # Also exclude dev/* because nonroot will cause a device creation error
    eval tar --ignore-failed-read --one-file-system --no-same-owner --no-same-permissions --mode=+w --exclude dev/* -xf "$1" -C "$IMAGE_DIR/0" $DEBUG_TAR
    # if directories after extraction lack the "w" attribute, deletion will result in a "Permission denied" error.
    # Therefore, we add the "rwx" attribute to the directories
    find "$IMAGE_DIR/0" -type d -exec chmod u+rwx {} + 2>/dev/null
    LIST_TAR_FILES=(`find "$IMAGE_DIR/0" -type f 2>/dev/null`)
    # "find" dont sort files by name, so we need sorting
    # Otherwise, we will get different tar and sha256 results. 
    # As a result, the hashes on different devices will not match 
    # and the same layer will have to be uploaded to the virustotal again
    printf "%s\n" "${LIST_TAR_FILES[@]}" > $TMP_FILE
    sort $TMP_FILE > $SORT_FILE
    LIST_TAR_FILES=()
    LIST_TAR_FILES=(`awk '{print $1}' $SORT_FILE`)
    # turning error checking back on
    set -Eeo pipefail    
}

# check mime-types
# find any file of malware mime-types
# mime-types path_to_tar
mime-types() {
    echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> check mime-types $FILES_COUNTER/$FILES_TOTAL\033[0K\r"
    for (( ii=0; ii<${#LIST_TAR_FILES[@]}; ii++ ));
    do
        MIME_TYPE=(`file --mime-type ${LIST_TAR_FILES[$ii]} | awk '{print $2}'`)
        if [[ $MIME_TYPE == application/x-* ]] || [[ $MIME_TYPE == text/x-* ]]; then
            # popular exclusions
            EXCLUDE=false
            for (( iii=0; iii<${#EXCLUDE_MIMES[@]}; iii++ )); do
                if [[ ${EXCLUDE_MIMES[iii]} = $MIME_TYPE ]]; then
                    EXCLUDE=true
                    break
                fi
            done

            if  [ "$EXCLUDE" = false ]  ; then
                IS_ANALYSIS=true
                # if cache exists then break
                if [ -f $1.list ] ; then
                    break
                # for advanced malware searching write all potential malware file-pathes to .list.tmp (not cache)   
                elif  [ "$IS_OK" = false ]  ; then
                    echo "${LIST_TAR_FILES[$ii]#$IMAGE_DIR'/0/'}" >> "$1.list.tmp"
                # inside function reduce-size 
                elif  [ "$IS_BIG_LAYER_REDUCE" = true ]  ; then
                    echo "${LIST_TAR_FILES[$ii]#$IMAGE_DIR'/0/'}" >> "$1.list.tmp"
                    echo `stat -c%s "${LIST_TAR_FILES[$ii]}"`" ${LIST_TAR_FILES[$ii]#$IMAGE_DIR'/0/'}" >> "$1.list.reduce.tmp"  
                # if first scan for layer and it is not big then break    
                else
                    break
                fi    
            fi    
        fi
    done
    # rename .list.tmp to .list (cache is ready)
    if [ -f $1.list.tmp ]; then
        `mv $1.list.tmp $1.list` debug_null
    fi
    # rename .list.reduce.tmp to .list.reduce (cache for reduce is ready)
    if [ -f $1.list.reduce.tmp ]; then
        `mv $1.list.reduce.tmp $1.list.reduce` debug_null
    fi
}

# check layer size
# and reduce it if is too big
# reduce-size path_to_tar
reduce-size() {
    # first check size
    SIZE_LAYER=`stat -c%s "$1"`
    if [[ $SIZE_LAYER -gt 629145600 ]]; then
        # rename tar if it is big - for ignoring it next time
        `mv $1 $1.big` debug_null
        # var for logic inside function mime-types
        IS_BIG_LAYER_REDUCE=true
        # function mime-types with exteded logic
        mime-types $1
        echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> reduce layer size $FILES_COUNTER/$FILES_TOTAL (`echo $SIZE_LAYER | numfmt --to=iec`)\033[0K\r"
        # pack files to upload (compression doesn't make much sense)
        eval tar -cf "$IMAGE_DIR/tmp.tar" -C $IMAGE_DIR/0 -T $1.list $DEBUG_TAR
        SHA256=`sha256sum $IMAGE_DIR/tmp.tar | awk '{ print $1 }'`
        `mv $IMAGE_DIR/tmp.tar $IMAGE_DIR/$SHA256.tar` debug_null
        # check size again
        SIZE_LAYER=`stat -c%s "$IMAGE_DIR/$SHA256.tar"`
        if [[ $SIZE_LAYER -gt 629145600 ]]; then
            # rename tar if it is big - for ignoring it next time
            `mv $IMAGE_DIR/$SHA256.tar $IMAGE_DIR/$SHA256.tar.old` debug_null
            # sort files by size
            sort -gr $1.list.reduce > $1.list.reduce.sort
            # summary size we should remove
            let SIZE_REMOVE=$SIZE_LAYER-629145600
            # get list of sizes from sort file
            LIST_SORT_SIZES=(`awk '{print $1}' $1.list.reduce.sort`)
            # init counters
            SIZE_COUNTER=0
            REMOVE_COUNT=0
            # summ file sizes from sorted list and compare with SIZE_REMOVE
            for (( ii=0; ii<${#LIST_SORT_SIZES[@]}; ii++ ));
            do 
                # summ file sizes
                let SIZE_COUNTER=$SIZE_COUNTER+${LIST_SORT_SIZES[$ii]}
                # if summ file sizes more when size to remove
                if [[ $SIZE_COUNTER -gt $SIZE_REMOVE ]]; then 
                    REMOVE_COUNT=$ii 
                    break 
                fi
            done
            # get list of files from sort file
            LIST_SORT_FILES=(`awk '{print $2}' $1.list.reduce.sort`)
            # recreate list of files to tar (sum size less when 650 MB)
            for (( ii=0; ii<${#LIST_SORT_FILES[@]}; ii++ ));
            do 
                # write to file for tar
                if [[ $ii -gt $REMOVE_COUNT ]]; then   
                    echo "${LIST_SORT_FILES[$ii]}" >> "$1.list.reduce-tar.tmp"    
                fi
            done  
            if [ -f $1.list.reduce-tar.tmp ]; then
                `mv $1.list.reduce-tar.tmp $1.list.reduce-tar` debug_null
            fi  
            # pack files to upload (compression important for tar-metadata)
            eval tar -czf "$IMAGE_DIR/tmp.tar" -C $IMAGE_DIR/0 -T $1.list.reduce-tar $DEBUG_TAR
            SHA256=`sha256sum $IMAGE_DIR/tmp.tar | awk '{ print $1 }'`
            `mv $IMAGE_DIR/tmp.tar $IMAGE_DIR/$SHA256.tar` debug_null
        fi
        # set f as new reduced layer
        f=$IMAGE_DIR/$SHA256.tar
    fi
}

# check exclusions before
set +e
if [ -z "$LOCAL_FILE" ]; then
    # check * pattern (12345abcd) for IMAGE_LINK
    /bin/bash $DEBUG$SCRIPTPATH/check-exclusions.sh -i $IMAGE_LINK --malware 12345abcd
    if [[ $? -eq 1 ]] ; then
        if [ "$DONT_OUTPUT_RESULT" == "false" ]; then
            echo -e "$IMAGE_LINK >>> OK (whitelisted)                      "
        fi    
        echo "OK (whitelisted)" > $RES_FILE
        exit 0
    fi    
fi
set -e

# download and unpack image or use cache 
if [ ! -z "$LOCAL_FILE" ]; then
    IMAGE_LINK=$LOCAL_FILE
    /bin/bash $DEBUG$SCRIPTPATH/scan-download-unpack.sh --tar $LOCAL_FILE
else
    /bin/bash $DEBUG$SCRIPTPATH/scan-download-unpack.sh -i $IMAGE_LINK
fi

# unpack layers and check mime-types
# if we find any file of malware mime-types
# the layer mark as download to virustotal

# list of layer hashes to be searched or uploaded
LIST_LAYERS_TO_ANALYSIS=()
# list of reduced layers (true/false)
LIST_LAYERS_REDUCE=()
# go through layers-archives
FILES=("$IMAGE_DIR"/*.tar)
FILES_TOTAL=${#FILES[@]}
FILES_COUNTER=0
for f in "${FILES[@]}"; 
do
    FILES_COUNTER=$((FILES_COUNTER+1))
    IS_ANALYSIS=false
    IS_BIG_LAYER_REDUCE=false
    unpack $f
    mime-types $f
    if [ "$IS_ANALYSIS" = true ]; then
        # reduce layer size if it more when 650 MB
        reduce-size $f
        # if malware mime-type is found the layer is to be scanned
        filename="${f##*/}"
        filename="${filename%.*}"
        LIST_LAYERS_TO_ANALYSIS+=($filename)
    fi
    # reduce layers to list, so dont do advanced malware search for reduced
    LIST_LAYERS_REDUCE+=($IS_BIG_LAYER_REDUCE)
done

# looking for layer hashes in virustotal
# periodic search for related images will return results for the same base layers
# and they won't have to be re-uploaded for analysis
LIST_RESULT=()
for (( i=0; i<${#LIST_LAYERS_TO_ANALYSIS[@]}; i++ ));
do
    echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> virustotal hash search $((i+1))/${#LIST_LAYERS_TO_ANALYSIS[@]}\033[0K\r"
    # first mark all values as unknown
    LIST_RESULT[$i]='unknown'
    hash_search ${LIST_LAYERS_TO_ANALYSIS[$i]}
    LIST_RESULT[$i]=$SEARCH_RESULT
done

# upload 'unknown' layers
IS_UPLOAD=false
# list of upload ids for check analysis
LIST_UPLOAD_ID=()
for (( i=0; i<${#LIST_LAYERS_TO_ANALYSIS[@]}; i++ ));
do
    ECHO_MESSAGE="${IMAGE_LINK} >>> upload to virustotal $((i+1))/${#LIST_LAYERS_TO_ANALYSIS[@]}"
    LIST_UPLOAD_ID[$i]=''
    if [ "${LIST_RESULT[$i]}" == "unknown" ]; then
        upload "$IMAGE_DIR/${LIST_LAYERS_TO_ANALYSIS[$i]}.tar"
        if [ "$UPLOAD_RESULT" == "big" ]; then
            LIST_RESULT[$i]='big'
        elif [ ! -z "$UPLOAD_RESULT" ]; then
            LIST_RESULT[$i]='upload'
            LIST_UPLOAD_ID[$i]=$UPLOAD_RESULT
        fi 
        IS_UPLOAD=true
    fi
done
    
# if something was upload to virustotal, you need to wait until the analysis passes
if [ "$IS_UPLOAD" = true ]; then
    echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> wait for virustotal analysis $EMOJI_SLEEP\033[0K\r"
    # check analysis ending for all layers
    for (( j=0; j<$MAX_ANALYSIS_TIME; j++ )); do
        # every 5 sec send request for checking
        if [ $(( $j % 5 )) -eq 0 ] && (( $j > 0 )); then
            IS_ANALYSIS_COMPLETE=true
            for (( i=0; i<${#LIST_RESULT[@]}; i++ ));
            do
                if [ "${LIST_RESULT[$i]}" == "upload" ]; then
                    analysis_search ${LIST_UPLOAD_ID[$i]}
                    LIST_RESULT[$i]=$SEARCH_RESULT
                fi    
            done
            if [ "$IS_ANALYSIS_COMPLETE" = true ] ; then
                break
            fi
        fi
        sleep 1
    done              
fi

# is there a virus in the layer
for (( i=0; i<${#LIST_LAYERS_TO_ANALYSIS[@]}; i++ ));
do
    if [ "${LIST_RESULT[$i]}" == "bad" ]; then
        IS_OK=false
    fi    
done

# advanced malware search inside layer.
# We get only executable files from malware layers
# then we upload them to virustotal again.
# This will allow to get more related malware files

LIST_RESULT_ADV=()
LIST_LAYERS_TO_ANALYSIS_ADV=()
LIST_UPLOAD_ID_ADV=()
if [ "$IS_OK" = false ] && [ "$DONT_ADV_SEARCH" = false ]; then
    for (( i=0; i<${#LIST_LAYERS_TO_ANALYSIS[@]}; i++ ));
    do
        LIST_RESULT_ADV[$i]='unknown'
        LIST_UPLOAD_ID_ADV[$i]=''
        LIST_LAYERS_TO_ANALYSIS_ADV[$i]=''
        if [ "${LIST_RESULT[$i]}" == "bad" ] && [ "${LIST_LAYERS_REDUCE[$i]}" == false ]; then
            # unpack again and check all mime-types in layer
            unpack $IMAGE_DIR/${LIST_LAYERS_TO_ANALYSIS[$i]}.tar
            mime-types $IMAGE_DIR/${LIST_LAYERS_TO_ANALYSIS[$i]}.tar
            
            echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> advanced malware analysis (pack)\033[0K\r"

            # check if original layer was compressed
            if (file ${LIST_LAYERS_TO_ANALYSIS[$i]}.tar | grep -q compressed ) ; then
                # pack files to upload  (with compression)
                eval tar -czf "$IMAGE_DIR/tmp.tar" -C $IMAGE_DIR/0 -T $IMAGE_DIR/${LIST_LAYERS_TO_ANALYSIS[$i]}.tar.list $DEBUG_TAR
            else
                # pack files to upload  (without compression)
                eval tar -cf "$IMAGE_DIR/tmp.tar" -C $IMAGE_DIR/0 -T $IMAGE_DIR/${LIST_LAYERS_TO_ANALYSIS[$i]}.tar.list $DEBUG_TAR
            fi   
            SHA256=`sha256sum $IMAGE_DIR/tmp.tar | awk '{ print $1 }'`
            `mv $IMAGE_DIR/tmp.tar $IMAGE_DIR/$SHA256.tar` debug_null
            
            echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> virustotal advanced hash search\033[0K\r"
            LIST_LAYERS_TO_ANALYSIS_ADV[$i]=$SHA256
            hash_search $SHA256
            LIST_RESULT_ADV[$i]=$SEARCH_RESULT
            
            IS_UPLOAD=false

            # upload tar with executables inside
            if [ "${LIST_RESULT_ADV[$i]}" == "unknown" ]; then
                ECHO_MESSAGE="${IMAGE_LINK} >>> upload to advanced virustotal analysis"
                upload "$IMAGE_DIR/$SHA256.tar"
                if [ ! -z "$UPLOAD_RESULT" ]; then
                    LIST_RESULT_ADV[$i]='upload'
                    LIST_UPLOAD_ID_ADV[$i]=$UPLOAD_RESULT
                    IS_UPLOAD=true
                fi 
            fi
            # we need to delete this tar so that 
            # it does not upload onto the virustotal 
            # the next time if it is run from the cache
            `rm -rf "$IMAGE_DIR/$SHA256.tar"` debug_null
        fi    
    done

    if [ "$IS_UPLOAD" = true ]; then
        # we need to wait until the analysis passes
        echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> wait for advanced virustotal analysis $EMOJI_SLEEP\033[0K\r"
        # check analysis ending for all layers
        for (( j=0; j<$MAX_ANALYSIS_TIME; j++ )); do
            # every 5 sec send request for checking
            if [ $(( $j % 5 )) -eq 0 ] && (( $j > 0 )); then
                IS_ANALYSIS_COMPLETE=true
                for (( i=0; i<${#LIST_RESULT_ADV[@]}; i++ ));
                do
                    if [ "${LIST_RESULT_ADV[$i]}" == "upload" ]; then
                        analysis_search ${LIST_UPLOAD_ID_ADV[$i]}
                        LIST_RESULT_ADV[$i]=$SEARCH_RESULT
                    fi
                done
                if [ "$IS_ANALYSIS_COMPLETE" = true ] ; then
                    break
                fi
            fi
            sleep 1
        done
    fi    
    
    echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> virustotal relationship search\033[0K\r"
    LIST_RESULT_PRINT=()
    for (( i=0; i<${#LIST_LAYERS_TO_ANALYSIS[@]}; i++ ));
    do
        LIST_RESULT_PRINT[$i]=''
        if [ "${LIST_RESULT[$i]}" == "bad" ]; then 
            SEARCH_RESULT_FIRST=()
            SEARCH_RESULT_SECOND=()
            SEARCH_RELATIONS_RESULT=()
            
            relationship_search ${LIST_LAYERS_TO_ANALYSIS[$i]}
            # copy result to another array
            SEARCH_RESULT_FIRST=("${SEARCH_RELATIONS_RESULT[@]}") 
            LIST_RESULT_PRINT[$i]='     https://www.virustotal.com/gui/file/'${LIST_LAYERS_TO_ANALYSIS[$i]}

            if [ "${LIST_RESULT_ADV[$i]}" == "bad" ]; then
                relationship_search ${LIST_LAYERS_TO_ANALYSIS_ADV[$i]}
                # copy result to another array
                SEARCH_RESULT_SECOND=("${SEARCH_RELATIONS_RESULT[@]}") 
                LIST_RESULT_PRINT[$i]=${LIST_RESULT_PRINT[$i]}$'\n     https://www.virustotal.com/gui/file/'${LIST_LAYERS_TO_ANALYSIS_ADV[$i]}
            fi  

            SEARCH_RELATIONS_RESULT=("${SEARCH_RESULT_FIRST[@]}")
            # no duplicates from second array
            for (( j=0; j<${#SEARCH_RESULT_SECOND[@]}; j++ )); do
                IS_ADD=true
                IS_EDIT=false
                for (( k=0; k<${#SEARCH_RELATIONS_RESULT[@]}; k++ )); do
                    # replace item by full path
                    if [[ "${SEARCH_RESULT_SECOND[$j]}" == *"${SEARCH_RELATIONS_RESULT[$k]}"* ]]; then
                        SEARCH_RELATIONS_RESULT[$k]="${SEARCH_RESULT_SECOND[$j]}"
                        IS_ADD=false
                        break
                    fi
                    # dont add the same or more short item
                    if [[ "${SEARCH_RELATIONS_RESULT[$k]}" == *"${SEARCH_RESULT_SECOND[$j]}"* ]]; then
                        IS_ADD=false
                        break
                    fi
                done
                if [ "$IS_ADD" = true ] ; then
                    SEARCH_RELATIONS_RESULT+=("${SEARCH_RESULT_SECOND[$j]}")
                fi
            done
            SEARCH_RESULT=''
            for (( j=0; j<${#SEARCH_RELATIONS_RESULT[@]}; j++ )); do
                SEARCH_RESULT=$SEARCH_RESULT$'\n'${SEARCH_RELATIONS_RESULT[$j]}
            done

            # if vt return relations
            if [ ${#SEARCH_RELATIONS_RESULT[@]} -gt 0 ] ; then 
                # draw beauty table
                echo "$SEARCH_RESULT" > $TMP_FILE
                sort $TMP_FILE > $SORT_FILE
                xargs -0 -n3 < $SORT_FILE | column -t -s' ' > $TMP_FILE
                sed 's/^/       /' $TMP_FILE > $SORT_FILE
                SEARCH_RESULT=$(<$SORT_FILE)  
                # for print
                LIST_RESULT_PRINT[$i]=${LIST_RESULT_PRINT[$i]}$'\n'$SEARCH_RESULT
            fi    
        fi
    done
fi

# generating result
RESULT_MESSAGE=''
if [ "$IS_OK" = false ]; then
    RESULT_MESSAGE="$EMOJI_MALWARE $C_RED$IMAGE_LINK$C_NIL >>> virustotal detected malicious file" 
    for (( i=0; i<${#LIST_LAYERS_TO_ANALYSIS[@]}; i++ ));
    do
        if [ "${LIST_RESULT[$i]}" == "bad" ]; then 
            if [ "${LIST_LAYERS_REDUCE[$i]}" == false ]; then
                RESULT_MESSAGE=$RESULT_MESSAGE$'\n''   layer:'${LIST_LAYERS_TO_ANALYSIS[$i]:0:8}
            else
                RESULT_MESSAGE=$RESULT_MESSAGE$'\n''   layer:'${LIST_LAYERS_TO_ANALYSIS[$i]:0:8}' (reduce)'
            fi
            RESULT_MESSAGE=$RESULT_MESSAGE$'\n'${LIST_RESULT_PRINT[$i]}
        fi
        if [ "${LIST_RESULT[$i]}" == "unknown" ]; then
            RESULT_MESSAGE=$RESULT_MESSAGE$'\n   layer '${LIST_LAYERS_TO_ANALYSIS[$i]:0:8}' is unknown for virustotal'
        fi
    done
fi

# result: output to console and write to file
if [ "$IS_OK" = false ]; then
    if [ "$DONT_OUTPUT_RESULT" == "false" ]; then
        echo -e "$RESULT_MESSAGE"
    fi    
    echo "$RESULT_MESSAGE" > $RES_FILE
else
    if [ "$DONT_OUTPUT_RESULT" == "false" ]; then
        echo -e "$IMAGE_LINK >>> OK                                    "
    fi    
    echo "OK" > $RES_FILE
fi

exit 0
