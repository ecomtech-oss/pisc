#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2024

# Usage
#     ./scan-virustotal.sh [--dont-adv-search] [--dont-output-result] -i image_link --virustotal-key API_KEY
# Available options:
#     --dont-adv-search                 don't use advanced malware search inside layer
#     --dont-output-result              don't output result into console, only into file
#     -i, --image string                only this image will be checked. Example: -i r0binak/mtkpi:v1.3
#     --virustotal-key string           specify virustotal API-key, example: ---virustotal-key 0123456789abcdef
# Example
#     ./scan-virustotal.sh --virustotal-key 0123456789abcdef -i r0binak/mtkpi:v1.3


set -Eeo pipefail

# exception handling
error_exit()
{
    echo "$1"
    exit 1
}

# var init (can be changed)
# list of false positive vendors
FALSE_POSITIVE_VENDOR=(
    "TrendMicro-HouseCall"
)
# waiting between requests
REQUEST_LIMIT=false
# wait while virustotal analyzes the image (seconds)
MAX_ANALYSIS_TIME=600
# if a limited account is used, then after 4 requests, wait as many seconds
SLEEP_TIME_AFTER_LIMIT=60

# var init
DONT_ADV_SEARCH=false
DONT_OUTPUT_RESULT=false
IMAGE_LINK=''
IS_OK=true
API_KEY=''
REQUEST_COUNT=0

C_RED='\033[0;31m'
C_BLU='\033[1;34m'
C_NIL='\033[0m'

EMOJI_SLEEP='\U1F4A4' # zzz
EMOJI_MALWARE='\U26A1' # high voltage
EMOJI_DEFAULT='\U1F4A9' # shit
EMOJI_OK='\U1F44D' # thumbs up
EMOJI_NAMES=(
    'vulnerabil'
    'xploit'
    'sploit'
    'crypto'
    'miner'
    'hack'
    'backdoor'
    'trojan'
    'worm'
)
EMOJI_CODES=(
    '\U1F41E' # lady beetle
    '\U1F419' # octopus
    '\U1F419' # octopus
    '\U1F511' # key
    '\U1F4B0' # money
    '\U1F47E' # alien
    '\U1F434' # horse
    '\U1F434' # horse
    '\U1F41B' # worm
)

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

IMAGE_DIR=$SCRIPTPATH'/image'
ADVANCED_DIR=$SCRIPTPATH'/advanced'

JSON_RELATIONSHIP_FILE=$SCRIPTPATH'/virustotal-rel.json'
JSON_SEARCH_FILE=$SCRIPTPATH'/virustotal.json'
URL_FILE=$SCRIPTPATH'/virustotal-url.json'
UPLOAD_JSON_FILE=$SCRIPTPATH'/virustotal-upload.json'
RES_FILE=$SCRIPTPATH'/scan-virustotal.result'
TMP_FILE=$SCRIPTPATH'/virustotal.tmp'
SORT_FILE=$SCRIPTPATH'/virustotal.sort'
rm -rf $RES_FILE &>/dev/null

# read the options
ARGS=$(getopt -o i: --long dont-adv-search,dont-output-result,image:,virustotal-key: -n $0 -- "$@")
eval set -- "$ARGS"

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
        -i|--image)
            case "$2" in
                "") shift 2 ;;
                *) IMAGE_LINK=$2 ; shift 2 ;;
            esac ;;    
        --virustotal-key)
            case "$2" in
                "") shift 2 ;;
                *) API_KEY=$2 ; shift 2 ;;
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
                echo -ne "  $IMAGE_LINK >>> virustotal - wait $(($SLEEP_TIME_AFTER_LIMIT-$ii)) sec (account limit) $EMOJI_SLEEP\033[0K\r" 
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
    curl -s --fail --request GET \
        --url "https://www.virustotal.com/api/v3/search?query=$1" \
        --header "x-apikey: $API_KEY" \
        -o "$JSON_SEARCH_FILE" \
        || error_exit "$IMAGE_LINK >>> error virustotal.com: please check api-key, internet connection and retry"            

    # check that the scan is completed by last_analysis_date
    LAST_ANALYSIS_DATE=`jq -r '.data[]?.attributes?.last_analysis_date?' $JSON_SEARCH_FILE` \
        || error_exit "$IMAGE_LINK >>> error virustotal.com: please check api-key"
    if [ ! -z "$LAST_ANALYSIS_DATE" ]; then
        
        # get vendors detected malware
        VENDORS=()
        VENDORS+=(`jq -r '.data[]?.attributes?.last_analysis_results?[]? | (select(.category == "malicious")) | .engine_name' $JSON_SEARCH_FILE`)
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
    curl -s --fail --request GET \
        --url "https://www.virustotal.com/api/v3/analyses/$1" \
        --header "x-apikey: $API_KEY" \
        -o "$JSON_SEARCH_FILE" \
        || error_exit "$IMAGE_LINK >>> error virustotal.com: please check api-key, internet connection and retry"            
    # check that the scan is completed by status
    ANALYSIS_STATUS=`jq -r '.data?.attributes?.status?' $JSON_SEARCH_FILE` \
        || error_exit "$IMAGE_LINK >>> error virustotal.com: please check api-key" 
    if [ "$ANALYSIS_STATUS" == "completed" ]; then 
        # get vendors detected malware
        VENDORS=()
        VENDORS+=(`jq -r '.data?.attributes?.results?[]? | (select(.category == "malicious")) | .engine_name' $JSON_SEARCH_FILE`)
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
    SEARCH_RESULT=''
    # 1 minute delay after 4 requests is the limit of the free virustotal account
    quota_sleep
    # increasing the request counter (this method is limited by the number per minute/day/month)
    REQUEST_COUNT=$((REQUEST_COUNT+1)) 
    curl -s --fail --request GET \
        --url "https://www.virustotal.com/api/v3/files/$1/bundled_files?limit=40" \
        --header "x-apikey: $API_KEY" \
        -o "$JSON_RELATIONSHIP_FILE" \
        || error_exit "$IMAGE_LINK >>> error virustotal.com: please check api-key, internet connection and retry"
    REL_STAT=()
    REL_PATH=()
    REL_PATH+=(`jq -r '.data[]? | (select(.attributes?.last_analysis_stats?.malicious? != 0)) | .context_attributes?.filename?' $JSON_RELATIONSHIP_FILE`)
    REL_ID=()
    REL_ID+=(`jq -r '.data[]? | (select(.attributes?.last_analysis_stats?.malicious? != 0)) | .id' $JSON_RELATIONSHIP_FILE`)
    REL_LABEL=()
    REL_LABEL+=(`jq -r '.data[]? | (select(.attributes?.last_analysis_stats?.malicious? != 0)) | .attributes?.popular_threat_classification?.suggested_threat_label?' $JSON_RELATIONSHIP_FILE`)
    REL_MALICIOUS=()  
    REL_MALICIOUS+=(`jq -r '.data[]? | (select(.attributes?.last_analysis_stats?.malicious? != 0)) | .attributes?.last_analysis_stats?.malicious?' $JSON_RELATIONSHIP_FILE`)  
    REL_SUSPICIOUS=()  
    REL_SUSPICIOUS+=(`jq -r '.data[]? | (select(.attributes?.last_analysis_stats?.malicious? != 0)) | .attributes?.last_analysis_stats?.suspicious?' $JSON_RELATIONSHIP_FILE`)
    REL_UNDETECTED=()  
    REL_UNDETECTED+=(`jq -r '.data[]? | (select(.attributes?.last_analysis_stats?.malicious? != 0)) | .attributes?.last_analysis_stats?.undetected?' $JSON_RELATIONSHIP_FILE`)
    REL_HARMLESS=()  
    REL_HARMLESS+=(`jq -r '.data[]? | (select(.attributes?.last_analysis_stats?.malicious? != 0)) | .attributes?.last_analysis_stats?.harmless?' $JSON_RELATIONSHIP_FILE`)
    for (( ii=0; ii<${#REL_ID[@]}; ii++ ));
    do
        # get vendors detected malware
        VENDORS=()
        VENDORS+=(`jq -r '.data[]? | (select(.id == "'${REL_ID[$ii]}'")) | .attributes?.last_analysis_results?[]? | (select(.category == "malicious")) | .engine_name?' $JSON_RELATIONSHIP_FILE`)
        false_positive_vendors_remove
       
        # if vendors count (after false positive vendors remove) > 0 then result is bad
        if [ ${#VENDORS[@]} -gt 0 ] ; then  
            # get name if path empty
            if [ "${REL_PATH[$ii]}" == 'null' ]; then
                REL_PATH[$ii]=`jq -r '.data[]? | (select(.id == "'${REL_ID[$ii]}'")) | .attributes?.meaningful_name?' $JSON_RELATIONSHIP_FILE`
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
                REL_MALWARE_NAME_LIST+=(`jq -r '.data[]? | (select(.id == "'${REL_ID[$ii]}'")) | .attributes?.last_analysis_results?[]? | (select(.category == "malicious")) | .result?' $JSON_RELATIONSHIP_FILE`)
                # set the longest malware name for label =)
                for (( jj=0; jj<${#REL_MALWARE_NAME_LIST[@]}; jj++ ));
                do
                if (( ${#REL_MALWARE_NAME_LIST[$jj]} > ${#REL_LABEL[$ii]} )); then
                    REL_LABEL[$ii]=${REL_MALWARE_NAME_LIST[$jj]}
                fi
                done
            fi

            # check known_distributors - false positive
            REL_KNOWN_DISTRIBUTORS=`jq -r '.data[]? | (select(.id == "'${REL_ID[$ii]}'")) | .attributes?.known_distributors?.distributors?[]?' $JSON_RELATIONSHIP_FILE`
            if [ ! -z "$REL_KNOWN_DISTRIBUTORS" ]; then 
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

            SEARCH_RESULT=$SEARCH_RESULT$'\n '${REL_PATH[$ii]}' '${REL_STAT[$ii]}' '${REL_LABEL[$ii]}
        fi    
    done
    # draw beauty table
    echo "$SEARCH_RESULT" > $TMP_FILE
    sort $TMP_FILE > $SORT_FILE
    xargs -0 -n3 < $SORT_FILE | column -t -s' ' > $TMP_FILE
    sed 's/^/    /' $TMP_FILE > $SORT_FILE
    SEARCH_RESULT=$(<$SORT_FILE)
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
        echo -ne "$ECHO_MESSAGE (`stat -c%s "$1" | numfmt --to=iec`)\033[0K\r"
        # if file size is less than 32 MB, then we use the usual url for uploading
        if [[ $(stat -c%s "$1") -lt 33554432 ]]; then
            UPLOAD_URL='https://www.virustotal.com/api/v3/files'
        # if file size is more than 32 MB, but less than 650 MB, request a special url for uploading
        else
            # this method is not limited to a free account, so we do not include waiting
            curl -s --fail --request GET \
                --url https://www.virustotal.com/api/v3/files/upload_url \
                --header "x-apikey: $API_KEY" \
                -o "$URL_FILE" \
                || error_exit "$IMAGE_LINK >>> error virustotal.com: please check api-key, internet connection and retry"
            UPLOAD_URL=`jq -r '.data' $URL_FILE` \
                || error_exit "$IMAGE_LINK >>> error virustotal.com: please check api-key"
        fi
        # 1 minute delay after 4 requests is the limit of the free virustotal account
        quota_sleep
        # increasing the request counter (this method is limited by the number per minute/day/month)
        REQUEST_COUNT=$((REQUEST_COUNT+1))    
        # upload the file to the desired url
        # method returns the id of the uploaded file
        curl -s --fail --request POST \
            --url "$UPLOAD_URL" \
            --header "accept: application/json" \
            --header "content-type: multipart/form-data" \
            --header "x-apikey: $API_KEY" \
            -o "$UPLOAD_JSON_FILE" \
            --form file="@$1" \
            || error_exit "$IMAGE_LINK >>> error virustotal.com: please check api-key, internet connection and retry"
        UPLOAD_RESULT=`jq -r '.data?.id' $UPLOAD_JSON_FILE` \
            || error_exit "$IMAGE_LINK >>> error virustotal.com: please check api-key"    
    fi
}

# unpack tar to image/0 and get list of files
unpack() {
    echo -ne "  $IMAGE_LINK >>> unpack layer\033[0K\r"
    # unpack the layer into a folder
    # sometimes rm and tar occurs an error
    # therefore disable error checking
    set +Eeo pipefail
    rm -rf "$IMAGE_DIR/0" &>/dev/null
    mkdir "$IMAGE_DIR/0" &>/dev/null
    # if you run tar embedded in alpine (OCI-image based on alpine)
    # then there is a tar of a different version (busybox) and occurs errors when unpacking
    # unreadable files, (in this place unreadable files may occur)
    # which causes the script to stop.
    # Therefore it is necessary to additionally install GNU-tar in the alpine-OCI-image
    # Also exclude dev/* because nonroot will cause a device creation error
    tar --ignore-failed-read --one-file-system --exclude dev/* -xf "$1" -C "$IMAGE_DIR/0" &>/dev/null
    # check if there is at least one application or x-shellscript in current layer
    LIST_TAR_FILES=()
    # sometimes "permission denied" was here
    LIST_TAR_FILES=(`find $IMAGE_DIR/0 -type f`)
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
# find any file of application/* or */x-shellscript
# mime-types path_to_tar
mime-types() {
    echo -ne "  $IMAGE_LINK >>> check mime-types\033[0K\r"
    for (( ii=0; ii<${#LIST_TAR_FILES[@]}; ii++ ));
    do
        MIME_TYPE=(`file --mime-type ${LIST_TAR_FILES[$ii]} | awk '{print $2}'`)
        if [[ $MIME_TYPE == application/x-* ]] || [[ $MIME_TYPE == text/x-* ]]; then
            IS_ANALYSIS=true
            # if this is first check (before upload) or
            # used cache from previous download
            # exit from for-loop on first file
            if [ "$IS_OK" = true ] || [ -f $1.list ]; then
                break
            # for advanced malware searching write all potential malware file-pathes to .list.tmp (not cache)   
            else
                # cut first part of path ($IMAGE_DIR/0/)
                # for normal tar-packing
                echo "${LIST_TAR_FILES[$ii]#$IMAGE_DIR'/0/'}" >> "$1.list.tmp"
            fi    
        fi
    done
    # rename .list.tmp to .list (cache is ready)
    if [ -f $1.list.tmp ]; then
        mv $1.list.tmp $1.list &>/dev/null
    fi
}

# download and unpack image or use cache 
/bin/bash $SCRIPTPATH/scan-download-unpack.sh -i $IMAGE_LINK

# unpack layers and check mime-types
# if we find any file of application/* or */x-shellscript
# the layer mark as download to virustotal

# list of layer hashes to be searched or uploaded
LIST_LAYERS_TO_ANALYSIS=()
# go through layers-archives
for f in "$IMAGE_DIR"/*.tar
do
    IS_ANALYSIS=false
    unpack $f
    mime-types $f
    if [ "$IS_ANALYSIS" = true ]; then
        # if application or x-shellscript is found the layer is to be scanned
        filename="${f##*/}"
        filename="${filename%.*}"
        LIST_LAYERS_TO_ANALYSIS+=($filename)
    fi
done

# looking for layer hashes in virustotal
# periodic search for related images will return results for the same base layers
# and they won't have to be re-uploaded for analysis
LIST_RESULT=()
for (( i=0; i<${#LIST_LAYERS_TO_ANALYSIS[@]}; i++ ));
do
    echo -ne "  $IMAGE_LINK >>> virustotal hash search $((i+1))/${#LIST_LAYERS_TO_ANALYSIS[@]}\033[0K\r"
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
    ECHO_MESSAGE="  ${IMAGE_LINK} >>> upload to virustotal $((i+1))/${#LIST_LAYERS_TO_ANALYSIS[@]}"
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
    echo -ne "  $IMAGE_LINK >>> wait for virustotal analysis $EMOJI_SLEEP\033[0K\r"
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
    #We can "tighten the nuts" and do not skip large layers or if there are problems with virustotal
    #if [ "${LIST_RESULT[$i]}" == "unknown" ] || [ "${LIST_RESULT[$i]}" == "big" ]; then
    #   IS_OK=false
    #fi
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
        if [ "${LIST_RESULT[$i]}" == "bad" ]; then
            # unpack again and check all mime-types in layer
            unpack $IMAGE_DIR/${LIST_LAYERS_TO_ANALYSIS[$i]}.tar
            mime-types $IMAGE_DIR/${LIST_LAYERS_TO_ANALYSIS[$i]}.tar
            
            echo -ne "  $IMAGE_LINK >>> advanced malware analysis (pack)\033[0K\r"

            # pack files to upload (compression doesn't make much sense)
            tar -cvf "$IMAGE_DIR/tmp.tar" -C $IMAGE_DIR/0 -T $IMAGE_DIR/${LIST_LAYERS_TO_ANALYSIS[$i]}.tar.list &>/dev/null
            SHA256=`sha256sum $IMAGE_DIR/tmp.tar | awk '{ print $1 }'` &>/dev/null
            mv $IMAGE_DIR/tmp.tar $IMAGE_DIR/$SHA256.tar &>/dev/null
            
            echo -ne "  $IMAGE_LINK >>> virustotal advanced hash search\033[0K\r"
            LIST_LAYERS_TO_ANALYSIS_ADV[$i]=$SHA256
            hash_search $SHA256
            LIST_RESULT_ADV[$i]=$SEARCH_RESULT
            
            IS_UPLOAD=false

            # upload tar with executables inside
            if [ "${LIST_RESULT_ADV[$i]}" == "unknown" ]; then
                ECHO_MESSAGE="  ${IMAGE_LINK} >>> upload to advanced virustotal analysis"
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
            rm -rf "$IMAGE_DIR/$SHA256.tar" &>/dev/null   
        fi    
    done

    if [ "$IS_UPLOAD" = true ]; then
        # we need to wait until the analysis passes
        echo -ne "  $IMAGE_LINK >>> wait for advanced virustotal analysis $EMOJI_SLEEP\033[0K\r"
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
    
    echo -ne "  $IMAGE_LINK >>> virustotal relationship search\033[0K\r"
    for (( i=0; i<${#LIST_LAYERS_TO_ANALYSIS[@]}; i++ ));
    do
        if [ "${LIST_RESULT_ADV[$i]}" == "bad" ]; then
            relationship_search ${LIST_LAYERS_TO_ANALYSIS_ADV[$i]}
            LIST_RESULT_ADV[$i]=$SEARCH_RESULT
            LIST_RESULT_ADV[$i]='  layer:'${LIST_LAYERS_TO_ANALYSIS[$i]:0:8}' - see \e]8;;https://www.virustotal.com/gui/file/'${LIST_LAYERS_TO_ANALYSIS_ADV[$i]}'/relations\avirustotal analysis\e]8;;\a'$'\n'$SEARCH_RESULT
        # if adv search not detect malware, show previous scan
        else
            LIST_RESULT_ADV[$i]='  https://www.virustotal.com/gui/file/'${LIST_LAYERS_TO_ANALYSIS[$i]}
        fi    
    done
fi

# generating result
RESULT_MESSAGE=''
if [ "$IS_OK" = false ]; then
    RESULT_MESSAGE="$EMOJI_MALWARE $C_RED$IMAGE_LINK$C_NIL >>> virustotal detected malicious file" 
    for (( i=0; i<${#LIST_LAYERS_TO_ANALYSIS[@]}; i++ ));
    do
        if [ "$DONT_ADV_SEARCH" = false ]; then
            if [ "${LIST_RESULT[$i]}" == "bad" ]; then
                RESULT_MESSAGE=$RESULT_MESSAGE$'\n'${LIST_RESULT_ADV[$i]}
            fi    
        else
            if [ "${LIST_RESULT[$i]}" == "bad" ]; then
                RESULT_MESSAGE=$RESULT_MESSAGE$'\n  https://www.virustotal.com/gui/file/'${LIST_LAYERS_TO_ANALYSIS[$i]}'/relations'
            fi
        fi    
        if [ "${LIST_RESULT[$i]}" == "big" ]; then
            RESULT_MESSAGE=$RESULT_MESSAGE$'\n  layer '${LIST_LAYERS_TO_ANALYSIS[$i]:0:8}' is too big, no virustotal scan'
        fi
        if [ "${LIST_RESULT[$i]}" == "unknown" ]; then
            RESULT_MESSAGE=$RESULT_MESSAGE$'\n  layer '${LIST_LAYERS_TO_ANALYSIS[$i]:0:8}' is unknown for virustotal'
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
