#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2024

# Usage
#     ./scan-virustotal.sh [--dont-output-result] -i image_link --virustotal-key virustotal_api_key
# Available options:
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

#var init (can be changed)
#Waiting between requests
VIRUSTOTAL_REQUEST_LIMIT=false
#Wait while virustotal analyzes the image (seconds)
VIRUSTOTAL_SLEEP_TIME_AFTER_UPLOAD=180
#If a limited account is used, then after 4 requests, wait as many seconds
VIRUSTOTAL_SLEEP_TIME_AFTER_LIMIT=60

#var init
DONT_OUTPUT_RESULT=false
IMAGE_LINK=''
VIRUSTOTAL_API_KEY=''
VIRUSTOTAL_REQUEST_COUNT=0

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

RES_FILE=$SCRIPTPATH'/scan-virustotal.result'
rm -f $RES_FILE

# read the options
ARGS=$(getopt -o i: --long dont-output-result,image:,virustotal-key: -n $0 -- "$@")
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
        --virustotal-key)
            case "$2" in
                "") shift 2 ;;
                *) VIRUSTOTAL_API_KEY=$2 ; shift 2 ;;
            esac ;; 
        --) shift ; break ;;
        *) echo "Wrong usage! Try '$0 --help' for more information." ; exit 2 ;;
    esac
done

#Waiting between requests on virustotal -
#limit on some free account methods,
#is disabled by VIRUSTOTAL_REQUEST_LIMIT
#1 minute delay after 4 requests
virustotal_sleep() {
    #If there is no limit of 4 requests per minute during testing
    #or there is a premium-API-key
    #By default there will be no waiting.
    #If restrictions are observed, change VIRUSTOTAL_REQUEST_LIMIT=true
    if [ "$VIRUSTOTAL_REQUEST_LIMIT" = true ]; then 
        if [ $(( $VIRUSTOTAL_REQUEST_COUNT % 4 )) -eq 0 ] && (( $VIRUSTOTAL_REQUEST_COUNT > 0 )); then
            for (( ii=0; ii<$VIRUSTOTAL_SLEEP_TIME_AFTER_LIMIT; ii++ ));
            do
                echo -ne "  $IMAGE_LINK >>> virustotal - wait $(($VIRUSTOTAL_SLEEP_TIME_AFTER_LIMIT-$ii)) sec (account limit)\033[0K\r" 
                sleep 1
            done
        fi  
    fi
}  

#Hash scanning on virustotal
#Is taken out separately, because it is used twice in the code:
#at the beginning and after downloading the file, if the hash is not found
virustotal_hash_check() {
    for (( i=0; i<$COUNT_LIST_VIRUSTOTAL; i++ ));
    do
        #check only "unknown" values (function is called twice)
        if [ "${LIST_VIRUSTOTAL_RESULT[$i]}" == "unknown" ]; then
            #1 minute delay after 4 requests is the limit of the free virustotal account
            virustotal_sleep
            #one hash per request
            echo -ne "  $IMAGE_LINK >>> virustotal hash search $((i+1))/$COUNT_LIST_VIRUSTOTAL\033[0K\r"
            curl -s --fail --request GET \
                --url "https://www.virustotal.com/api/v3/search?query=${LIST_VIRUSTOTAL_SHA256[$i]}" \
                --header "x-apikey: $VIRUSTOTAL_API_KEY" \
                -o "$SCRIPTPATH/virustotal.json" \
                || error_exit "$IMAGE_LINK >>> error virustotal.com: please check api-key, internet connection and retry"
            #Checking for an error above does not only check the upstream curl, for example, for the absence of Internet,
            #but also the underlying jq, for example, if the API key is not valid
            #therefore, we report general information about the problem
            LIST_VIRUSTOTAL_MALICIOUS=(`jq '.data[]?.attributes?.last_analysis_stats?.malicious' $SCRIPTPATH/virustotal.json`) \
            || error_exit "$IMAGE_LINK >>> error virustotal.com: please check api-key"
            LIST_VIRUSTOTAL_SUSPICIOUS=(`jq '.data[]?.attributes?.last_analysis_stats?.suspicious' $SCRIPTPATH/virustotal.json`) \
            || error_exit "$IMAGE_LINK >>> error virustotal.com: please check api-key"
            #Increasing the request counter (this method is limited by the number per minute/day/month)
            VIRUSTOTAL_REQUEST_COUNT=$((VIRUSTOTAL_REQUEST_COUNT+1))  
            #if the result is empty mark that the layer needs to be sent for scanning
            if [ -z "$LIST_VIRUSTOTAL_MALICIOUS" ]; then
                LIST_VIRUSTOTAL_RESULT[$i]='unknown'
            #if zeros then mark that the layer is good
            elif [ $LIST_VIRUSTOTAL_MALICIOUS -eq 0 ] && [ $LIST_VIRUSTOTAL_SUSPICIOUS -eq 0 ]; then 
                LIST_VIRUSTOTAL_RESULT[$i]='good'
            #else mark that the bad layer (with malware)
            else 
                LIST_VIRUSTOTAL_RESULT[$i]='bad'
                IS_MALWARE=true
                #do not stop for-loop - scan everything to the end
            fi
        fi
    done
} 

# download and unpack image or use cache 
/bin/bash $SCRIPTPATH/scan-download-unpack.sh -i $IMAGE_LINK

#Unpack layers and check mime-types
#If we find any file of application/* or */x-shellscript
#the layer mark as download to virustotal

LIST_VIRUSTOTAL_SHA256=()
#Go through layers-archives
for f in "$SCRIPTPATH/image"/*.tar
do
    #Unpack the layer into a folder
    #Sometimes rm and tar occurs an error
    #Therefore disable error checking
    set +Eeo pipefail
    rm -rf "$SCRIPTPATH/image/0" &>/dev/null
    mkdir "$SCRIPTPATH/image/0" &>/dev/null
    #if you run tar embedded in alpine (OCI-image based on alpine)
    #then there is a tar of a different version (busybox) and occurs errors when unpacking
    #unreadable files, (in this place unreadable files may occur)
    #which causes the script to stop.
    #Therefore it is necessary to additionally install GNU-tar in the alpine-OCI-image
    #Also exclude dev/* because nonroot will cause a device creation error
    tar --ignore-failed-read --one-file-system --exclude dev/* -xf "$f" -C "$SCRIPTPATH/image/0" &>/dev/null
    #Check if there is at least one application or x-shellscript in current layer
    LIST_TAR_FILES=()
    #sometimes "permission denied" was here
    LIST_TAR_FILES=(`find $SCRIPTPATH/image/0 -type f`)
    #Turning error checking back on
    set -Eeo pipefail

    echo -ne "  $IMAGE_LINK >>> check mime-types\033[0K\r"
    for (( j=0; j<${#LIST_TAR_FILES[@]}; j++ ));
    do
        MIME_TYPE=(`file --mime-type ${LIST_TAR_FILES[$j]} | awk '{print $2}'`)
        if [[ $MIME_TYPE == application/* ]] || [[ $MIME_TYPE == */x-shellscript ]]; then 
            #if application or x-shellscript is found the layer is to be scanned
            filename="${f##*/}"
            filename="${filename%.*}"
            LIST_VIRUSTOTAL_SHA256+=($filename)
            break
        fi
    done
done

#Looking for layer hashes in virustotal
#Periodic search for related images will return results for the same base layers
#and they won't have to be re-uploaded for verification

echo -ne "  $IMAGE_LINK >>> virustotal hash search\033[0K\r"
LIST_VIRUSTOTAL_RESULT=()
#COUNT_LIST_VIRUSTOTAL - number of layers to scan
COUNT_LIST_VIRUSTOTAL=${#LIST_VIRUSTOTAL_SHA256[@]}
#Mark the values as unknown in advance
for (( i=0; i<$COUNT_LIST_VIRUSTOTAL; i++ ));
do
    LIST_VIRUSTOTAL_RESULT[$i]='unknown'  
done
virustotal_hash_check
#Upload the layer not found on virustotal for checking
LIST_VIRUSTOTAL_UPLOAD_ID=()
#var init that means: was something loaded as a result on virustotal?
IS_VIRUSTOTAL_UPLOAD=false
for (( i=0; i<$COUNT_LIST_VIRUSTOTAL; i++ ));
do
    echo -ne "  ${IMAGE_LINK} >>> upload to virustotal $((i+1))/$COUNT_LIST_VIRUSTOTAL\033[0K\r"
    LIST_VIRUSTOTAL_UPLOAD_ID+=('')
    if [ "${LIST_VIRUSTOTAL_RESULT[$i]}" == "unknown" ]; then
        TAR_FILE="$SCRIPTPATH/image/${LIST_VIRUSTOTAL_SHA256[$i]}.tar"
        #File is too big to download (>650 MB) - we do not load it
        if [[ $(stat -c%s "$TAR_FILE") -gt 629145600 ]]; then
            LIST_VIRUSTOTAL_RESULT[$i]='big'
        else  
            #If file is less than 32 MB, then we use the usual url for downloading
            if [[ $(stat -c%s "$TAR_FILE") -lt 33554432 ]]; then
                VIRUSTOTAL_UPLOAD_URL='https://www.virustotal.com/api/v3/files'
            #If it is more than 32 MB, but less than 650 MB, request a special url for downloading
            else
                #This method is not limited to a free account, so we do not include waiting
                curl -s --fail --request GET \
                    --url https://www.virustotal.com/api/v3/files/upload_url \
                    --header "x-apikey: $VIRUSTOTAL_API_KEY" \
                    -o "$SCRIPTPATH/virustotal_url.json" \
                    || error_exit "$IMAGE_LINK >>> error virustotal.com: please check api-key, internet connection and retry"
                VIRUSTOTAL_UPLOAD_URL=(`jq -r '.data' $SCRIPTPATH/virustotal_url.json`) \
                    || error_exit "$IMAGE_LINK >>> error virustotal.com: please check api-key"
            fi
            #1 minute delay after 4 requests is the limit of the free virustotal account
            virustotal_sleep
            #Upload the file to the desired url
            curl -s --fail --request POST \
                --url "$VIRUSTOTAL_UPLOAD_URL" \
                --header "accept: application/json" \
                --header "content-type: multipart/form-data" \
                --header "x-apikey: $VIRUSTOTAL_API_KEY" \
                -o "$SCRIPTPATH/virustotal_upload.json" \
                --form file="@$TAR_FILE" \
                || error_exit "$IMAGE_LINK >>> error virustotal.com: please check api-key, internet connection and retry"
            #The method returns the id of the uploaded file, but we don't use it, we immediately look for the hash
            #Increasing the request counter (this method is limited by the number per minute/day/month)
            VIRUSTOTAL_REQUEST_COUNT=$((VIRUSTOTAL_REQUEST_COUNT+1))    
            IS_VIRUSTOTAL_UPLOAD=true
        fi
    fi
done
    
# if something was upload to virustotal, you need to wait until the analysis passes
if [ "$IS_VIRUSTOTAL_UPLOAD" = true ]; then
    # this output is preferable for CI output
    if [ ! -z "$IMAGE_LINK" ]; then 
        echo -ne "  $IMAGE_LINK >>> wait $VIRUSTOTAL_SLEEP_TIME_AFTER_UPLOAD sec for virustotal analyze\033[0K\r"
        sleep $VIRUSTOTAL_SLEEP_TIME_AFTER_UPLOAD
    # this output is preferable for local start    
    else    
        for (( i=0; i<$VIRUSTOTAL_SLEEP_TIME_AFTER_UPLOAD; i++ ));
        do 
            echo -ne "  $IMAGE_LINK >>> wait $(($VIRUSTOTAL_SLEEP_TIME_AFTER_UPLOAD-$i)) sec for virustotal analyze  \033[0K\r"
            sleep 1
        done
    fi
    # after checking the hash again
    virustotal_hash_check
fi

# generating result
IS_VIRUSTOTAL_OK=true
for (( i=0; i<$COUNT_LIST_VIRUSTOTAL; i++ ));
do
    if [ "${LIST_VIRUSTOTAL_RESULT[$i]}" == "bad" ]; then
        IS_VIRUSTOTAL_OK=false
    fi    
    #We can "tighten the nuts" and do not skip large layers or if there are problems with virustotal
    #if [ "${LIST_VIRUSTOTAL_RESULT[$i]}" == "unknown" ] || [ "${LIST_VIRUSTOTAL_RESULT[$i]}" == "big" ]; then
    #   IS_VIRUSTOTAL_OK=false
    #fi
done

# output result message
VIRUSTOTAL_RESULT_MESSAGE=''
if [ "$IS_VIRUSTOTAL_OK" = false ]; then
    VIRUSTOTAL_RESULT_MESSAGE="$IMAGE_LINK >>> virustotal detected malicious file" 
    for (( i=0; i<$COUNT_LIST_VIRUSTOTAL; i++ ));
    do
        if [ "${LIST_VIRUSTOTAL_RESULT[$i]}" == "bad" ]; then
            VIRUSTOTAL_RESULT_MESSAGE=$VIRUSTOTAL_RESULT_MESSAGE$'\n  https://www.virustotal.com/gui/file/'${LIST_VIRUSTOTAL_SHA256[$i]}
        fi
        if [ "${LIST_VIRUSTOTAL_RESULT[$i]}" == "big" ]; then
            VIRUSTOTAL_RESULT_MESSAGE=$VIRUSTOTAL_RESULT_MESSAGE$'\n  layer '${LIST_VIRUSTOTAL_SHA256[$i]}' is too big, no virustotal scan'
        fi
        if [ "${LIST_VIRUSTOTAL_RESULT[$i]}" == "unknown" ]; then
            VIRUSTOTAL_RESULT_MESSAGE=$VIRUSTOTAL_RESULT_MESSAGE$'\n  layer '${LIST_VIRUSTOTAL_SHA256[$i]}' is unknown for virustotal'
        fi
    done                   
fi

# result: output to console and write to file
if [ "$IS_VIRUSTOTAL_OK" = false ]; then
    if [ "$DONT_OUTPUT_RESULT" == "false" ]; then
        echo "$VIRUSTOTAL_RESULT_MESSAGE"
    fi    
    echo "$VIRUSTOTAL_RESULT_MESSAGE" > $RES_FILE
else
    if [ "$DONT_OUTPUT_RESULT" == "false" ]; then
        echo "$IMAGE_LINK >>> OK                        "
    fi    
    echo "OK" > $RES_FILE
fi

exit 0
