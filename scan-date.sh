#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2026

# Usage
#     ./scan-date.sh [--dont-output-result] [-i image_link | --tar /path/to/private-image.tar]
# Available options:
#     --dont-output-result              don't output result into console, only into file
#     -i, --image string                only this image will be checked. Example: -i gcr.io/distroless/base-debian11:nonroot-amd64
#     --tar string                      check local image-tar. Example: --tar /path/to/private-image.tar

# Examples
# ./scan-date.sh -i alpine
# ./scan-date.sh -i gcr.io/distroless/base-debian11:nonroot-amd64

set -Eeo pipefail

# exception handling
error_exit()
{
    echo "$1"
    exit 2
}

result_exit()
{
    echo "$CREATED_DATE" > $RES_FILE
    if [ "$DONT_OUTPUT_RESULT" == "false" ]; then  
        echo "$IMAGE_LINK >>> $CREATED_DATE                 "
    fi    
    exit 0
}

#var init
CREATED_DATE=''
DONT_OUTPUT_RESULT=false
FLAG_IMAGE='-i'
IMAGE_LINK=''
LOCAL_FILE=''

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# get exported var with default value if it is empty
: "${OUT_DIR:=/tmp}"
# check debug mode to debug child scripts and external tools
DEBUG=''
DEBUG_SKOPEO=''
DEBUG_TAR='2>/dev/null'
if [[ "$-" == *x* ]]; then
    DEBUG='-x '
    DEBUG_SKOPEO='--debug '
    DEBUG_TAR=''
fi
debug_null() {
    if [[ "$-" != *x* ]]; then 
        eval &>/dev/null
    fi    
}

IMAGE_DIR=$OUT_DIR'/image'
JSON_FILE=$OUT_DIR'/inspect.json'
RES_FILE=$OUT_DIR'/scan-date.result'
rm -f $RES_FILE

SKOPEO_AUTH_FLAG=''
AUTH_FILE=$OUT_DIR'/auth.json'
if [ -f "$AUTH_FILE" ]; then
    SKOPEO_AUTH_FLAG="--authfile=$AUTH_FILE"
fi

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

# set local-tar as image
if [ ! -z "$LOCAL_FILE" ]; then
    IMAGE_LINK=$LOCAL_FILE
    FLAG_IMAGE='--tar'
    SKOPEO_INPUT="docker-archive:$LOCAL_FILE"
else
    FLAG_IMAGE='-i'
    SKOPEO_INPUT="docker://$IMAGE_LINK"
fi

# check the date of the image by downloading metadata
echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> check date\033[0K\r"
skopeo $DEBUG_SKOPEO inspect "$SKOPEO_INPUT" $SKOPEO_AUTH_FLAG > $JSON_FILE
CREATED_DATE=(`jq '.Created' $JSON_FILE | cut -b 2-11`) \
    || error_exit "$IMAGE_LINK >>> error image inspect"
# if a copy error exit with error
if [ $? -ne 0 ]; then
    echo "$IMAGE_LINK >>> can't inspect, check image name and tag"
    exit 1
fi 

# if date is normal then result and exit
if [ "$CREATED_DATE" != "0001-01-01" ] && [ "$CREATED_DATE" != "1970-01-01" ]; then
    result_exit
fi    
 
# If the metadata does not specify the date of image build (for example, as in distroless)
# we will find it through the date of the most recent file,
# we also scan files in unpacked layers, as in the block above
echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> extended check date\033[0K\r"

# download and unpack image or use cache 
/bin/bash $DEBUG$SCRIPTPATH/scan-download-unpack.sh $FLAG_IMAGE $IMAGE_LINK

# var init for advanced date search
CREATED_DATE_EXT=0

# Go through layers-archives for extended date searching
for f in "$IMAGE_DIR"/*.tar
do
    # Unpack the layer into a folder
    # Sometimes rm and tar occurs an error
    # Therefore disable error checking
    set +Eeo pipefail
    `rm -rf "$IMAGE_DIR/0"` debug_null
    `mkdir "$IMAGE_DIR/0"` debug_null
    # if you run tar embedded in alpine (OCI-image based on alpine)
    # then there is a tar of a different version (busybox) and occurs errors when unpacking
    # unreadable files, (in this place unreadable files may occur)
    # which causes the script to stop.
    # Therefore it is necessary to additionally install GNU-tar in the alpine-OCI-image
    # Also exclude dev/* because nonroot will cause a device creation error
    eval tar --ignore-failed-read --one-file-system --no-same-owner --no-same-permissions --mode=+w --exclude dev/* -xf "$f" -C "$IMAGE_DIR/0" $DEBUG_TAR
    # if directories after extraction lack the "w" attribute, deletion will result in a "Permission denied" error.
    # Therefore, we add the "rwx" attribute to the directories
    find "$IMAGE_DIR/0" -type d -exec chmod u+rwx {} + 2>/dev/null
    # Check if there is at least one application or x-shellscript in current layer
    LIST_TAR_FILES=(`find "$IMAGE_DIR/0" -type f 2>/dev/null`)
    # Turning error checking back on
    set -Eeo pipefail

    for (( j=0; j<${#LIST_TAR_FILES[@]}; j++ ));
    do
        d=(`date -r ${LIST_TAR_FILES[$j]} +%s`)
        if (( $d > $CREATED_DATE_EXT )); then
            CREATED_DATE_EXT=$d
        fi
    done
done

CREATED_DATE=(`date -d @$CREATED_DATE_EXT "+%Y-%m-%d"`)

result_exit
