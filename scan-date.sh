#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2024

# Usage
#     ./scan-date.sh [--dont-output-result] -i image_link
# Available options:
#     --dont-output-result              don't output result into console, only into file
#     -i, --image string                only this image will be checked. Example: -i gcr.io/distroless/base-debian11:nonroot-amd64

# Examples
# ./scan-date.sh -i alpine
# ./scan-date.sh -i gcr.io/distroless/base-debian11:nonroot-amd64

set -Eeo pipefail

# exception handling
error_exit()
{
    echo "$1"
    exit 1
}

result_exit()
{
    echo "$CREATED_DATE" > $RES_FILE
    if [ "$DONT_OUTPUT_RESULT" == "false" ]; then  
        echo "$IMAGE_LINK >>> $CREATED_DATE               "
    fi    
    exit 0
}

#var init
CREATED_DATE=''
DONT_OUTPUT_RESULT=false
IMAGE_LINK=''

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

JSON_FILE=$SCRIPTPATH'/inspect.json'
RES_FILE=$SCRIPTPATH'/scan-date.result'
rm -f $RES_FILE

# read the options
ARGS=$(getopt -o i: --long dont-output-result,image: -n $0 -- "$@")
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
        --) shift ; break ;;
        *) echo "Wrong usage! Try '$0 --help' for more information." ; exit 2 ;;
    esac
done

# check the date of the image by downloading metadata
echo -ne "  $IMAGE_LINK >>> check date\033[0K\r"
skopeo inspect "docker://$IMAGE_LINK" > $JSON_FILE
CREATED_DATE=(`jq '.Created' $JSON_FILE | cut -b 2-11`) \
    || error_exit "$IMAGE_LINK >>> error image inspect"
# if a copy error exit with error
if [ $? -ne 0 ]; then
    echo "$IMAGE_LINK >>> can't inspect, check image name and tag"
    exit 1
fi 

# if date is normal then result and exit
if [ "$CREATED_DATE" != "0001-01-01" ] ; then
    result_exit
fi    
 
# If the metadata does not specify the date of image build (for example, as in distroless)
# we will find it through the date of the most recent file,
# we also scan files in unpacked layers, as in the block above
echo -ne "  $IMAGE_LINK >>> extended check date\033[0K\r"

# download and unpack image or use cache 
/bin/bash $SCRIPTPATH/scan-download-unpack.sh -i $IMAGE_LINK

# var init for advanced date search
CREATED_DATE_EXT=0

# Go through layers-archives for extended date searching
for f in "$SCRIPTPATH/image"/*.tar
do
    # Unpack the layer into a folder
    # Sometimes rm and tar occurs an error
    # Therefore disable error checking
    set +Eeo pipefail
    rm -rf "$SCRIPTPATH/image/0" &>/dev/null
    mkdir "$SCRIPTPATH/image/0" &>/dev/null
    # if you run tar embedded in alpine (OCI-image based on alpine)
    # then there is a tar of a different version (busybox) and occurs errors when unpacking
    # unreadable files, (in this place unreadable files may occur)
    # which causes the script to stop.
    # Therefore it is necessary to additionally install GNU-tar in the alpine-OCI-image
    # Also exclude dev/* because nonroot will cause a device creation error
    tar --ignore-failed-read --one-file-system --exclude dev/* -xf "$f" -C "$SCRIPTPATH/image/0" &>/dev/null
    # Check if there is at least one application or x-shellscript in current layer
    LIST_TAR_FILES=()
    # sometimes "permission denied" was here
    LIST_TAR_FILES=(`find image/0 -type f`)
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
