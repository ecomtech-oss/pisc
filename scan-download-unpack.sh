#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2024

# Examples
# ./scan-download-unpack.sh -i gcr.io/distroless/base-debian11:nonroot-amd64

set -Eeo pipefail

# exception handling
error_exit()
{
    echo "$1"
    exit 1
}

#var init
IMAGE_LINK=''
DONT_DOWNLOAD=false

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

RES_FILE=$SCRIPTPATH'/scan-download-unpack.result'

# read the options
ARGS=$(getopt -o i: --long image: -n $0 -- "$@")
eval set -- "$ARGS"

# extract options and their arguments into variables.
while true ; do
    case "$1" in 
        -i|--image)
            case "$2" in
                "") shift 2 ;;
                *) IMAGE_LINK=$2 ; shift 2 ;;
            esac ;;
        --) shift ; break ;;
        *) echo "Wrong usage! Try '$0 --help' for more information." ; exit 2 ;;
    esac
done

# check last download image
if [ -f $RES_FILE ]; then
    LAST_DOWNLOAD=$(<$RES_FILE)
    if [ "$LAST_DOWNLOAD" == "$IMAGE_LINK" ]; then
        if [ -d "$SCRIPTPATH/image" ]; then
            exit 0
        fi    
    fi
fi    

rm -f $SCRIPTPATH/image.tar &>/dev/null
# copy image to archive
echo -ne "  $IMAGE_LINK >>> copy\033[0K\r"
skopeo copy "docker://$IMAGE_LINK" "docker-archive:$SCRIPTPATH/image.tar" &>/dev/null \
    || error_exit "$IMAGE_LINK >>> can't copy, check image name and tag"   

echo -ne "  $IMAGE_LINK >>> unpack image\033[0K\r"
#Sometimes rm and tar occurs an error
#Therefore disable error checking
set +Eeo pipefail
#Unpack to the folder "image"
rm -rf $SCRIPTPATH/image &>/dev/null
mkdir $SCRIPTPATH/image &>/dev/null
tar -xf $SCRIPTPATH/image.tar -C $SCRIPTPATH/image &>/dev/null
#Turning error checking back on
set -Eeo pipefail

echo "$IMAGE_LINK" > $RES_FILE
exit 0
