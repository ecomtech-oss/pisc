#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2026

# Show mime-types statistic for image

# Usage
#     ./mime-helper.sh -i image_link
# Available options:
#     -i, --image string                only this image will be checked. Example: -i r0binak/mtkpi:v1.3
# Example
#     ./mime-helper.sh -i r0binak/mtkpi:v1.3


set -Eeo pipefail

# exception handling
error_exit()
{
    echo "$1"
    exit 2
}

# var init
IMAGE_LINK=''

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# get exported var with default value if it is empty
: "${OUT_DIR:=/tmp}"
# check debug mode to debug child scripts
DEBUG=''
if [[ "$-" == *x* ]]; then
    DEBUG='-x '
fi

U_LINE2='\U02550\U02550\U02550\U02550\U02550\U02550\U02550\U02550'
U_LINE=$U_LINE2$U_LINE2$U_LINE2$U_LINE2$U_LINE2

IMAGE_DIR=$OUT_DIR'/image'
TMP_FILE=$OUT_DIR'/virustotal.tmp'
SORT_FILE=$OUT_DIR'/virustotal.sort'

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
    eval tar --ignore-failed-read --one-file-system --no-same-owner --no-same-permissions --mode=+w --exclude dev/* -xf "$1" -C "$IMAGE_DIR/0" 2>/dev/null
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
    if [[ ! -f $1.mime-x.sort ]] && [[ ! -f $1.mime-no-x.sort ]]; then
        layer="${f##*/}"
        layer="${layer%.*}"
        layer=${layer:0:8}
        echo -ne "  $layer >>> check mime-types\033[0K\r"
        for (( ii=0; ii<${#LIST_TAR_FILES[@]}; ii++ ));
        do
            MIME_TYPE=(`file --mime-type ${LIST_TAR_FILES[$ii]} | awk '{print $2}'`)
            echo "$MIME_TYPE ${LIST_TAR_FILES[$ii]#$IMAGE_DIR'/0/'}" >> "$1.mime.tmp"
        done
        # sort output
        if [ -f $1.mime.tmp ]; then
            mv $1.mime.tmp $1.mime &>/dev/null
            awk '{print $1}' $1.mime | sort | uniq -c | sort -k2rn > $1.mime.sort
        fi
    fi    
}

# download and unpack image or use cache 
/bin/bash $DEBUG$SCRIPTPATH/scan-download-unpack.sh -i $IMAGE_LINK

# go through layers-archives
for f in "$IMAGE_DIR"/*.tar
do
    unpack $f
    mime-types $f
done

echo -e "$U_LINE"
# print result
for f in "$IMAGE_DIR"/*.tar
do
    layer="${f##*/}"
    layer="${layer%.*}"
    layer=${layer:0:8}
    echo $layer" (`stat -c%s "$f" | numfmt --to=iec`)"
    if [ -f $f.mime.sort ]; then
        cat $f.mime.sort
    fi    
done

exit 0
