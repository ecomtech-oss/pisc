#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2026

# Usage
#     ./scan-new-tags.sh [--dont-output-result] -i image_link
# Available options:
#     --dont-output-result              don't output result into console, only into file
#     -i, --image string                only this image will be checked. Example: -i gcr.io/distroless/base-debian11:nonroot-amd64

# Examples
# ./scan-new-tags.sh -i alpine:3.10
# ./scan-new-tags.sh -i gcr.io/distroless/base-debian11:nonroot-amd64

set -Eeo pipefail

# exception handling
error_exit()
{
    echo "$1"
    exit 2
}

#var init
DONT_OUTPUT_RESULT=false
IMAGE_LINK=''

C_RED='\033[0;31m'
C_NIL='\033[0m'
EMOJI_INFO='\U1F4A1' # bulb

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# get exported var with default value if it is empty
: "${OUT_DIR:=/tmp}"
# check debug mode to debug child scripts and external tools
DEBUG_SKOPEO=''
if [[ "$-" == *x* ]]; then
    DEBUG_SKOPEO='--debug '
fi

# result of skopeo inspect of source image (don't remove)
JSON_FILE=$OUT_DIR'/inspect.json'
# result of skopeo inspect of new-version images
JSON_TEMP_FILE=$OUT_DIR'/inspect-temp.json'
# result output
RES_FILE=$OUT_DIR'/scan-new-tags.result'
#temp version file after sorting
SORT_FILE=$OUT_DIR'/scan-new-tags.sort'
#temp version file before sorting
TMP_FILE=$OUT_DIR'/scan-new-tags.tmp'
rm -f $JSON_TEMP_FILE $RES_FILE $SORT_FILE $TMP_FILE

SKOPEO_AUTH_FLAG=''
AUTH_FILE=$SCRIPTPATH'/auth.json'
if [ -f "$AUTH_FILE" ]; then
    SKOPEO_AUTH_FLAG="--authfile=$AUTH_FILE"
fi

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

# download metadata or use cache
if [ ! -f $JSON_FILE ]; then
    echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> inspect image\033[0K\r"
    skopeo inspect "docker://$IMAGE_LINK" $SKOPEO_AUTH_FLAG $DEBUG_SKOPEO> $JSON_FILE
    # if a copy error exit with error
    if [ $? -ne 0 ]; then
        error_exit "$IMAGE_LINK >>> can't inspect, check image name and tag"
    fi 
fi

echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> find newer tags\033[0K\r"

LIST_TAG=(`jq '.RepoTags[]' $JSON_FILE | cut -c2- | rev | cut -c2- | rev`) \
    || error_exit "$IMAGE_LINK >>> error reading $JSON_FILE"

# removing tags without a version and platform specific
for (( i=0; i<${#LIST_TAG[@]}; i++ ));
do
    if [[ ${LIST_TAG[$i]} == *"."* ]] &&
    [[ ${LIST_TAG[$i]} != *"amd"* ]] &&
    [[ ${LIST_TAG[$i]} != *"amd64"* ]] &&
    [[ ${LIST_TAG[$i]} != *"arm"* ]] &&
    [[ ${LIST_TAG[$i]} != *"arm64"* ]] &&
    [[ ${LIST_TAG[$i]} != *"ubi"* ]] &&
    [[ ${LIST_TAG[$i]} != *"s390x"* ]] &&
    [[ ${LIST_TAG[$i]} != *"ppc64le"* ]] &&
    [[ ${LIST_TAG[$i]} =~ [0-9] ]]; then	  
        echo ${LIST_TAG[$i]} >> $TMP_FILE
    fi    
done    

# sorting by version correctly
if [ -f $TMP_FILE ]; then
    sort -V $TMP_FILE > $SORT_FILE
fi 

LIST_VER=()
if [ -f $SORT_FILE ]; then
    LIST_VER=(`awk '{print $1}' $SORT_FILE`)
    # leave versions more than in the image tag
    IMAGE_TAG=${IMAGE_LINK#*:}
    IMAGE_NAME=${IMAGE_LINK%%:*}
    LIST_VER_NEW=()
    IS_NEWER=false
    STRING_VER_NEW=""
    for (( i=0; i<${#LIST_VER[@]}; i++ ));
    do
        if [ "$IS_NEWER" = true ]; then
            LIST_VER_NEW+=(${LIST_VER[$i]})
            STRING_VER_NEW="$STRING_VER_NEW ${LIST_VER[$i]}"
        fi	    
        if [ "${LIST_VER[$i]}" == "$IMAGE_TAG" ]; then
            IS_NEWER=true
        fi	  
    done
fi    

# go back through the list and check the build date
CREATED_DATE_LAST='1970-01-01'
for (( i=0; i<${#LIST_VER_NEW[@]}; i++ ));
do
    # look at the last 3 dates to select the last one  
    if (( $i < 3 )); then 
        IMAGE_CHECK=$IMAGE_NAME":"${LIST_VER_NEW[${#LIST_VER_NEW[@]}-$i-1]}
        # we do not catch exceptions here because this is not an important functionality
        skopeo inspect "docker://$IMAGE_CHECK" $SKOPEO_AUTH_FLAG $DEBUG_SKOPEO> $JSON_TEMP_FILE
        CREATED_DATE_NEW=(`jq '.Created' $JSON_TEMP_FILE | cut -b 2-11`)
        DIFF_DAYS=$(( ($(date -d $CREATED_DATE_NEW +%s) - $(date -d $CREATED_DATE_LAST +%s)) / 86400 ))
        if (( $DIFF_DAYS > 0 )); then
            CREATED_DATE_LAST=$CREATED_DATE_NEW
        fi
    fi
done

# draw beauty table of versions
echo $STRING_VER_NEW > $TMP_FILE
xargs -n5 < $TMP_FILE | column -t -s' ' > $SORT_FILE
sed 's/^/   /' $SORT_FILE > $TMP_FILE
STRING_VER_NEW=$(<$TMP_FILE)

# result: output to console and write to file
RESULT_MESSAGE="$CREATED_DATE_LAST"
if [ ! -z "${STRING_VER_NEW}" ]; then
    RESULT_MESSAGE=${RESULT_MESSAGE}$'\n'"$EMOJI_INFO $C_RED${IMAGE_LINK}$C_NIL >>> use a newer tags:"
    RESULT_MESSAGE=${RESULT_MESSAGE}$'\n'$STRING_VER_NEW
fi
echo "$RESULT_MESSAGE" > $RES_FILE
if [ "${DONT_OUTPUT_RESULT}" == "false" ]; then  
    echo -e "$RESULT_MESSAGE"
fi 

exit 0
