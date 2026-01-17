#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2025

# Usage
#     ./scan-trivy.sh [-i image_link | --tar /path/to/private-image.tar]
# Available options:
#     --ignore-errors                   ignore errors (instead, write to $ERROR_FILE)
#     -i, --image string                only this image will be checked. Example: -i kapistka/log4shell:0.0.3-nonroot
#     --offline-feeds                   use a self-contained offline image with pre-downloaded vulnerability feeds (e.g., :latest-feeds)
#     --tar string                      check local image-tar. Example: --tar /path/to/private-image.tar
#     --trivy-server string             use trivy server if you can. Specify trivy URL, example: --trivy-server http://trivy.something.io:8080
#     --trivy-token string              use trivy server if you can. Specify trivy token, example: --trivy-token 0123456789abZ
# Example
#     ./scan-trivy.sh -i kapistka/log4shell:0.0.3-nonroot


set -Eeo pipefail

# var init
IGNORE_ERRORS=false
IMAGE_LINK=''
IS_ERROR=false
RESULT_MESSAGE=''
OFFLINE_FEEDS_FLAG=''
TRIVY_SERVER=''
TRIVY_TOKEN=''

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# check debug mode to debug child scripts
DEBUG=''
DEBUG_TRIVY='2>/dev/null'
if [[ "$-" == *x* ]]; then
    DEBUG='-x '
    DEBUG_TRIVY='--debug'
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

# default tar path
INPUT_FILE=$OUT_DIR/image.tar
# trivy output
CSV_FILE=$OUT_DIR'/scan-trivy.csv'
# result this script for main output
RES_FILE=$OUT_DIR'/scan-trivy.result'
# error file
ERROR_FILE=$OUT_DIR'/scan-trivy.error'
# template file
TMPL_FILE=$SCRIPTPATH'/trivy.tmpl'
eval "rm -f $CSV_FILE $RES_FILE $ERROR_FILE"
touch $RES_FILE

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
ARGS=$(getopt -o i: --long ignore-errors,image:,offline-feeds,tar:,trivy-server:,trivy-token: -n $0 -- "$@")
eval set -- "$ARGS"
debug_set true

# extract options and their arguments into variables.
while true ; do
    case "$1" in
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
        --offline-feeds)
            case "$2" in
                "") shift 1 ;;
                *) OFFLINE_FEEDS=true ; shift 1 ;;
            esac ;;
        --tar)
            case "$2" in
                "") shift 2 ;;
                *) INPUT_FILE=$2 ; shift 2 ;;
            esac ;;
        --trivy-server)
            case "$2" in
                "") shift 2 ;;
                *) TRIVY_SERVER=$2 ; shift 2 ;;
            esac ;;
        --trivy-token)
            case "$2" in
                "") shift 2 ;;
                *) debug_set false ; TRIVY_TOKEN=$2 ; debug_set true ; shift 2 ;;
            esac ;;
        --) shift ; break ;;
        *) echo "Wrong usage! Try '$0 --help' for more information." ; exit 2 ;;
    esac
done

# offline mode
if [[ "$OFFLINE_FEEDS" = true ]] && [[ -d "/opt/db/trivy" ]]; then
    OFFLINE_FEEDS_FLAG='--skip-db-update'
  if  (touch "/opt/db/trivy/.check_rw" ) 2>/dev/null; then
      OFFLINE_FEEDS_DIR=$OFFLINE_FEEDS_DIR'/trivy'
  else
    OFFLINE_FEEDS_DIR="$OUT_DIR"'/.cache/trivy'
    if [[ ! -d "$OFFLINE_FEEDS_DIR" ]]; then
      mkdir -p "$OUT_DIR"'/.cache/trivy' && cp -r /opt/db/trivy "$OUT_DIR"'/.cache/'
    fi
  fi
else
    OFFLINE_FEEDS_FLAG=''
    OFFLINE_FEEDS_DIR=$OUT_DIR'/.cache/trivy'
    mkdir -p "$OFFLINE_FEEDS_DIR"
fi
echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> scan vulnerabilities by trivy\033[0K\r"

# use template

# {{- range . }}
# {{- range .Vulnerabilities }}
# {{- $score := "" -}}
# {{- range $key, $cvss := .CVSS }}
# {{- if eq (printf "%s" $key) "nvd" }}
# {{- $score = printf "%.1f" $cvss.V3Score }}
# {{- end }}
# {{- end }}
# {{ .VulnerabilityID }}|{{ .Severity }}|{{ $score }}|{{ .FixedVersion }}|{{ .PkgName }}
# {{- end }}
# {{- end }}

# if trivy-token is not specified, then use the local database (slow, if the script is in a OCI-image, the CI/CD speed suffers)
debug_set false
if [ -z "$TRIVY_TOKEN" ]; then
    debug_set true
    eval "trivy image --cache-dir $OFFLINE_FEEDS_DIR --scanners vuln $OFFLINE_FEEDS_FLAG --format template --template @$TMPL_FILE -o $CSV_FILE --input $INPUT_FILE $DEBUG_TRIVY" || \
    error_exit "error trivy client"
# if trivy-token is specified, then we use the trivy-server
else
    eval "trivy image --cache-dir $OFFLINE_FEEDS_DIR --scanners vuln $OFFLINE_FEEDS_FLAG --format template --template @$TMPL_FILE -o $CSV_FILE --input $INPUT_FILE --server $TRIVY_SERVER --token $TRIVY_TOKEN --timeout 15m $DEBUG_TRIVY" || \
    eval "trivy image --cache-dir $OFFLINE_FEEDS_DIR --scanners vuln $OFFLINE_FEEDS_FLAG --format template --template @$TMPL_FILE -o $CSV_FILE --input $INPUT_FILE $DEBUG_TRIVY" || \
    error_exit "error trivy server/client"
fi
debug_set true

# get values
LIST_CVE=()
LIST_SEVERITY=()
LIST_SCORE=()
LIST_FIXED=()
LIST_PKG=()
while IFS='|' read -r cve severity score fix package; do
    if [[ "$cve" =~ CVE ]]; then
        LIST_CVE+=("$cve")
        LIST_SEVERITY+=("$severity")
        LIST_SCORE+=("$score")
        LIST_FIXED+=("$fix")
        # remove windows line-ending
        package=${package//$'\r'/}
        LIST_PKG+=("$package")
    fi
done < "$CSV_FILE"
LIST_length=${#LIST_CVE[@]}

# normalize and print values
for (( i=0; i<$LIST_length; i++ ));
do
    if [ "${LIST_FIXED[$i]}" = "" ]; then
        LIST_FIXED[$i]='-'
    else
        LIST_FIXED[$i]='+'
    fi
    if [ "${LIST_SCORE[$i]}" = "" ]; then
        LIST_SCORE[$i]='-'
    fi
    echo "${LIST_PKG[$i]} ${LIST_CVE[$i]} ${LIST_SEVERITY[$i]} ${LIST_SCORE[$i]} ${LIST_FIXED[$i]}" >> $RES_FILE
done

exit 0
