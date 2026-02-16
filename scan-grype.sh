#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2026

# Usage
#     ./scan-grype.sh [-i image_link | --tar /path/to/private-image.tar]
# Available options:
#     --ignore-errors                   ignore errors (instead, write to $ERROR_FILE)
#     -i, --image string                only this image will be checked. Example: -i kapistka/log4shell:0.0.3-nonroot
#     --offline-feeds                   use a self-contained offline image with pre-downloaded vulnerability feeds (e.g., :latest-feeds)
#     --tar string                      check local image-tar. Example: --tar /path/to/private-image.tar
# Example
#     ./scan-grype.sh -i kapistka/log4shell:0.0.3-nonroot


set -Eeo pipefail

# var init
IGNORE_ERRORS=false
IMAGE_LINK=''
IS_ERROR=false
OFFLINE_FEEDS=false
RESULT_MESSAGE=''

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# get exported var with default value if it is empty
: "${OUT_DIR:=/tmp}"
export TMPDIR=$OUT_DIR
# check debug mode to debug child scripts
DEBUG=''
DEBUG_GRYPE='-q'
if [[ "$-" == *x* ]]; then
    DEBUG='-x '
    DEBUG_GRYPE='-vv'
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
# grype output
CSV_FILE=$OUT_DIR'/scan-grype.csv'
# result this script for main output
RES_FILE=$OUT_DIR'/scan-grype.result'
# error file
ERROR_FILE=$OUT_DIR'/scan-grype.error'
# template file
TMPL_FILE=$SCRIPTPATH'/grype.tmpl'
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
ARGS=$(getopt -o i: --long ignore-errors,image:,offline-feeds,tar: -n $0 -- "$@")
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
        --) shift ; break ;;
        *) echo "Wrong usage! Try '$0 --help' for more information." ; exit 2 ;;
    esac
done

echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> scan vulnerabilities by grype\033[0K\r"

# offline mode
if [[ "$OFFLINE_FEEDS" = true ]] && [[ -d "/opt/db/grype" ]]; then
  export GRYPE_DB_AUTO_UPDATE=false
  if (touch "/opt/db/grype/.check_rw" ) 2>/dev/null; then
    export GRYPE_DB_CACHE_DIR=/opt/db/grype
  else
    export GRYPE_DB_CACHE_DIR="$OUT_DIR"'/.cache/grype'
    if [[ ! -d "$GRYPE_DB_CACHE_DIR" ]]; then
      mkdir -p "$OUT_DIR"'/.cache/grype' && cp -r /opt/db/grype/ "$OUT_DIR"'/.cache/'
    fi
  fi
else
    export GRYPE_DB_AUTO_UPDATE=true
    export GRYPE_DB_CACHE_DIR=$OUT_DIR'/.cache/grype'
    mkdir -p "$GRYPE_DB_CACHE_DIR"

fi

# use one-string template

# {{- range .Matches }}{{- $cvss := .Vulnerability.Cvss }}
# {{- if gt (len $cvss) 0 }}{{- $first := index $cvss 0 }}
# {{- $score := printf "%.1f" $first.Metrics.BaseScore }}
# {{ .Vulnerability.ID }}|{{ .Vulnerability.Severity }}|
# {{ $score }}|{{ .Vulnerability.Fix.State }}|{{ .Artifact.Name }}
# {{ else }}{{ .Vulnerability.ID }}|{{ .Vulnerability.Severity }}||
# {{ .Vulnerability.Fix.State }}|{{ .Artifact.Name }}{{ end }}{{ "\n" -}}{{- end }}
grype file:$INPUT_FILE --by-cve -o template -t $TMPL_FILE $DEBUG_GRYPE > $CSV_FILE \
    || error_exit "error grype"

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
        LIST_PKG+=("$package")
    fi
done < "$CSV_FILE"
LIST_length=${#LIST_CVE[@]}

# normalize and print values
for (( i=0; i<$LIST_length; i++ ));
do
    if [ "${LIST_SEVERITY[$i]}" = "Critical" ]; then
        LIST_SEVERITY[$i]='CRITICAL'
    elif [ "${LIST_SEVERITY[$i]}" = "High" ]; then
        LIST_SEVERITY[$i]='HIGH'
    elif [ "${LIST_SEVERITY[$i]}" = "Medium" ]; then
        LIST_SEVERITY[$i]='MEDIUM'
    elif [ "${LIST_SEVERITY[$i]}" = "Low" ] || [ "${LIST_SEVERITY[$i]}" = "Negligible" ]; then
        LIST_SEVERITY[$i]='LOW'
    else
        LIST_SEVERITY[$i]='UNKNOWN'
    fi
    if [ "${LIST_FIXED[$i]}" = "fixed" ]; then
        LIST_FIXED[$i]='+'
    else
        LIST_FIXED[$i]='-'
    fi
    if [ "${LIST_SCORE[$i]}" = "" ]; then
        LIST_SCORE[$i]='-'
    fi
    echo "${LIST_PKG[$i]} ${LIST_CVE[$i]} ${LIST_SEVERITY[$i]} ${LIST_SCORE[$i]} ${LIST_FIXED[$i]}" >> $RES_FILE
done

exit 0
