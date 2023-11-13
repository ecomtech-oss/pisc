#!/bin/bash
#Public OCI-Image Security Checker
#Author: @kapistka, 2023

set -Eeo pipefail

usage() {
  cat <<EOF

Public OCI-Image Security Checker
Author: @kapistka, 2023

                    ##         .
              ## ## ##        ==
           ## ## #P WN       ===
       /""""""""""""""""\___/ ===
      {        /              /
       \______ o          __/
         |||||\        __/
          |||||\______/

Gives a result = 1 if any:
 - image older then N days (365 by default)
 - has exploitable vulnerabilities
 - contains malware
 - non-version tag (:latest)

Usage: $(basename "${BASH_SOURCE[0]}") [-h] [-l] [-m virustotal_api_key] [-v vulners_api_key] [-t trivy_token] image_link [-w] [-f filepath]

Available options:
 -h              Print this help and exit
 -l              Check non-version tag (:latest and the same)
 -f file_path    Check all images from file. Example: -f images.txt
 -v api_key      Check vulners.com for exploitable vulnerabilities. Specify vulners API-key, example: -v 0123456789ABCDXYZ
 -m api_key      Check virustotal.com for malware. Specify virustotal API-key, example: -m 0123456789abcdef
 -w              Wait for bypass virustotal.com limits (if it happened)
 -t token        Use trivy server if you can. Specify trivy token, example: -t 0123456789abZ
 image_link      Link to OCI-image

Examples:
  ./scan.sh alpine:latest
  ./scan.sh -l -m 0123XYZ -v 0123def -t 0123abZ -f images.txt
EOF
  exit 0
}

#var init (can be changed)

#trivy-server (used if trivy-token is specified)
TRIVY_SERVER='http://trivy-server:8080'
#vulners endpoint (used if -v api_key is specified)
VULNERS_ENDPOINT='https://vulners.com'
#Wait while virustotal analyzes the image (seconds)
VIRUSTOTAL_SLEEP_TIME_AFTER_UPLOAD=180
#If a limited account is used, then after 4 requests, wait as many seconds
VIRUSTOTAL_SLEEP_TIME_AFTER_LIMIT=60
#The image is considered outdated if the build was more than N days ago
OLD_BUILD_DAYS=365

#var init (don't change)
VULNERS_API_KEY=''
VIRUSTOTAL_API_KEY=''
VIRUSTOTAL_REQUEST_COUNT=0
VIRUSTOTAL_REQUEST_LIMIT=false
SCAN_RETURN_CODE=0
CHECK_LATEST=false
TRIVY_TOKEN=''

#arguments parsing
FILE_SCAN=''
IS_LIST_IMAGES=false
while getopts ":f:v:m:t:whl" o; do
  case "${o}" in
    h)  usage ;;
    l)  CHECK_LATEST=true ;;
    f)  FILE_SCAN="${OPTARG}" ;;
    v)  VULNERS_API_KEY="${OPTARG}" ;;
    m)  VIRUSTOTAL_API_KEY="${OPTARG}" ;;
    w)  VIRUSTOTAL_REQUEST_LIMIT=true ;;
    t)  TRIVY_TOKEN="${OPTARG}" ;;
  esac
done
shift $((OPTIND-1))

#arguments check
if [ ! -z "${FILE_SCAN}" ]; then
  if [ -f ${FILE_SCAN} ]; then
    IS_LIST_IMAGES=true
    LIST_IMAGES=()
    LIST_IMAGES=(`awk '{print $1}' ${FILE_SCAN}`)
  else
    echo "${FILE_SCAN} >>> file not found"
    exit 2
  fi
else
  if [ -z "${1}" ]; then 
    echo "please specify image or file -f"
    exit 2
  fi  
fi
if [ -z "${VIRUSTOTAL_API_KEY}" ]; then
  echo "WARNING! No malware checks. Specify virustotal API-key"
fi
if [ -z "${VULNERS_API_KEY}" ]; then
  echo "WARNING! No vulnerability checks. Specify vulners API-key"
fi

#exception handling
error_exit()
{
  echo "$1"
  exit 1
}

#Waiting between requests on virustotal -
#limit on some free account methods,
#is disabled in the script parameters (if there is no -w)
#1 minute delay after 4 requests
virustotal_sleep() {
  #If there is no limit of 4 requests per minute during testing
  #or there is a premium-API-key
  #then you can run the script without the -w parameter, then there will be no waiting.
  #If restrictions are observed, run the script with the -w parameter
  if [ "$VIRUSTOTAL_REQUEST_LIMIT" = true ]; then 
    if [ $(( $VIRUSTOTAL_REQUEST_COUNT % 4 )) -eq 0 ] && (( $VIRUSTOTAL_REQUEST_COUNT > 0 )); then
      for (( ii=0; ii<$VIRUSTOTAL_SLEEP_TIME_AFTER_LIMIT; ii++ ));
      do
        echo -ne "  ${1} >>> virustotal - wait $(($VIRUSTOTAL_SLEEP_TIME_AFTER_LIMIT-$ii)) sec (account limit)\033[0K\r" 
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
      virustotal_sleep "${1}"
      #one hash per request
      echo -ne "  ${1} >>> virustotal hash search $((i+1))/$COUNT_LIST_VIRUSTOTAL\033[0K\r"
      curl -s --fail --request GET \
        --url "https://www.virustotal.com/api/v3/search?query=${LIST_VIRUSTOTAL_SHA256[$i]}" \
        --header "x-apikey: ${VIRUSTOTAL_API_KEY}" \
        -o "virustotal.json" \
        || error_exit "${1} >>> error virustotal.com: please check api-key, internet connection and retry"
      #Checking for an error above does not only check the upstream curl, for example, for the absence of Internet,
      #but also the underlying jq, for example, if the API key is not valid
      #therefore, we report general information about the problem
      LIST_VIRUSTOTAL_MALICIOUS=(`jq '.data[]?.attributes?.last_analysis_stats?.malicious' virustotal.json`) \
      || error_exit "${1} >>> error virustotal.com: please check api-key"
      LIST_VIRUSTOTAL_SUSPICIOUS=(`jq '.data[]?.attributes?.last_analysis_stats?.suspicious' virustotal.json`) \
      || error_exit "${1} >>> error virustotal.com: please check api-key"
      #Increasing the request counter (this method is limited by the number per minute/day/month)
      VIRUSTOTAL_REQUEST_COUNT=$((VIRUSTOTAL_REQUEST_COUNT+1))  
      #if the result is empty mark that the layer needs to be sent for scanning
      if [ -z "${LIST_VIRUSTOTAL_MALICIOUS}" ]; then
        LIST_VIRUSTOTAL_RESULT[$i]='unknown'
      #if zeros then mark that the layer is good
      elif [ ${LIST_VIRUSTOTAL_MALICIOUS} -eq 0 ] && [ ${LIST_VIRUSTOTAL_SUSPICIOUS} -eq 0 ]; then 
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

#Single image verification
scan_image() {
  echo "____________________"
  echo -ne "  ${1} >>> start scan    \033[0K\r"
  
  #remove files from previous analysis of another image
  rm -f image.tar \
        trivy-report.json \
        result.txt \
        vuln.json \
        vuln.txt \
        inspect.json \
        ver.txt \
        &>/dev/null

  #Check the absence of a digit in the tag (evolution of "latest")
  IS_LATEST=false
  if [ "$CHECK_LATEST" = true ]; then
    echo -ne "  ${1} >>> check non version tag\033[0K\r"
    IMAGE_DIGEST=${1#*@}
    if [[ ${IMAGE_DIGEST} != *"@"* ]]; then
      IMAGE_TAG=${1#*:}
      if [[ ! ${IMAGE_TAG} =~ [0-9] ]]; then
        IS_LATEST=true
      fi
    fi
  fi  

  #check the date of the image by downloading metadata
  echo -ne "  ${1} >>> check date\033[0K\r"
  skopeo inspect "docker://${1}" > inspect.json
  CREATED_DATE=(`jq '.Created' inspect.json | cut -b 2-11`) \
  || error_exit "${1} >>> error image inspect"
  #if a copy error exit the function
  if [ $? -ne 0 ]; then
    echo "${1} >>> can't inspect, check image name and tag"
    SCAN_RETURN_CODE=$?
    return $?
  fi 
  #var init to define a more recent build
  CREATED_DATE_LAST=$CREATED_DATE
  #var init for advanced date search in case the date is not in the metadata
  CREATED_DATE_EXT=0

  #copy image to archive
  echo -ne "  ${1} >>> copy\033[0K\r"
  skopeo copy "docker://${1}" "docker-archive:./image.tar" &>/dev/null
  #if a copy error exit the function
  if [ $? -ne 0 ]; then
    echo "${1} >>> can't inspect, check image name and tag"
    SCAN_RETURN_CODE=$?
    return $?
  fi

  IS_MALWARE=false
  #If virustotal scan is required
  #or the date of the image is not found in the metadata
  #then unpack the tar and work with layers
  if [ ! -z "${VIRUSTOTAL_API_KEY}" ] || [ "${CREATED_DATE}" == "0001-01-01" ]; then
    echo -ne "  ${1} >>> unpack image\033[0K\r"
    LIST_VIRUSTOTAL_SHA256=()
    #Sometimes rm and tar occurs an error
    #Therefore disable error checking
    set +Eeo pipefail
    #Unpack to the folder "image"
    rm -rf image &>/dev/null
    mkdir image &>/dev/null
    tar -xf image.tar -C image &>/dev/null
    #Turning error checking back on
    set -Eeo pipefail
    #Go through layers-archives
    for f in "image"/*.tar
    do
      #Unpack the layer into a folder
      #Sometimes rm and tar occurs an error
      #Therefore disable error checking
      set +Eeo pipefail
      rm -rf "image/0" &>/dev/null
      mkdir "image/0" &>/dev/null
      #if you run tar embedded in alpine (OCI-image based on alpine)
      #then there is a tar of a different version (busybox) and occurs errors when unpacking
      #unreadable files, (in this place unreadable files may occur)
      #which causes the script to stop.
      #Therefore it is necessary to additionally install GNU-tar in the alpine-OCI-image
      #Also exclude dev/* because nonroot will cause a device creation error
      tar --ignore-failed-read --one-file-system --exclude dev/* -xf "$f" -C "image/0" &>/dev/null
      #Turning error checking back on
      set -Eeo pipefail
      #Check if there is at least one application or x-shellscript in current layer
      LIST_TAR_FILES=()
      LIST_TAR_FILES=(`find image/0 -type f`)

      #If virustotal scan needed check the mime types
      if [ ! -z "${VIRUSTOTAL_API_KEY}" ]; then
        echo -ne "  ${1} >>> check mime-types\033[0K\r"
        for (( j=0; j<${#LIST_TAR_FILES[@]}; j++ ));
        do
          MIME_TYPE=(`file --mime-type ${LIST_TAR_FILES[$j]} | awk '{print $2}'`)
          if [[ $MIME_TYPE == application/* ]] || [[ $MIME_TYPE == */x-shellscript ]]; then 
            #if application or x-shellscript is found the layer is to be scanned
            filename="${f##*/}"
            filename="${filename%.*}"
            LIST_VIRUSTOTAL_SHA256+=(${filename})
            break
          fi
        done
      fi  

      #If the metadata does not specify the date of image build (for example, as in distroless)
      #we will find it through the date of the most recent file,
      #we also scan files in unpacked layers, as in the block above
      if [ "${CREATED_DATE}" == "0001-01-01" ]; then
        echo -ne "  ${1} >>> extended check date\033[0K\r"
        for (( j=0; j<${#LIST_TAR_FILES[@]}; j++ ));
        do
          d=(`date -r ${LIST_TAR_FILES[$j]} +%s`)
          if (( $d > $CREATED_DATE_EXT )); then
            CREATED_DATE_EXT=$d
          fi
        done
      fi
    done
  fi  

  #If we searched for the date through the files (the block above) then update the date of the image
  if (( $CREATED_DATE_EXT > 0 )); then
    CREATED_DATE=(`date -d @$CREATED_DATE_EXT "+%Y-%m-%d"`)
  fi
  #Was built more than N days ago
  IS_OLD=false
  if [ "${CREATED_DATE}" != "0001-01-01" ] && [ "${CREATED_DATE}" != "1970-01-01" ]; then
    AGE_DAYS=$(( ($(date +%s) - $(date -d ${CREATED_DATE} +%s)) / 86400 ))
    if awk "BEGIN {exit !(${AGE_DAYS} >= ${OLD_BUILD_DAYS})}"; then
      IS_OLD=true
    fi
  fi

  #If a virustotal scan is required
  if [ ! -z "${VIRUSTOTAL_API_KEY}" ]; then
    #Looking for layer hashes in virustotal
    #Periodic search for related images will return results for the same base layers
    #and they won't have to be re-uploaded for verification
    echo -ne "  ${1} >>> virustotal hash search\033[0K\r"
    LIST_VIRUSTOTAL_RESULT=()
    #COUNT_LIST_VIRUSTOTAL - number of layers to scan
    COUNT_LIST_VIRUSTOTAL=${#LIST_VIRUSTOTAL_SHA256[@]}
    #Mark the values as unknown in advance
    for (( i=0; i<$COUNT_LIST_VIRUSTOTAL; i++ ));
    do
      LIST_VIRUSTOTAL_RESULT[$i]='unknown'  
    done
    virustotal_hash_check "${1}"
    #Upload the layer not found on virustotal for checking
    LIST_VIRUSTOTAL_UPLOAD_ID=()
    #var init that means: was something loaded as a result on virustotal?
    IS_VIRUSTOTAL_UPLOAD=false
    for (( i=0; i<$COUNT_LIST_VIRUSTOTAL; i++ ));
    do
      echo -ne "  ${1} >>> upload to virustotal $((i+1))/$COUNT_LIST_VIRUSTOTAL\033[0K\r"
      LIST_VIRUSTOTAL_UPLOAD_ID+=('')
      if [ "${LIST_VIRUSTOTAL_RESULT[$i]}" == "unknown" ]; then
        TAR_FILE="image/${LIST_VIRUSTOTAL_SHA256[$i]}.tar"
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
              --header "x-apikey: ${VIRUSTOTAL_API_KEY}" \
              -o "virustotal_url.json" \
              || error_exit "${1} >>> error virustotal.com: please check api-key, internet connection and retry"
            VIRUSTOTAL_UPLOAD_URL=(`jq -r '.data' virustotal_url.json`) \
            || error_exit "${1} >>> error virustotal.com: please check api-key"
          fi
          #1 minute delay after 4 requests is the limit of the free virustotal account
          virustotal_sleep "${1}"
          #Upload the file to the desired url
          curl -s --fail --request POST \
            --url "${VIRUSTOTAL_UPLOAD_URL}" \
            --header "accept: application/json" \
            --header "content-type: multipart/form-data" \
            --header "x-apikey: ${VIRUSTOTAL_API_KEY}" \
            -o "virustotal_upload.json" \
            --form file="@${TAR_FILE}" \
            || error_exit "${1} >>> error virustotal.com: please check api-key, internet connection and retry"
          #The method returns the id of the uploaded file, but we don't use it, we immediately look for the hash
          #Increasing the request counter (this method is limited by the number per minute/day/month)
          VIRUSTOTAL_REQUEST_COUNT=$((VIRUSTOTAL_REQUEST_COUNT+1))    
          IS_VIRUSTOTAL_UPLOAD=true
        fi
      fi
    done
    
    #If something was upload to virustotal, you need to wait until the analysis passes
    if [ "$IS_VIRUSTOTAL_UPLOAD" = true ]; then
      #This output is preferable for CI output
      echo -ne "  ${1} >>> wait $VIRUSTOTAL_SLEEP_TIME_AFTER_UPLOAD sec for virustotal analyze\033[0K\r"
      sleep $VIRUSTOTAL_SLEEP_TIME_AFTER_UPLOAD
      #This output is preferable for local start
      #for (( i=0; i<$VIRUSTOTAL_SLEEP_TIME_AFTER_UPLOAD; i++ ));
      #do 
      #  echo -ne "  ${1} >>> wait $(($VIRUSTOTAL_SLEEP_TIME_AFTER_UPLOAD-$i)) sec for virustotal analyze  \033[0K\r"
      #  sleep 1
      #done
      #After checking the hash again
      virustotal_hash_check "${1}"
    fi

    #Generating the result by virustotal
    IS_VIRUSTOTAL_OK=true
    for (( i=0; i<$COUNT_LIST_VIRUSTOTAL; i++ ));
    do
      if [ "${LIST_VIRUSTOTAL_RESULT[$i]}" == "bad" ]; then
        IS_VIRUSTOTAL_OK=false
      fi    
      #We can "tighten" the nuts and do not skip large layers or if there are problems with virustotal
      #if [ "${LIST_VIRUSTOTAL_RESULT[$i]}" == "unknown" ] || [ "${LIST_VIRUSTOTAL_RESULT[$i]}" == "big" ]; then
      #  IS_VIRUSTOTAL_OK=false
      #fi
    done
  fi  

  IS_EXPLOITABLE=false
  IS_HIGH_EPSS=false
  #If vulnerability scanning is required
  if [ ! -z "${VULNERS_API_KEY}" ]; then
    #Scan the archive by trivy and collect vulnerability data
    echo -ne "  ${1} >>> scan vulnerabilities\033[0K\r"
    #If trivy-token is not specified, then use the local database (slow, if the script is in a OCI-image, the CI/CD speed suffers)
    if [ -z "${TRIVY_TOKEN}" ]; then
      trivy image -f json -o trivy-report.json --severity CRITICAL --input image.tar &>/dev/null \
      || error_exit "${1} >>> error trivy: please check connection to internet and retry"
    #If trivy-token is specified, then we use the trivy-server
    else
      trivy image --server $TRIVY_SERVER --timeout 15m --token $TRIVY_TOKEN -f json -o trivy-report.json --severity CRITICAL --input image.tar &>/dev/null \
      || error_exit "${1} >>> error trivy server: please retry then contact the security team"
    fi
    LIST_VULN=(`jq '.Results[]?.Vulnerabilities[]?.VulnerabilityID' trivy-report.json | cut -c2- | rev | cut -c2- | rev`) \
    || error_exit "${1} >>> error trivy parsing, contact the security team"
    LIST_FIXED=(`jq '.Results[]?.Vulnerabilities[]?.FixedVersion' trivy-report.json | cut -c2- | rev | cut -c2- | rev`) \
    || error_exit "${1} >>> error trivy parsing, contact the security team"
    LIST_PKG=(`jq '.Results[]?.Vulnerabilities[]?.PkgName' trivy-report.json | cut -c2- | rev | cut -c2- | rev`) \
    || error_exit "${1} >>> error trivy parsing, contact the security team"
    LIST_length=${#LIST_VULN[@]}

    #Sorting the array and removing duplicates CVE+PKG
    for (( i=0; i<${LIST_length}; i++ ));
    do
      echo "${LIST_VULN[$i]} ${LIST_FIXED[$i]} ${LIST_PKG[$i]}" >> vuln.txt
    done
    LIST_VULN_SORT=()
    LIST_FIXED_SORT=()
    LIST_PKG_SORT=()
    if [ -f vuln.txt ]; then
      sort -u vuln.txt > vuln_sort.txt
      LIST_VULN_SORT=(`awk '{print $1}' vuln_sort.txt`)
      LIST_FIXED_SORT=(`awk '{print $2}' vuln_sort.txt`)
      LIST_PKG_SORT=(`awk '{print $3}' vuln_sort.txt`)
      LIST_length=${#LIST_VULN_SORT[@]}
      #Removing the remaining duplicate CVE with different PKG
      LIST_VULN=()
      LIST_FIXED=()
      LIST_PKG=()
      for (( i=0; i<${LIST_length}; i++ ));
      do
        if [ $i -eq 0 ]; then
          LIST_VULN+=(${LIST_VULN_SORT[0]})
          LIST_FIXED+=(${LIST_FIXED_SORT[0]})
          LIST_PKG+=(${LIST_PKG_SORT[0]})
        else
          if [ "${LIST_VULN_SORT[$i]}" != "${LIST_VULN_SORT[$i-1]}" ]; then
            LIST_VULN+=(${LIST_VULN_SORT[$i]})
            LIST_FIXED+=(${LIST_FIXED_SORT[$i]})
            LIST_PKG+=(${LIST_PKG_SORT[$i]})
          fi	    
        fi	  
      done
      LIST_length=${#LIST_VULN[@]}
    fi  

    #Find out more information about vulnerabilities in vulners.com
    echo -ne "  ${1} >>> check vulners.com\033[0K\r"
    LIST_EXPL=()
    LIST_EPSS=()
    LIST_CVSS=()
    for (( i=0; i<${LIST_length}; i++ ));
    do	
      curl -s --fail -XPOST --compressed -L ${VULNERS_ENDPOINT}/api/v3/search/id \
        -o 'vuln.json' \
        -H 'Content-Type: application/json' --data-binary @- <<EOF
      {
      "id": "${LIST_VULN[$i]}",
      "fields": ["*"],
      "apiKey": "${VULNERS_API_KEY}"
      }
EOF
      LIST_EXPL+=(`jq '.data.documents."'${LIST_VULN[$i]}'".enchantments.exploitation.wildExploited' vuln.json`)
      LIST_EPSS+=(`jq '.data.documents."'${LIST_VULN[$i]}'".epss[0].epss' vuln.json`)
      LIST_CVSS+=(`jq '.data.documents."'${LIST_VULN[$i]}'".cvss.score' vuln.json`)
      #If there is an error accessing the resource, exit the for-loop and the function
      if [ $? -ne 0 ]; then
        echo "${1} >>> error vulners.com: please check api-key, internet connection and retry"
        exit 1
      fi 
    done

    #The presence of an exploit
    for (( i=0; i<${LIST_length}; i++ ));
    do
      if [ "${LIST_EXPL[$i]}" == "true" ]; then
        IS_EXPLOITABLE=true
        break
      fi	  
    done
    #EPSS more than 0.5
    for (( i=0; i<${LIST_length}; i++ ));
    do
      if awk "BEGIN {exit !(${LIST_EPSS[$i]} >= 0.5)}"; then
        IS_HIGH_EPSS=true
        break
      fi
    done
    #quoting EXPL and EPSS to "+"
    for (( i=0; i<${LIST_length}; i++ ));
    do
      if [ "${LIST_FIXED[$i]}" == "ul" ]; then
        LIST_FIXED[$i]=""
      else
        LIST_FIXED[$i]="+"
      fi
      if [ "${LIST_EXPL[$i]}" == "true" ]; then
        LIST_EXPL[$i]="+"
      else
        LIST_EXPL[$i]=""
      fi
    done
  fi

  #Candidates for a new image if it is outdated or there are exploits
  if [ "$IS_OLD" = true ] ||  [ "$IS_EXPLOITABLE" = true ]; then
    LIST_TAG=(`jq '.RepoTags[]' inspect.json | cut -c2- | rev | cut -c2- | rev`)
    for (( i=0; i<${#LIST_TAG[@]}; i++ ));
    #Removing tags without a version and platform specific
    do
      if [[ ${LIST_TAG[$i]} == *"."* ]]; then
        if [[ ${LIST_TAG[$i]} != *"amd"* ]]; then
          if [[ ${LIST_TAG[$i]} != *"arm"* ]]; then
            if [[ ${LIST_TAG[$i]} != *"ubi"* ]]; then
              if [[ ${LIST_TAG[$i]} =~ [0-9] ]]; then		  
                echo ${LIST_TAG[$i]} >> ver.txt
              fi
            fi  
          fi
        fi
      fi	    
    done
    #Sorting by version correctly
    if [ -f ver.txt ]; then
      sort -V ver.txt > ver_sort.txt
    fi  
    LIST_VER=()
    LIST_VER=(`awk '{print $1}' ver_sort.txt`)
    #Leave versions more than in the image tag
    IMAGE_TAG=${1#*:}
    IMAGE_NAME=${1%%:*}
    LIST_VER_NEW=()
    IS_NEWER=false
    STRING_VER_NEW=""
    for (( i=0; i<${#LIST_VER[@]}; i++ ));
    do
      if [ "$IS_NEWER" = true ]; then
        LIST_VER_NEW+=(${LIST_VER[$i]})
        STRING_VER_NEW="${STRING_VER_NEW} ${LIST_VER[$i]}"
      fi	    
      if [ "${LIST_VER[$i]}" == "$IMAGE_TAG" ]; then
        IS_NEWER=true
      fi	  
    done
    #Go back through the list and check the build date
    echo -ne "  ${1} >>> find newer tags\033[0K\r"
    for (( i=0; i<${#LIST_VER_NEW[@]}; i++ ));
    do
      #Look at the last 3 dates to select the last one  
      if (( $i < 3 )); then 
        IMAGE_CHECK=$IMAGE_NAME":"${LIST_VER_NEW[${#LIST_VER_NEW[@]}-$i-1]}
        skopeo inspect "docker://$IMAGE_CHECK" > inspect.json
        CREATED_DATE_NEW=(`jq '.Created' inspect.json | cut -b 2-11`) \
        || error_exit "${1} >>> error image date inspect"
        DIFF_DAYS=$(( ($(date -d ${CREATED_DATE_NEW} +%s) - $(date -d ${CREATED_DATE_LAST} +%s)) / 86400 ))
        if (( $DIFF_DAYS > 0 )); then
          CREATED_DATE_LAST=$CREATED_DATE_NEW
        fi
      fi
      #If there is a copy error, exit the loop and the function
      if [ $? -ne 0 ]; then
        echo "$IMAGE_CHECK >>> can't inspect"
        SCAN_RETURN_CODE=$?
        return $?
      fi 
    done	
  fi

  #Result output
  #Separating strip for CI
  echo -ne "__________                  \033[0K\r"

  #If a virustotal scan is required
  if [ ! -z "${VIRUSTOTAL_API_KEY}" ]; then
    #Output of the virustotal result
    if [ "$IS_VIRUSTOTAL_OK" = false ]; then
      echo "${1} >>> virustotal detected malicious file"                   
    fi
    for (( i=0; i<$COUNT_LIST_VIRUSTOTAL; i++ ));
    do
      if [ "${LIST_VIRUSTOTAL_RESULT[$i]}" == "bad" ]; then
        echo "  https://www.virustotal.com/gui/file/${LIST_VIRUSTOTAL_SHA256[$i]}"
      fi
      if [ "${LIST_VIRUSTOTAL_RESULT[$i]}" == "big" ]; then
        echo "  layer ${LIST_VIRUSTOTAL_SHA256[$i]} is too big, no virustotal scan"
      fi
      if [ "${LIST_VIRUSTOTAL_RESULT[$i]}" == "unknown" ]; then
        echo "  layer ${LIST_VIRUSTOTAL_SHA256[$i]} is unknown for virustotal"
      fi
    done   
  fi  

  #Output of the result by the non-version tag
  if [ "$IS_LATEST" = true ]; then
    echo "${1} >>> non-version tag                      "
  fi

  #Output of the result (EXPL or EPS) if there is an exploit
  if [ "$IS_EXPLOITABLE" = true ]; then
    echo "${1} >>> is subject to a dangerous exploit"
    echo " CVE CVSS EPSS FIX EXPL PKG" >> result.txt
    for (( i=0; i<${LIST_length}; i++ ));
    do
      if [ "${LIST_EXPL[$i]}" == "+" ] || ( awk "BEGIN {exit !(${LIST_EPSS[$i]} >= 0.5)}" ); then
        echo " ${LIST_VULN[$i]} ${LIST_CVSS[$i]} ${LIST_EPSS[$i]} ${LIST_FIXED[$i]} ${LIST_EXPL[$i]} ${LIST_PKG[$i]}" >> result.txt
      fi
    done
    column -t -s' ' result.txt
  #Output of the result (EPS) if the image is old and EPS
  elif [ "$IS_HIGH_EPSS" = true ] && [ "$IS_OLD" = true ]; then
    echo "${1} >>> has a dangerous vulnerability"
    echo " CVE CVSS EPSS FIX EXPL PKG" >> result.txt
    for (( i=0; i<${LIST_length}; i++ ));
    do
      if (( ${LIST_EPSS[$i]} >= 0.5 )); then
        echo " ${LIST_VULN[$i]} ${LIST_CVSS[$i]} ${LIST_EPSS[$i]} ${LIST_FIXED[$i]} ${LIST_EXPL[$i]} ${LIST_PKG[$i]}" >> result.txt
      fi
    done
    column -t -s' ' result.txt
  fi

  #Output of the result according to the old image
  DIFF_DAYS=$(( ($(date -d ${CREATED_DATE_LAST} +%s) - $(date -d ${CREATED_DATE} +%s)) / 86400 ))
  if (( $DIFF_DAYS > 0 )); then
    #If old and there is a fresh version
    if [ "$IS_OLD" = true ]; then
      echo "${1} >>> is old, created: ${CREATED_DATE}. Last update: ${CREATED_DATE_LAST}"
      echo "${1} >>> use a newer tags:"
      echo $STRING_VER_NEW > tags.txt
      xargs -n5 < tags.txt | column -t -s' '
    #If not old, but there is an exploit and there is a fresh version
    elif [ "$IS_EXPLOITABLE" = true ]; then
      echo "${1} >>> created: ${CREATED_DATE}. Last update: ${CREATED_DATE_LAST}"
      echo "${1} >>> use a newer tags:"
      echo $STRING_VER_NEW > tags.txt
      xargs -n5 < tags.txt | column -t -s' '
    fi
  #If the old one, and the latest version was not found
  elif [ "$IS_OLD" = true ]; then
    echo "${1} >>> is old, created: ${CREATED_DATE}. Find a newer image"
  #If not old, but there is an exploit
  elif [ "$IS_EXPLOITABLE" = true ]; then
    echo "${1} >>> created: ${CREATED_DATE}. Find another image" 
  fi

  #Decision logic
  if [ "$IS_OLD" = true ] ||  [ "$IS_EXPLOITABLE" = true ] ||  [ "$IS_VIRUSTOTAL_OK" = false ] ||  [ "$IS_LATEST" = true ]; then
    return 1
    SCAN_RETURN_CODE=1
  else
    echo "${1} >>> OK                        "
    return 0
  fi    
}

#Scanning the list from the file
if [ "$IS_LIST_IMAGES" = true ]; then
  for (( j=0; j<${#LIST_IMAGES[@]}; j++ ));
  do
    scan_image "${LIST_IMAGES[j]}"
  done
#Scanning the image from the argument
else
  scan_image "${1}"
fi

exit $SCAN_RETURN_CODE