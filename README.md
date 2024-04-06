# Public OCI-Image Security Checker

## What is it?

PISC (Public OCI-Image or docker-image Security Checker) is a set of bash scripts that check the following:
* **malware** (exploits, backdoors, crypto-miners, etc) by [virustotal](https://www.virustotal.com/)
* exploitable critical **vulnerabilities** by [trivy](https://github.com/aquasecurity/trivy) and [inthewild.io](https://inthewild.io/)
* image **misconfigurations** like [CVE-2024-21626](https://www.docker.com/blog/docker-security-advisory-multiple-vulnerabilities-in-runc-buildkit-and-moby/)
* old **creation date**
* [non-version](https://docs.docker.com/engine/security/trust/#image-tags-and-dct) **tag** (optional)
  
It can be used to automatically check the security of public OCI-images before run them in a private environment or before using them as base images for CI/CD process.
<p align="center">
  <img src="./sample.png" alt="sample" width="738">
</p>

## Usage

### Preparation
[Get API key](https://docs.virustotal.com/docs/please-give-me-an-api-key) for [virustotal](https://www.virustotal.com/). Standard free end-user account has limitations.

### Quick Start via Docker
```sh
docker run kapistka/pisc:latest /bin/bash ./scan.sh -delm --virustotal-key <virustotal-api-key> -i kapistka/log4shell:0.0.3-nonroot
```

### Common Start
Look at the [Dockerfile](./Dockerfile#L4) to find dependencies. You need to install `trivy`, `skopeo`, `jq` and other packages depending on the distribution used.
```sh
Usage: ./scan.sh [flags] [image_link or image_list]

Flags:
  -d, --date                      check old build date (365 by default)
  --d-days int                    check old build date. Specify the number of days for old build date, example: --d-days 180
  -e, --exploits                  check exploitable vulnerabilities by trivy and inthewild.io
  -f, --file string               all images from file will be checked. Example: -f images.txt
  -h, --help                      print this help
  -i, --image string              only this image will be checked. Example: -i r0binak/mtkpi:v1.3
  -l, --latest                    check non-version tag (:latest and the same)
  -m, --misconfig                 check dangerous misconfigurations
  --trivy-server string           use trivy server if you can. Specify trivy URL, example: --trivy-server http://trivy.something.io:8080
  --trivy-token string            use trivy server if you can. Specify trivy token, example: --trivy-token 0123456789abZ
  -v, --version                   show version
  --virustotal-key string         check malware by virustotal.com. Specify virustotal API-key, example: --virustotal-key 0123456789abcdef
  --vulners-key string            check exploitable vulnerabilities by vulners.com instead of inthewild.io. Specify vulners API-key, example: --vulners-key 0123456789ABCDXYZ

Examples:
  ./scan.sh --virustotal-key 0123456789abcdef -i r0binak/mtkpi:v1.3
  ./scan.sh -delm --virustotal-key 0123456789abcdef -f images.txt
```

## Releases here:
https://hub.docker.com/r/kapistka/pisc/tags
