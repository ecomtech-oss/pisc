FROM aquasec/trivy:0.68.2 AS trivy

FROM alpine:3

RUN apk update && apk upgrade && apk --no-cache add bash coreutils curl jq yq util-linux skopeo file tar sqlite gnupg \
  && GRYPE_VERSION="0.104.4" \
  && curl -sSL "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" -o grype.tar.gz \
  && tar -xzf grype.tar.gz -C /usr/local/bin grype \
  && rm grype.tar.gz

COPY --from=trivy /contrib /contrib
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

RUN addgroup -g 65532 -S nonroot \
  && adduser -u 65532 -S nonroot -G nonroot -s /bin/sh

WORKDIR /home/nonroot

COPY check-exclusions.sh \
  grype.tmpl \
  mime-helper.sh \
  scan.sh \
  scan-date.sh \
  scan-download-unpack.sh \
  scan-epss.sh \
  scan-grype.sh \
  scan-inthewild-io.sh \
  scan-misconfig.sh \
  scan-new-tags.sh \
  scan-trivy.sh \
  scan-virustotal.sh \
  scan-vulners-com.sh \
  scan-vulnerabilities.sh \
  trivy.tmpl \
  ./

RUN chown -R 65532:65532 *.sh && chmod -R 755 *.sh

USER nonroot
