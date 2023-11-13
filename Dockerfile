FROM aquasec/trivy:latest AS trivy

FROM alpine:3
RUN apk update && apk upgrade && apk --no-cache add bash curl jq util-linux skopeo file tar
COPY --from=trivy /contrib /contrib
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

RUN addgroup -g 65532 -S nonroot \
  && adduser -u 65532 -S nonroot -G nonroot -s /bin/sh

COPY scan.sh /home/nonroot/scan.sh
RUN chown -R 65532:65532 /home/nonroot/scan.sh && chmod -R 755 /home/nonroot/scan.sh

USER nonroot
WORKDIR /home/nonroot
