FROM golang:1.24 AS BUILDER
WORKDIR /go/src/github.com/jtblin/kube2iam
ENV ARCH=linux
ENV CGO_ENABLED=0
COPY . ./
RUN make setup && make build

FROM alpine:3.22
RUN apk --no-cache add \
    ca-certificates \
    iptables \
    nftables
COPY --from=BUILDER /go/src/github.com/jtblin/kube2iam/build/bin/linux/kube2iam /bin/kube2iam
ENTRYPOINT ["kube2iam"]
