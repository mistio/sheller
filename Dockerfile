
FROM golang:1.18 as build-env

WORKDIR /go/src/app

COPY go.* ./
RUN go mod download

ADD . /go/src/app
RUN go build -o /go/bin/app

FROM gcr.io/distroless/base
COPY --from=build-env /go/bin/app /
CMD ["/app"]