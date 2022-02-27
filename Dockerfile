<<<<<<< HEAD
FROM golang:1.18 as build-env
=======
FROM golang:1.17 as build-env
>>>>>>> fix build issue

WORKDIR /go/src/app
ADD . /go/src/app

RUN go get -d -v ./...

RUN go build -o /go/bin/app

FROM gcr.io/distroless/base
COPY --from=build-env /go/bin/app /
CMD ["/app"]