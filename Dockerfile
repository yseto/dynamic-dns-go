FROM golang:1.23-bookworm AS build

WORKDIR /usr/src/app/
COPY go.mod go.sum  /usr/src/app/
RUN go mod download
COPY ./ /usr/src/app/
ENV CGO_ENABLED=0
RUN go build -o /usr/src/app/ddns main.go

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build --chown=nonroot:nonroot /usr/src/app/ddns /

EXPOSE 1053/udp

CMD ["/ddns"]

