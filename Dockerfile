# syntax=docker/dockerfile:1

FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o webhook .

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=build /src/webhook /webhook
USER nonroot:nonroot
ENTRYPOINT ["/webhook"]
