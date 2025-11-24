module go.opentelemetry.io/obi/internal/test/integration/components/old_grpc/backend

go 1.25.3

require (
	github.com/caarlos0/env/v7 v7.1.0
	go.opentelemetry.io/obi/internal/test/integration/components/old_grpc/worker v0.0.0-20251020181413-b62a788abdb6
	google.golang.org/grpc v1.56.3
	google.golang.org/protobuf v1.33.0
)

require (
	github.com/golang/protobuf v1.5.3 // indirect
	golang.org/x/net v0.12.0 // indirect
	golang.org/x/sys v0.10.0 // indirect
	golang.org/x/text v0.11.0 // indirect
	google.golang.org/genproto v0.0.0-20230410155749-daa745c078e1 // indirect
)

replace go.opentelemetry.io/obi v0.0.0 => ../../../../../../../

replace go.opentelemetry.io/obi/internal/test/integration/components/old_grpc/worker => ../worker/
