package harvesters

import (
	"log/slog"

	"go.opentelemetry.io/obi/pkg/components/exec"
	"go.opentelemetry.io/obi/pkg/components/svc"
)

type RouteHarvester struct {
	log  *slog.Logger
	java *javaRouteHarvester
}

func NewRouteHarvester() *RouteHarvester {
	return &RouteHarvester{
		log:  slog.With("component", "route.harvester"),
		java: NewJavaRouteHarvester(),
	}
}

func (h *RouteHarvester) HarvestRoutes(fileInfo *exec.FileInfo) ([]string, error) {
	routes := []string{}

	if fileInfo.Service.SDKLanguage == svc.InstrumentableJava {
		return h.java.ExtractRoutes(fileInfo.Pid)
	}

	return routes, nil
}
