// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package activerequests // import "go.opentelemetry.io/obi/pkg/activerequests"

import (
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// OTELGetters returns metric attributes available from an active HTTP server request.
func OTELGetters() attributes.NamedGetters[*Request, attribute.KeyValue] {
	return otelGetter
}

func otelGetter(name attr.Name) (attributes.Getter[*Request, attribute.KeyValue], bool) {
	var getter attributes.Getter[*Request, attribute.KeyValue]
	switch name {
	case attr.HTTPRequestMethod:
		getter = func(r *Request) attribute.KeyValue {
			method := r.Method
			if !request.IsKnownHTTPMethod(method) {
				method = request.HTTPMethodOther
			}
			return name.OTEL().String(method)
		}
	case attr.HTTPURLScheme:
		getter = func(r *Request) attribute.KeyValue { return name.OTEL().String(r.Scheme) }
	case attr.ServerAddr:
		getter = func(r *Request) attribute.KeyValue {
			if r.ServerAddress == "" {
				return attribute.KeyValue{}
			}
			return name.OTEL().String(r.ServerAddress)
		}
	case attr.ServerPort:
		getter = func(r *Request) attribute.KeyValue {
			if r.ServerPort == 0 {
				return attribute.KeyValue{}
			}
			return name.OTEL().Int(r.ServerPort)
		}
	case attr.HTTPUrlPath:
		getter = func(r *Request) attribute.KeyValue { return name.OTEL().String(r.Path) }
	case attr.HTTPRoute, attr.HTTPUrlTemplate:
		getter = func(r *Request) attribute.KeyValue {
			if r.Route == "" {
				return attribute.KeyValue{}
			}
			return name.OTEL().String(r.Route)
		}
	case attr.ServiceName:
		getter = func(r *Request) attribute.KeyValue { return name.OTEL().String(r.Service.UID.Name) }
	case attr.ServiceNamespace:
		getter = func(r *Request) attribute.KeyValue { return name.OTEL().String(r.Service.UID.Namespace) }
	case attr.ServiceInstanceID, attr.Instance:
		getter = func(r *Request) attribute.KeyValue { return name.OTEL().String(r.Service.UID.Instance) }
	case attr.Job:
		getter = func(r *Request) attribute.KeyValue { return name.OTEL().String(r.Service.Job()) }
	case attr.TelemetrySDKLanguage:
		getter = func(r *Request) attribute.KeyValue { return name.OTEL().String(r.Service.SDKLanguage.String()) }
	case attr.Source:
		getter = func(_ *Request) attribute.KeyValue { return name.OTEL().String(attr.VendorPrefix) }
	}
	if getter == nil {
		getter = func(r *Request) attribute.KeyValue {
			if value := r.Service.Metadata[name]; value != "" {
				return name.OTEL().String(value)
			}
			return attribute.KeyValue{}
		}
	}
	return getter, true
}

// PromGetters returns fixed-label values, including service metadata, for active requests.
func PromGetters() attributes.NamedGetters[*Request, string] {
	return promGetter
}

func promGetter(name attr.Name) (attributes.Getter[*Request, string], bool) {
	getter, _ := otelGetter(name)
	return func(r *Request) string {
		if kv := getter(r); kv.Valid() {
			return kv.Value.Emit()
		}
		return ""
	}, true
}
