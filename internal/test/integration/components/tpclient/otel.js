// otel.js: loaded with `node --require` to instrument a tpclient process with the
// OpenTelemetry SDK. Its OTLP trace exports make OBI classify the process as
// OTel-instrumented, and its HTTP instrumentation writes the traceparent after
// the headers the application set, as SDKs do.
const { NodeTracerProvider, SimpleSpanProcessor } = require('@opentelemetry/sdk-trace-node');
const { OTLPTraceExporter } = require('@opentelemetry/exporter-trace-otlp-http');
const { registerInstrumentations } = require('@opentelemetry/instrumentation');
const { HttpInstrumentation } = require('@opentelemetry/instrumentation-http');
const { resourceFromAttributes } = require('@opentelemetry/resources');

const provider = new NodeTracerProvider({
  resource: resourceFromAttributes({ 'service.name': 'tpclient-sdk' }),
  // exports every span as it ends, so OBI sees an export right after each request.
  // Straight to Jaeger: the collector only receives OBI's telemetry, which weaver validates
  spanProcessors: [
    new SimpleSpanProcessor(new OTLPTraceExporter({ url: 'http://jaeger:4318/v1/traces' })),
  ],
});
provider.register();

registerInstrumentations({ instrumentations: [new HttpInstrumentation()] });
