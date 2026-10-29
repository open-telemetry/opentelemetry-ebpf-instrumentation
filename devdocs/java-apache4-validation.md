# Apache HttpClient 4 validation evidence

The implementation and load candidate is
`c6cb7d42b6abe445d24aff1e1f2dacb6bd6c815d`, based on upstream main
`1d6df6a4ce8db0de39c5924da14eb1bc20667013`. It includes the merged #3798
and #3941 foundations. The measured candidate binary SHA-256 is
`d85b9ef181ac21031d7c306aa0fd349d0ddedf0e9b1c90b0b0cfb70df38dd29c`.

Required sustained-load validation and the final native runtime matrix are still
running. This evidence page does not yet claim production-readiness acceptance.
The [reproduction instructions](../internal/test/integration/components/java_apache_httpclient/validation/README.md)
describe the source, TLS proxy, standard OpenTelemetry downstream, controls,
measurements, and accounting limits. Completed results will replace this status.
