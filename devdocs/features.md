# Supported Protocols

| Protocol      | Languages |    Versions | Methods                                                                                  | Secure | Propagates Context |                                                                                                                                                     Limitations
|:--------------|:---------:|------------:|------------------------------------------------------------------------------------------|:------:|-------------------:|----------------------------------------------------------------------------------------------------------------------------------------------------------------:
| HTTP          |    All    | 1.0/1.1/2.0 | All                                                                                      |  Yes   |                Yes |                                                                                                                                                             N/A
| gRPC          |    All    |        1.0+ | All                                                                                      |  Yes   |                 No |                                                                      Can't get method for long living connections before OBI started, will mark method with `*`
| MySQL         |    All    |         All | All                                                                                      |  Yes   |                 No |                                             In the case of prepared statements, if the statement was prepated before OBI started then the query might be missed
| PostgreSQL    |    All    |         All | All                                                                                      |  Yes   |                 No |                                             In the case of prepared statements, if the statement was prepated before OBI started then the query might be missed
| Redis         |    All    |         All | All                                                                                      |  Yes   |                 No |                                             For already started connections, can't infer the number of the database, and won't add the `db.namespace` attribute
| MongoDB       |    All    |        5.0+ | insert, update, find, delete, findAndModify, aggregate, count, distinct, mapReduce       |  Yes   |                 No |                                                                                                                              no support for compressed payloads
| Couchbase     |    All    |         All | All                                                                                      |  Yes   |                 No | Bucket unknown if SELECT_BUCKET occurred before OBI started; Collection unknown if GET_COLLECTION_ID occured before OBI started No support for SQL++ operations
| Kafka         |    All    |         All | produce, fetch                                                                           |  Yes   |                 No |                                                     Might fail getting topic name for fetch requests in newer versions of kafka (where Fetch api version >= 13)
| MQTT          |    All    |   3.1.1/5.0 | publish, subscribe                                                                       |   No   |                 No |                                                                                            For subscribe, only first topic filter is used; payload not captured
| GraphQL       |    All    |         All | All                                                                                      |  Yes   |                 No |                                                                                                                                                             N/A
| Elasticsearch |    All    |       7.14+ | /_search, /_msearch, /_bulk, /_doc                                                       |  Yes   |                 No |                                                                                                                                                             N/A
| Opensearch    |    All    |      3.0.0+ | /_search, /_msearch, /_bulk, /_doc                                                       |  Yes   |                 No |                                                                                                                                                             N/A
| AWS S3        |    All    |         All | CreateBucket, DeleteBucket, PutObject, DeleteObject, ListBuckets, ListObjects, GetObject |  Yes   |                 No |                                                                                                                                                             N/A
| AWS SQS       |    All    |         All | All                                                                                      |  Yes   |                 No |                                                                                                                                                             N/A

## Go Instrumentation

Specifically for Go applications, OBI chooses to instrument libraries directly using Uprobes, instead of instrumenting
at the network level. This allows for more accurate tracing and context propagation.
This set of instrumentations currently replaces all the network level instrumentation for Go applications.
To turn this off and fallback to the normal network based instrumentation for Go processes, you set
`discovery.skip_go_specific_tracers` to `true` in the config, or set the environment variable
`OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS=true`.

| Library                        |  Protocol  |              Versions | Methods | Secure | Propagates Context | Limitations
|:-------------------------------|:----------:|----------------------:|---------|:------:|-------------------:|------------:
| net/http                       |    HTTP    |               >= 1.17 | All     |  Yes   |                Yes |         N/A
| golang.org/x/net/http2         |    HTTP    |             >= 0.12.0 | All     |  Yes   |                Yes |         N/A
| github.com/gorilla/mux         |    HTTP    |             >= v1.5.0 | All     |  Yes   |                Yes |         N/A
| github.com/gin-gonic/gin       |    HTTP    |   >= v1.6.0,!= v1.7.5 | All     |  Yes   |                Yes |         N/A
| google.golang.org/grpc         |    gRPC    |               >= 1.40 | All     |  Yes   |                Yes |         N/A
| net/rpc/jsonrpc                |  JsonRPC   |               >= 1.17 | All     |  Yes   |                 No |         N/A
| database/sql                   |    SQL     |               >= 1.17 | All     |  Yes   |                 No |         N/A
| github.com/go-sql-driver/mysql |   MySQL    |             >= v1.5.0 | All     |  Yes   |                 No |         N/A
| github.com/lib/pq              | PostgreSQL |                   All | All     |  Yes   |                 No |         N/A
| github.com/redis/go-redis/v9   |   Redis    |             >= v9.0.0 | All     |  Yes   |                 No |         N/A
| github.com/segmentio/kafka-go  |   Kafka    |            >= v0.4.11 | All     |  Yes   |                 No |         N/A
| github.com/IBM/sarama          |   Kafka    |               >= 1.37 | All     |  Yes   |                 No |         N/A
| go.mongodb.org/mongo-driver    |  MongoDB   | >= v1.10.1, >= v2.0.1 | All     |  Yes   |                 No |         N/A
