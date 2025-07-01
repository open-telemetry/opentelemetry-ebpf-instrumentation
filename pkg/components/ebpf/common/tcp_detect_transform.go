package ebpfcommon

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/ringbuf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/sqlprune"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/config"
)

var (
	errFallback = errors.New("falling back to generic handler")
	errIgnore   = errors.New("ignoring event")
)

// ReadTCPRequestIntoSpan returns a request.Span from the provided ring buffer record
//
//nolint:cyclop
func ReadTCPRequestIntoSpan(parseCtx *EBPFParseContext, cfg *config.EBPFTracer, record *ringbuf.Record, filter ServiceFilter) (request.Span, bool, error) {
	event, err := ReinterpretCast[TCPRequestInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	if !filter.ValidPID(event.Pid.UserPid, event.Pid.Ns, PIDTypeKProbes) {
		return request.Span{}, true, nil
	}

	requestBuffer, responseBuffer := fixupBuffers(parseCtx, event)

	if cfg.ProtocolDebug {
		fmt.Printf("[>] %v\n", requestBuffer)
		fmt.Printf("[<] %v\n", responseBuffer)
	}

	// We might know already the protocol for this event
	switch event.ProtocolType {
	case ProtocolTypeMySQL: // MySQL
		span, err := handleMySQL(parseCtx, event, requestBuffer, responseBuffer)
		if errors.Is(err, errFallback) {
			slog.Warn("MySQL: falling back to generic handler")
			break
		}
		if errors.Is(err, errIgnore) {
			return request.Span{}, true, nil
		}
		if err != nil {
			return request.Span{}, true, fmt.Errorf("failed to handle MySQL event: %w", err)
		}

		return span, false, nil
	case ProtocolTypeUnknown:
		fallthrough
	default:
		slog.Debug("Unknown protocol type, falling back to generic handler", "protocolType", event.ProtocolType)
	}

	// Check if we have a SQL statement
	op, table, sql, kind := detectSQLPayload(cfg.HeuristicSQLDetect, requestBuffer)
	if validSQL(op, table, kind) {
		return TCPToSQLToSpan(event, op, table, sql, kind, "", nil), false, nil
	} else {
		op, table, sql, kind = detectSQLPayload(cfg.HeuristicSQLDetect, responseBuffer)
		if validSQL(op, table, kind) {
			reverseTCPEvent(event)
			return TCPToSQLToSpan(event, op, table, sql, kind, "", nil), false, nil
		}
	}

	if maybeFastCGI(requestBuffer) {
		op, uri, status := detectFastCGI(requestBuffer, responseBuffer)
		if status >= 0 {
			return TCPToFastCGIToSpan(event, op, uri, status), false, nil
		}
	}

	var mongoRequest *MongoRequestValue
	var moreToCome bool
	_, _, err = ProcessMongoEvent(requestBuffer, int64(event.StartMonotimeNs), int64(event.EndMonotimeNs), event.ConnInfo, parseCtx.mongoRequestCache)
	if err == nil {
		mongoRequest, moreToCome, err = ProcessMongoEvent(event.Rbuf[:l], int64(event.StartMonotimeNs), int64(event.EndMonotimeNs), event.ConnInfo, parseCtx.mongoRequestCache)
	}
	if err == nil && !moreToCome && mongoRequest != nil {
		mongoInfo, err := getMongoInfo(mongoRequest)
		if err == nil {
			mongoSpan := TCPToMongoToSpan(event, mongoInfo)
			return mongoSpan, false, nil
		}
	}

	switch {
	case isRedis(requestBuffer) && isRedis(responseBuffer):
		op, text, ok := parseRedisRequest(string(requestBuffer))

		if ok {
			var status int
			var redisErr request.DBError
			if op == "" {
				op, text, ok = parseRedisRequest(string(responseBuffer))
				if !ok || op == "" {
					return request.Span{}, true, nil // ignore if we couldn't parse it
				}
				// We've caught the event reversed in the middle of communication, let's
				// reverse the event
				reverseTCPEvent(event)
				redisErr, status = redisStatus(requestBuffer)
			} else {
				redisErr, status = redisStatus(responseBuffer)
			}

			db, found := getRedisDB(event.ConnInfo, op, text, parseCtx.redisDBCache)
			if !found {
				db = -1 // if we don't have the db in cache, we assume it's not set
			}
			return TCPToRedisToSpan(event, op, text, status, db, redisErr), false, nil
		}
	default:
		// Kafka and gRPC can look very similar in terms of bytes. We can mistake one for another.
		// We try gRPC first because it's more reliable in detecting false gRPC sequences.
		if isHTTP2(requestBuffer, int(event.Len)) || isHTTP2(responseBuffer, int(event.RespLen)) {
			evCopy := *event
			MisclassifiedEvents <- MisclassifiedEvent{EventType: EventTypeKHTTP2, TCPInfo: &evCopy}
		} else {
			k, err := ProcessPossibleKafkaEvent(event, requestBuffer, responseBuffer)
			if err == nil {
				return TCPToKafkaToSpan(event, k), false, nil
			}
		}
	}

	return request.Span{}, true, nil // ignore if we couldn't parse it
}

func fixupBuffers(parseCtx *EBPFParseContext, event *TCPRequestInfo) (req []byte, resp []byte) {
	l := int(event.Len)
	if l < 0 || len(event.Buf) < l {
		l = len(event.Buf)
	}
	req = event.Buf[:l]

	l = int(event.RespLen)
	if l < 0 || len(event.Rbuf) < l {
		l = len(event.Rbuf)
	}
	resp = event.Rbuf[:l]

	if event.HasLargeBuffers == 1 {
		if b, ok := getTCPLargeBuffer(parseCtx, event.Tp.TraceId, event.Tp.SpanId, 0); ok {
			req = b
		}
		if b, ok := getTCPLargeBuffer(parseCtx, event.Tp.TraceId, event.Tp.SpanId, 1); ok {
			resp = b
		}
	}

	return
}

func handleMySQL(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer []byte) (request.Span, error) {
	var span request.Span

	if len(requestBuffer) < sqlprune.MySQLHdrSize+1 {
		slog.Warn("MySQL request too short")
		return span, errFallback
	}

	stmt := string(requestBuffer[sqlprune.MySQLHdrSize+1:])
	sqlCommand := sqlprune.SQLParseCommandID(request.DBMySQL, requestBuffer)
	if sqlCommand == "" {
		slog.Warn("MySQL command ID unhandled", "commandID", requestBuffer[sqlprune.MySQLHdrSize])
		return span, errIgnore
	}

	sqlError := sqlprune.SQLParseError(responseBuffer)

	switch sqlCommand {
	case "STMT_PREPARE":
		if sqlError != nil {
			slog.Debug("MySQL PREPARE command errored, ignoring", "error", sqlError)
			return span, errIgnore
		}

		// On the PREPARE command, the statement ID is the first 4 bytes after the header and command ID
		// in the response buffer.
		stmtID := sqlprune.SQLParseStatementID(request.DBMySQL, responseBuffer)
		if stmtID == 0 {
			slog.Warn("MySQL PREPARE command with invalid statement ID")
			return span, errFallback
		}

		stmt = string(requestBuffer[sqlprune.MySQLHdrSize+1:])

		parseCtx.mysqlPreparedStatements.Add(mysqlPreparedStatementsKey{
			connInfo: event.ConnInfo,
			stmtID:   stmtID,
		}, stmt)

		return span, errIgnore
	case "STMT_EXECUTE":
		if sqlError != nil {
			slog.Debug("MySQL EXECUTE command errored, ignoring", "error", sqlError)
			return span, errIgnore
		}

		// On the EXECUTE command, the statement ID is the first 4 bytes after the header and command ID
		// in the request buffer.
		stmtID := sqlprune.SQLParseStatementID(request.DBMySQL, requestBuffer)
		if stmtID == 0 {
			slog.Warn("MySQL EXECUTE command with invalid statement ID")
			return span, errFallback
		}

		var found bool
		stmt, found = parseCtx.mysqlPreparedStatements.Get(mysqlPreparedStatementsKey{
			connInfo: event.ConnInfo,
			stmtID:   stmtID,
		})
		if !found {
			slog.Debug("MySQL EXECUTE command with unknown statement ID", "stmtID", stmtID)
			return span, errFallback
		}
	case "QUERY":
	default:
		slog.Warn("MySQL command ID unhandled", "commandID", requestBuffer[sqlprune.MySQLHdrSize])
		return span, errFallback
	}

	var op, table string
	defer func() {
		if r := recover(); r != nil {
			slog.Error("recovered from panic in SQLParseOperationAndTableNEW", "error", r)
			op = ""
			table = ""
		}
	}()

	op, table = sqlprune.SQLParseOperationAndTableNEW(stmt)
	if !validSQL(op, table, request.DBMySQL) {
		slog.Warn("MySQL operation and/or table are invalid", "stmt", stmt)
		return span, errFallback
	}

	return TCPToSQLToSpan(event, op, table, stmt, request.DBMySQL, sqlCommand, sqlError), nil
}

func reverseTCPEvent(trace *TCPRequestInfo) {
	if trace.Direction == 0 {
		trace.Direction = 1
	} else {
		trace.Direction = 0
	}

	port := trace.ConnInfo.S_port
	addr := trace.ConnInfo.S_addr
	trace.ConnInfo.S_addr = trace.ConnInfo.D_addr
	trace.ConnInfo.S_port = trace.ConnInfo.D_port
	trace.ConnInfo.D_addr = addr
	trace.ConnInfo.D_port = port
}
