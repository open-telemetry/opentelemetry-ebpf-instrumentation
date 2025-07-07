package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/v2/bson"
)

var requests = expirable.NewLRU[MongoRequestKey, *MongoRequestValue](1000, nil, 0)

const (
	StartTime     = 1000
	EndTime       = 2000
	MessageLength = 65
	PreBodyLength = 21 // 16 for header + 5 for flags and section type
	RequestID     = 1
)

func getConnInfo() BpfConnectionInfoT {
	return BpfConnectionInfoT{
		S_addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1},
		D_addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8},
		S_port: 27017,
		D_port: 27017,
	}
}

var (
	defaultRequestData  = bson.D{bson.E{Key: commFind, Value: "my_collection"}, bson.E{Key: "$db", Value: "my_db"}}
	defaultResponseData = bson.D{bson.E{Key: "ok", Value: 1.0}}
)

func getRequestPayload(hdr *msgHeader, flags uint32, section SectionType, body *bson.D) []byte {
	if body == nil {
		body = &defaultRequestData
	}
	bsonBytes, _ := bson.Marshal(*body)
	if hdr == nil {
		hdr = &msgHeader{
			MessageLength: PreBodyLength + int32(len(bsonBytes)),
			RequestID:     RequestID,
			ResponseTo:    0,
			OpCode:        opMsg,
		}
	}
	byteBuffer := new(bytes.Buffer)
	_ = binary.Write(byteBuffer, binary.LittleEndian, hdr)
	_ = binary.Write(byteBuffer, binary.LittleEndian, flags) // empty flags
	_ = binary.Write(byteBuffer, binary.LittleEndian, section)
	_ = binary.Write(byteBuffer, binary.LittleEndian, bsonBytes)
	return byteBuffer.Bytes()
}

func getResponsePayload(hdr *msgHeader, flags uint32, section SectionType, data *bson.D) []byte {
	if data == nil {
		data = &defaultResponseData
	}
	bsonBytes, _ := bson.Marshal(*data)
	if hdr == nil {
		hdr = &msgHeader{
			MessageLength: PreBodyLength + int32(len(bsonBytes)),
			RequestID:     RequestID + 1,
			ResponseTo:    RequestID,
			OpCode:        opMsg,
		}
	}
	byteBuffer := new(bytes.Buffer)
	_ = binary.Write(byteBuffer, binary.LittleEndian, hdr)
	_ = binary.Write(byteBuffer, binary.LittleEndian, flags) // empty flags
	_ = binary.Write(byteBuffer, binary.LittleEndian, section)
	_ = binary.Write(byteBuffer, binary.LittleEndian, bsonBytes)
	return byteBuffer.Bytes()
}

func TestProcessMongoEventFailIfPayloadShorterThenHeader(t *testing.T) {
	defer requests.Purge()
	connInfo := getConnInfo()
	_, _, err := ProcessMongoEvent([]uint8{0x00, 0x00, 0x00, 0x00}, StartTime, EndTime, connInfo, requests)
	assert.Error(t, err, "Expected error for short buffer")
}

func TestProcessMongoEventFailIfHdrMessageLengthLessThenHeaderLength(t *testing.T) {
	defer requests.Purge()
	connInfo := getConnInfo()
	shortHdr := msgHeader{
		MessageLength: 3,
		RequestID:     RequestID,
		ResponseTo:    0,
		OpCode:        opMsg,
	}
	payload := getRequestPayload(&shortHdr, 0, sectionTypeBody, nil)
	_, _, err := ProcessMongoEvent(payload, StartTime, EndTime, connInfo, requests)
	assert.Error(t, err, "Expected error for message length less than header length")
}

func TestProcessMongoEventFailOnUnknownOp(t *testing.T) {
	defer requests.Purge()
	connInfo := getConnInfo()
	invalidOpHdr := msgHeader{
		MessageLength: MessageLength,
		RequestID:     RequestID,
		ResponseTo:    0,
		OpCode:        42,
	}
	payload := getRequestPayload(&invalidOpHdr, 0, sectionTypeBody, nil)
	_, _, err := ProcessMongoEvent(payload, StartTime, EndTime, connInfo, requests)
	assert.Error(t, err, "Expected error for unknown opcode")
}

func TestProcessMongoEventFailOnInvalidFlags(t *testing.T) {
	defer requests.Purge()
	connInfo := getConnInfo()
	payload := getRequestPayload(nil, 0|0x08, sectionTypeBody, nil)
	_, _, err := ProcessMongoEvent(payload, StartTime, EndTime, connInfo, requests)
	assert.Error(t, err, "Expected error for invalid flags")
}

func TestProcessMongoEventFailOnInvalidSectionType(t *testing.T) {
	defer requests.Purge()
	connInfo := getConnInfo()
	payload := getRequestPayload(nil, 0|0x08, 6, nil)
	_, _, err := ProcessMongoEvent(payload, StartTime, EndTime, connInfo, requests)
	assert.Error(t, err, "Expected error for invalid section type")
}

func TestProcessMongoEventFailIfResponseHasNoMatchingRequest(t *testing.T) {
	defer requests.Purge()
	connInfo := getConnInfo()
	payload := getResponsePayload(nil, 0, sectionTypeBody, nil)
	_, _, err := ProcessMongoEvent(payload, StartTime, EndTime, connInfo, requests)
	assert.Error(t, err, "Expected error response without matching request")
}

func TestProcessMongoEventFailIfResponseToDoesNotMatchRequest(t *testing.T) {
	defer requests.Purge()
	connInfo := getConnInfo()
	requestPayload := getRequestPayload(nil, 0, sectionTypeBody, nil)
	_, moreToCome, err := ProcessMongoEvent(requestPayload, StartTime, EndTime, connInfo, requests)
	require.NoError(t, err, "Expected no error for valid MongoDB event")
	assert.True(t, moreToCome)
	response := bson.D{bson.E{Key: "ok", Value: 1.0}}
	responsePayload := getResponsePayload(&msgHeader{
		MessageLength: PreBodyLength + int32(len(response)),
		RequestID:     RequestID + 1,
		ResponseTo:    RequestID + 5,
		OpCode:        opMsg,
	}, 0, sectionTypeBody, &response)
	// send the same request again, the connection should be expecting a response
	_, _, err = ProcessMongoEvent(responsePayload, StartTime, EndTime, connInfo, requests)
	assert.Error(t, err, "Expected error, responseTo does not match request ID")
}

func TestProcessMongoEventFailNoAdditionalRequestIfNoMoreToComeInRequest(t *testing.T) {
	defer requests.Purge()
	connInfo := getConnInfo()
	payload := getRequestPayload(nil, 0, sectionTypeBody, nil)
	_, moreToCome, err := ProcessMongoEvent(payload, StartTime, EndTime, connInfo, requests)
	require.NoError(t, err, "Expected no error for valid MongoDB event")
	assert.True(t, moreToCome)

	// send the same request again, the connection should be expecting a response
	_, _, err = ProcessMongoEvent(payload, StartTime, EndTime, connInfo, requests)
	assert.Error(t, err, "Expected error when not expecting more request data but receiving it")
}

func TestProcessMongoEventFailExpectsMoreRequestToComeButGotResponse(t *testing.T) {
	defer requests.Purge()
	connInfo := getConnInfo()
	requestPayload := getRequestPayload(nil, 0|flagMoreToCome, sectionTypeBody, nil)
	_, moreToCome, err := ProcessMongoEvent(requestPayload, StartTime, EndTime, connInfo, requests)
	require.NoError(t, err, "Expected no error for valid MongoDB event")
	assert.True(t, moreToCome)

	responsePayload := getResponsePayload(nil, 0, sectionTypeBody, nil)
	// send the same request again, the connection should be expecting a response
	_, _, err = ProcessMongoEvent(responsePayload, StartTime, EndTime, connInfo, requests)
	assert.Error(t, err, "Expected error when not expecting more request data but receiving it")
}

func TestProcessMongoEventFailIfMultiResponseSentButNoExhaustAllowed(t *testing.T) {
	defer requests.Purge()
	connInfo := getConnInfo()
	requestPayload := getRequestPayload(nil, 0, sectionTypeBody, nil)
	_, moreToCome, err := ProcessMongoEvent(requestPayload, StartTime, EndTime, connInfo, requests)
	require.NoError(t, err, "Expected no error for valid MongoDB event")
	assert.True(t, moreToCome)

	responsePayload := getResponsePayload(nil, 0|flagMoreToCome, sectionTypeBody, nil)
	_, _, err = ProcessMongoEvent(responsePayload, StartTime, EndTime, connInfo, requests)
	assert.Error(t, err, "Expected error if multi-response sent but no exhaust allowed")
}

func TestProcessMongoEventFailSendRequestAfterResponse(t *testing.T) {
	defer requests.Purge()
	connInfo := getConnInfo()
	requestPayload := getRequestPayload(nil, 0|flagExhaustAllowed, sectionTypeBody, nil)
	_, moreToCome, err := ProcessMongoEvent(requestPayload, StartTime, EndTime, connInfo, requests)
	require.NoError(t, err, "Expected no error for valid MongoDB event")
	assert.True(t, moreToCome)

	responsePayload := getResponsePayload(nil, 0|flagMoreToCome, sectionTypeBody, nil)
	_, moreToCome, err = ProcessMongoEvent(responsePayload, StartTime, EndTime, connInfo, requests)
	require.NoError(t, err, "Expected no error for valid MongoDB event")
	assert.True(t, moreToCome)
	// send the same request again, the connection should be expecting a response
	_, _, err = ProcessMongoEvent(requestPayload, StartTime, EndTime, connInfo, requests)
	assert.Error(t, err, "Expected error when sending request after response")
}

func TestProcessMongoEventSuccessParsingSingleRequestResponse(t *testing.T) {
	defer requests.Purge()
	connInfo := getConnInfo()
	requestPayload := getRequestPayload(nil, 0, sectionTypeBody, nil)
	_, moreToCome, err := ProcessMongoEvent(requestPayload, StartTime, EndTime, connInfo, requests)
	require.NoError(t, err, "Expected no error for valid MongoDB event")
	assert.True(t, moreToCome)

	responsePayload := getResponsePayload(nil, 0, sectionTypeBody, nil)
	// send the same request again, the connection should be expecting a response
	mongoRequestValue, moreToCome, err := ProcessMongoEvent(responsePayload, StartTime, EndTime, connInfo, requests)
	require.NoError(t, err, "Expected no error for valid MongoDB event")
	assert.False(t, moreToCome, "Expected no more data to come after response")
	assert.NotNil(t, mongoRequestValue, "Expected MongoRequestValue to be returned")
	assert.Len(t, mongoRequestValue.RequestSections, 1, "Expected one request section")
	firstRequestSection := mongoRequestValue.RequestSections[0]
	assert.Equal(t, sectionTypeBody, firstRequestSection.Type, "Expected first section type to be sectionTypeBody")
	assert.Equal(t, defaultRequestData, firstRequestSection.Body, "Expected first section body to match request data")
	assert.Len(t, mongoRequestValue.ResponseSections, 1, "Expected one response section")
	firstResponseSection := mongoRequestValue.ResponseSections[0]
	assert.Equal(t, sectionTypeBody, firstResponseSection.Type, "Expected first section type to be sectionTypeBody")
	assert.Equal(t, defaultResponseData, firstResponseSection.Body, "Expected first section body to match request data")
}

func TestProcessMongoEventSuccessParsingMultiRequestSingleResponse(t *testing.T) {
	defer requests.Purge()
	connInfo := getConnInfo()
	insertComm := bson.D{bson.E{Key: commInsert, Value: "my_collection"}, bson.E{Key: "$db", Value: "my_db"}}
	requestPayload := getRequestPayload(nil, 0|flagMoreToCome, sectionTypeBody, &insertComm)
	_, moreToCome, err := ProcessMongoEvent(requestPayload, StartTime, EndTime, connInfo, requests)
	require.NoError(t, err, "Expected no error for valid MongoDB event")
	assert.True(t, moreToCome)
	data := bson.D{bson.E{Key: "Name", Value: "Alice"}}
	dataRequestPayload := getRequestPayload(nil, 0, sectionTypeDocumentSequence, &data)
	_, moreToCome, err = ProcessMongoEvent(dataRequestPayload, StartTime, EndTime, connInfo, requests)
	require.NoError(t, err, "Expected no error for valid MongoDB event")
	assert.True(t, moreToCome)

	responsePayload := getResponsePayload(nil, 0, sectionTypeBody, nil)
	// send the same request again, the connection should be expecting a response
	mongoRequestValue, moreToCome, err := ProcessMongoEvent(responsePayload, StartTime, EndTime, connInfo, requests)
	require.NoError(t, err, "Expected no error for valid MongoDB event")
	assert.False(t, moreToCome, "Expected no more data to come after response")
	assert.NotNil(t, mongoRequestValue, "Expected MongoRequestValue to be returned")

	assert.Len(t, mongoRequestValue.RequestSections, 2, "Expected one request section")

	firstRequestSection := mongoRequestValue.RequestSections[0]
	assert.Equal(t, sectionTypeBody, firstRequestSection.Type, "Expected first section type to be sectionTypeBody")
	assert.Equal(t, insertComm, firstRequestSection.Body, "Expected first section body to match request data")

	secondRequestSection := mongoRequestValue.RequestSections[1]
	assert.Equal(t, sectionTypeDocumentSequence, secondRequestSection.Type, "Expected first section type to be sectionTypeBody")

	assert.Len(t, mongoRequestValue.ResponseSections, 1, "Expected one response section")
	firstResponseSection := mongoRequestValue.ResponseSections[0]
	assert.Equal(t, sectionTypeBody, firstResponseSection.Type, "Expected first section type to be sectionTypeBody")
	assert.Equal(t, defaultResponseData, firstResponseSection.Body, "Expected first section body to match request data")
}

func TestProcessMongoEventSuccessParsingSingleRequestMultiResponse(t *testing.T) {
	defer requests.Purge()
	connInfo := getConnInfo()
	requestPayload := getRequestPayload(nil, 0|flagExhaustAllowed, sectionTypeBody, nil)
	_, moreToCome, err := ProcessMongoEvent(requestPayload, StartTime, EndTime, connInfo, requests)
	require.NoError(t, err, "Expected no error for valid MongoDB event")
	assert.True(t, moreToCome)

	responsePayload := getResponsePayload(nil, 0|flagMoreToCome, sectionTypeBody, nil)
	// send the same request again, the connection should be expecting a response
	_, moreToCome, err = ProcessMongoEvent(responsePayload, StartTime, EndTime, connInfo, requests)
	require.NoError(t, err, "Expected no error for valid MongoDB event")
	assert.True(t, moreToCome, "Expected no more data to come after response")

	data := bson.D{bson.E{Key: "Name", Value: "Alice"}}
	dataRequestPayload := getResponsePayload(nil, 0, sectionTypeDocumentSequence, &data)
	mongoRequestValue, moreToCome, err := ProcessMongoEvent(dataRequestPayload, StartTime, EndTime, connInfo, requests)
	require.NoError(t, err, "Expected no error for valid MongoDB event")
	assert.False(t, moreToCome)
	assert.NotNil(t, mongoRequestValue, "Expected MongoRequestValue to be returned")

	assert.Len(t, mongoRequestValue.RequestSections, 1, "Expected one request section")
	requestSection := mongoRequestValue.RequestSections[0]
	assert.Equal(t, sectionTypeBody, requestSection.Type, "Expected first section type to be sectionTypeBody")
	assert.Equal(t, defaultRequestData, requestSection.Body, "Expected first section body to match request data")

	assert.Len(t, mongoRequestValue.ResponseSections, 2, "Expected one response section")

	firstResponseSection := mongoRequestValue.ResponseSections[0]
	assert.Equal(t, sectionTypeBody, firstResponseSection.Type, "Expected first section type to be sectionTypeBody")
	assert.Equal(t, defaultResponseData, firstResponseSection.Body, "Expected first section body to match request data")
	secondResponseSection := mongoRequestValue.ResponseSections[1]
	assert.Equal(t, sectionTypeDocumentSequence, secondResponseSection.Type, "Expected first section type to be sectionTypeBody")
}

func TestProcessMongoEventSuccessWhenResponseOnlyContainsHeader(t *testing.T) {
	defer requests.Purge()
	connInfo := getConnInfo()
	requestPayload := getRequestPayload(nil, 0, sectionTypeBody, nil)
	_, moreToCome, err := ProcessMongoEvent(requestPayload, StartTime, EndTime, connInfo, requests)
	require.NoError(t, err, "Expected no error for valid MongoDB event")
	assert.True(t, moreToCome)

	hdr := &msgHeader{
		MessageLength: PreBodyLength + 50,
		RequestID:     RequestID + 1,
		ResponseTo:    RequestID,
		OpCode:        opMsg,
	}
	// includes only header, no body
	byteBuffer := new(bytes.Buffer)
	_ = binary.Write(byteBuffer, binary.LittleEndian, hdr)

	// send the same request again, the connection should be expecting a response
	mongoRequestValue, moreToCome, err := ProcessMongoEvent(byteBuffer.Bytes(), StartTime, EndTime, connInfo, requests)
	require.NoError(t, err, "Expected no error for valid MongoDB event")
	assert.False(t, moreToCome, "Expected no more data to come after response")
	assert.NotNil(t, mongoRequestValue, "Expected MongoRequestValue to be returned")
	assert.Len(t, mongoRequestValue.RequestSections, 1, "Expected one request section")
	firstRequestSection := mongoRequestValue.RequestSections[0]
	assert.Equal(t, sectionTypeBody, firstRequestSection.Type, "Expected first section type to be sectionTypeBody")
	assert.Equal(t, defaultRequestData, firstRequestSection.Body, "Expected first section body to match request data")
	assert.Empty(t, mongoRequestValue.ResponseSections, "Expected zero response section")
}

func TestProcessMongoEventSuccessWhenCannotParseBsonInRequest(t *testing.T) {
	defer requests.Purge()
	connInfo := getConnInfo()
	bsonBytes, _ := bson.Marshal(defaultRequestData)
	hdr := msgHeader{
		MessageLength: PreBodyLength + int32(len(bsonBytes)),
		RequestID:     RequestID,
		ResponseTo:    0,
		OpCode:        opMsg,
	}
	byteBuffer := new(bytes.Buffer)
	_ = binary.Write(byteBuffer, binary.LittleEndian, hdr)
	_ = binary.Write(byteBuffer, binary.LittleEndian, int32(0))
	_ = binary.Write(byteBuffer, binary.LittleEndian, sectionTypeBody)
	_ = binary.Write(byteBuffer, binary.LittleEndian, bsonBytes[:len(bsonBytes)-4]) // truncate last bytes to make it invalid BSON
	requestPayload := byteBuffer.Bytes()
	_, moreToCome, err := ProcessMongoEvent(requestPayload, StartTime, EndTime, connInfo, requests)
	require.NoError(t, err, "Expected no error for valid MongoDB event")
	assert.True(t, moreToCome)

	responsePayload := getResponsePayload(nil, 0, sectionTypeBody, nil)
	// send the same request again, the connection should be expecting a response
	mongoRequestValue, moreToCome, err := ProcessMongoEvent(responsePayload, StartTime, EndTime, connInfo, requests)
	require.NoError(t, err, "Expected no error for valid MongoDB event")
	assert.False(t, moreToCome, "Expected no more data to come after response")
	assert.NotNil(t, mongoRequestValue, "Expected MongoRequestValue to be returned")
	assert.Len(t, mongoRequestValue.RequestSections, 1, "Expected one request section")
	firstRequestSection := mongoRequestValue.RequestSections[0]
	assert.Equal(t, sectionTypeBody, firstRequestSection.Type, "Expected first section type to be sectionTypeBody")
	assert.Equal(t, bson.D{}, firstRequestSection.Body, "Expected first section body be empty due to parsing error")
	assert.Len(t, mongoRequestValue.ResponseSections, 1, "Expected one response section")
	firstResponseSection := mongoRequestValue.ResponseSections[0]
	assert.Equal(t, sectionTypeBody, firstResponseSection.Type, "Expected first section type to be sectionTypeBody")
	assert.Equal(t, defaultResponseData, firstResponseSection.Body, "Expected first section body to match request data")
}

// getMongoInfo

func TestGetMongoInfoFindRequest(t *testing.T) {
	mongoRequest := MongoRequestValue{
		RequestSections: []mongoSection{
			{
				Type: sectionTypeBody,
				Body: bson.D{bson.E{Key: commFind, Value: "my_collection"}, bson.E{Key: "$db", Value: "my_db"}},
			},
		},
		ResponseSections: []mongoSection{
			{
				Type: sectionTypeBody,
				Body: bson.D{bson.E{Key: "ok", Value: float64(1)}},
			},
		},
	}
	res, err := getMongoInfo(&mongoRequest)
	require.NoError(t, err, "Expected no error when mongodb failed")
	assert.Equal(t, "my_db", res.DB, "Expected DB to be 'my_db'")
	assert.Equal(t, "my_collection", res.Collection, "Expected Collection to be 'my_collection'")
	assert.Equal(t, commFind, res.OpName, "Expected Operation to be 'find'")
	assert.True(t, res.Success, "Expected Response to be 'ok'")
	assert.Empty(t, res.Error, "Expected Error to be empty in successful request")
	assert.Empty(t, res.ErrorCode, "Expected ErrorCode to be empty in successful request")
	assert.Empty(t, res.ErrorCodeName, "Expected ErrorCodeName to be empty in successful request")
}

func TestGetMongoInfoErrorRequest(t *testing.T) {
	mongoRequest := MongoRequestValue{
		RequestSections: []mongoSection{
			{
				Type: sectionTypeBody,
				Body: bson.D{bson.E{Key: commFind, Value: "my_collection"}, bson.E{Key: "$db", Value: "my_db"}},
			},
		},
		ResponseSections: []mongoSection{
			{
				Type: sectionTypeBody,
				Body: bson.D{bson.E{Key: "ok", Value: float64(0)}, bson.E{Key: "errmsg", Value: "some error"}, bson.E{Key: "code", Value: 12345}, bson.E{Key: "codeName", Value: "SomeError"}},
			},
		},
	}
	res, err := getMongoInfo(&mongoRequest)
	require.NoError(t, err, "Expected no error when mongodb failed")
	assert.Equal(t, "my_db", res.DB, "Expected DB to be 'my_db'")
	assert.Equal(t, "my_collection", res.Collection, "Expected Collection to be 'my_collection'")
	assert.Equal(t, commFind, res.OpName, "Expected Operation to be 'find'")
	assert.False(t, res.Success, "Expected Response to not be 'ok'")
	assert.Equal(t, "some error", res.Error, "Expected Error to be 'some error'")
	assert.Equal(t, 12345, res.ErrorCode, "Expected ErrorCode to be 12345")
	assert.Equal(t, "SomeError", res.ErrorCodeName, "Expected ErrorCodeName to be 'SomeError'")
}

func TestGetMongoInfoNoResponseSectionShouldBeSuccess(t *testing.T) {
	mongoRequest := MongoRequestValue{
		RequestSections: []mongoSection{
			{
				Type: sectionTypeBody,
				Body: bson.D{bson.E{Key: commFind, Value: "my_collection"}, bson.E{Key: "$db", Value: "my_db"}},
			},
		},
		ResponseSections: []mongoSection{},
	}
	res, err := getMongoInfo(&mongoRequest)
	require.NoError(t, err, "Expected no error when mongodb failed")
	assert.Equal(t, "my_db", res.DB, "Expected DB to be 'my_db'")
	assert.Equal(t, "my_collection", res.Collection, "Expected Collection to be 'my_collection'")
	assert.Equal(t, commFind, res.OpName, "Expected Operation to be 'find'")
	assert.True(t, res.Success, "Expected Response to be 'ok'")
	assert.Empty(t, res.Error, "Expected Error to be empty in successful request")
	assert.Empty(t, res.ErrorCode, "Expected ErrorCode to be empty in successful request")
	assert.Empty(t, res.ErrorCodeName, "Expected ErrorCodeName to be empty in successful request")
}

func TestGetMongoInfoFailWhenHealthCommand(t *testing.T) {
	mongoRequest := MongoRequestValue{
		RequestSections: []mongoSection{
			{
				Type: sectionTypeBody,
				Body: bson.D{bson.E{Key: commHello}},
			},
		},
		ResponseSections: []mongoSection{
			{
				Type: sectionTypeBody,
				Body: bson.D{bson.E{Key: "ok", Value: float64(1)}},
			},
		},
	}
	_, err := getMongoInfo(&mongoRequest)
	assert.Error(t, err, "Expected error when processing health command")
}

func TestGetMongoInfoWithUnknownCommand(t *testing.T) {
	mongoRequest := MongoRequestValue{
		RequestSections: []mongoSection{
			{
				Type: sectionTypeBody,
				Body: bson.D{bson.E{Key: "createUser", Value: "my_collection"}},
			},
		},
		ResponseSections: []mongoSection{},
	}
	res, err := getMongoInfo(&mongoRequest)
	require.NoError(t, err, "Expected no error when mongodb failed")
	assert.Empty(t, res.DB, "Expected DB to be empty for unknown command")
	assert.Empty(t, res.Collection, "Expected Collection to be empty for unknown command")
	assert.Equal(t, "createUser", res.OpName, "Expected Operation to be 'find'")
	assert.True(t, res.Success, "Expected Response to be 'ok'")
	assert.Empty(t, res.Error, "Expected Error to be empty in successful request")
	assert.Empty(t, res.ErrorCode, "Expected ErrorCode to be empty in successful request")
	assert.Empty(t, res.ErrorCodeName, "Expected ErrorCodeName to be empty in successful request")
}

func TestGetMongoInfoOperationUnknownForEmptyRequestSection(t *testing.T) {
	mongoRequest := MongoRequestValue{
		RequestSections: []mongoSection{
			{
				Type: sectionTypeBody,
				Body: bson.D{},
			},
		},
		ResponseSections: []mongoSection{},
	}
	res, err := getMongoInfo(&mongoRequest)
	require.NoError(t, err, "Expected no error when mongodb failed")
	assert.Empty(t, res.DB, "Expected DB to be empty for unknown command")
	assert.Empty(t, res.Collection, "Expected Collection to be empty for unknown command")
	assert.Equal(t, "*", res.OpName, "Expected Operation to be 'find'")
	assert.True(t, res.Success, "Expected Response to be 'ok'")
	assert.Empty(t, res.Error, "Expected Error to be empty in successful request")
	assert.Empty(t, res.ErrorCode, "Expected ErrorCode to be empty in successful request")
	assert.Empty(t, res.ErrorCodeName, "Expected ErrorCodeName to be empty in successful request")
}
