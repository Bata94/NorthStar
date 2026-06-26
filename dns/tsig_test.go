package dns

import (
	"crypto/hmac"
	"encoding/hex"
	"testing"
)

func TestTSIGParsePackRoundTrip(t *testing.T) {
	tsig := &TSIG{
		Algorithm:  AlgHMACSHA256,
		TimeSigned: 1700000000,
		Fudge:      300,
		MAC:        []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		OriginalID: 42,
		Error:      TSIGErrNoError,
		OtherLen:   6,
		OtherData:  []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}

	rdata, err := PackTSIG(tsig)
	if err != nil {
		t.Fatalf("PackTSIG failed: %v", err)
	}

	rr := &ResourceRecord{
		Name:     "",
		Type:     TypeTSIG,
		Class:    0,
		TTL:      0,
		RDLength: uint16(len(rdata)),
		RData:    rdata,
	}

	parsed, err := ParseTSIG(rr)
	if err != nil {
		t.Fatalf("ParseTSIG failed: %v", err)
	}

	wantAlg := "hmac-sha256"
	if parsed.Algorithm != wantAlg {
		t.Errorf("Algorithm: got %q, want %q", parsed.Algorithm, wantAlg)
	}
	if parsed.TimeSigned != tsig.TimeSigned {
		t.Errorf("TimeSigned: got %d, want %d", parsed.TimeSigned, tsig.TimeSigned)
	}
	if parsed.Fudge != tsig.Fudge {
		t.Errorf("Fudge: got %d, want %d", parsed.Fudge, tsig.Fudge)
	}
	if parsed.OriginalID != tsig.OriginalID {
		t.Errorf("OriginalID: got %d, want %d", parsed.OriginalID, tsig.OriginalID)
	}
	if parsed.Error != tsig.Error {
		t.Errorf("Error: got %d, want %d", parsed.Error, tsig.Error)
	}
	if parsed.OtherLen != tsig.OtherLen {
		t.Errorf("OtherLen: got %d, want %d", parsed.OtherLen, tsig.OtherLen)
	}
	if len(parsed.MAC) != len(tsig.MAC) {
		t.Errorf("MAC length: got %d, want %d", len(parsed.MAC), len(tsig.MAC))
	}
}

func TestTSIGParseErrors(t *testing.T) {
	tests := []struct {
		name  string
		rdata []byte
	}{
		{"too short", []byte{0x00}},
		{"no algorithm", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"truncated time", []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := &ResourceRecord{
				Type:  TypeTSIG,
				RData: tt.rdata,
			}
			_, err := ParseTSIG(rr)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestParseTSIGWrongType(t *testing.T) {
	rr := &ResourceRecord{
		Name:  "example.com.",
		Type:  TypeA,
		RData: []byte{192, 168, 1, 1},
	}
	_, err := ParseTSIG(rr)
	if err == nil {
		t.Error("expected error for non-TSIG record")
	}
}

func TestTSIGHashForAlgorithm(t *testing.T) {
	tests := []struct {
		alg   string
		valid bool
	}{
		{AlgHMACMD5, true},
		{AlgHMACSHA1, true},
		{AlgHMACSHA256, true},
		{AlgHMACSHA512, true},
		{"hmac-sha224.", false},
		{"unknown.", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			hf, err := TSIGHashForAlgorithm(tt.alg)
			if tt.valid && err != nil {
				t.Fatalf("expected valid, got error: %v", err)
			}
			if !tt.valid && err == nil {
				t.Fatal("expected error, got nil")
			}
			if tt.valid && hf == nil {
				t.Fatal("expected hash function, got nil")
			}
		})
	}
}

func TestTSIGKeyLength(t *testing.T) {
	tests := []struct {
		alg  string
		want int
	}{
		{AlgHMACMD5, 16},
		{AlgHMACSHA1, 20},
		{AlgHMACSHA256, 32},
		{AlgHMACSHA512, 64},
		{"unknown.", 0},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			if got := TSIGKeyLength(tt.alg); got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSignVerifyMessage(t *testing.T) {
	key := []byte("test-tsig-key-12345")

	msg := &Message{
		Header: Header{
			ID:      12345,
			Flags:   0x0100,
			QDCount: 1,
		},
		Questions: []Question{
			{Name: "example.com", Type: TypeA, Class: ClassIN},
		},
	}

	tsig := &TSIG{
		Algorithm:  AlgHMACSHA256,
		Fudge:      300,
		OriginalID: msg.Header.ID,
		Error:      TSIGErrNoError,
	}

	if err := SignMessage(msg, tsig, key); err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}

	if len(tsig.MAC) == 0 {
		t.Fatal("expected non-empty MAC after signing")
	}

	parsedTSIG := ExtractTSIG(msg)
	if parsedTSIG == nil {
		t.Fatal("expected TSIG record in message")
	}

	if parsedTSIG.Error != TSIGErrNoError {
		t.Errorf("Error: got %d, want %d", parsedTSIG.Error, TSIGErrNoError)
	}

	if err := VerifyTSIG(msg, parsedTSIG, key); err != nil {
		t.Fatalf("VerifyTSIG failed: %v", err)
	}
}

func TestVerifyWrongKey(t *testing.T) {
	key := []byte("correct-key")
	wrongKey := []byte("wrong-key")

	msg := &Message{
		Header: Header{
			ID:      9999,
			Flags:   0x0100,
			QDCount: 1,
		},
		Questions: []Question{
			{Name: "test.example", Type: TypeA, Class: ClassIN},
		},
	}

	tsig := &TSIG{
		Algorithm:  AlgHMACSHA256,
		Fudge:      300,
		OriginalID: msg.Header.ID,
		Error:      TSIGErrNoError,
	}

	if err := SignMessage(msg, tsig, key); err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}

	parsedTSIG := ExtractTSIG(msg)
	if parsedTSIG == nil {
		t.Fatal("expected TSIG record in message")
	}

	if err := VerifyTSIG(msg, parsedTSIG, wrongKey); err == nil {
		t.Fatal("expected verification to fail with wrong key")
	}
}

func TestVerifyTamperedMessage(t *testing.T) {
	key := []byte("test-key")

	msg := &Message{
		Header: Header{
			ID:      42,
			Flags:   0x0100,
			QDCount: 1,
		},
		Questions: []Question{
			{Name: "example.com", Type: TypeA, Class: ClassIN},
		},
	}

	tsig := &TSIG{
		Algorithm:  AlgHMACSHA256,
		Fudge:      300,
		OriginalID: msg.Header.ID,
		Error:      TSIGErrNoError,
	}

	if err := SignMessage(msg, tsig, key); err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}

	msg.Questions[0].Name = "evil.com"

	parsedTSIG := ExtractTSIG(msg)
	if err := VerifyTSIG(msg, parsedTSIG, key); err == nil {
		t.Fatal("expected verification to fail with tampered message")
	}
}

func TestSignVerifyAllAlgorithms(t *testing.T) {
	algs := []string{AlgHMACMD5, AlgHMACSHA1, AlgHMACSHA256, AlgHMACSHA512}

	for _, alg := range algs {
		t.Run(alg, func(t *testing.T) {
			keyLen := TSIGKeyLength(alg)
			key := make([]byte, keyLen)
			for i := range key {
				key[i] = byte(i)
			}

			msg := &Message{
				Header: Header{
					ID:      777,
					Flags:   0x0100,
					QDCount: 1,
				},
				Questions: []Question{
					{Name: "example.com", Type: TypeA, Class: ClassIN},
				},
			}

			tsig := &TSIG{
				Algorithm:  alg,
				Fudge:      300,
				OriginalID: msg.Header.ID,
				Error:      TSIGErrNoError,
			}

			if err := SignMessage(msg, tsig, key); err != nil {
				t.Fatalf("SignMessage failed: %v", err)
			}

			parsedTSIG := ExtractTSIG(msg)
			if parsedTSIG == nil {
				t.Fatal("expected TSIG record in message")
			}

			if err := VerifyTSIG(msg, parsedTSIG, key); err != nil {
				t.Fatalf("VerifyTSIG failed: %v", err)
			}
		})
	}
}

func TestTSIGExtractRemove(t *testing.T) {
	tsig := &TSIG{
		Algorithm:  AlgHMACSHA256,
		TimeSigned: 1700000000,
		Fudge:      300,
		MAC:        []byte{0x01, 0x02, 0x03, 0x04},
		OriginalID: 100,
		Error:      TSIGErrNoError,
	}
	rdata, err := PackTSIG(tsig)
	if err != nil {
		t.Fatalf("PackTSIG: %v", err)
	}

	msg := &Message{
		Header: Header{
			ID:      100,
			Flags:   0x8000,
			QDCount: 1,
			ANCount: 1,
			ARCount: 2,
		},
		Questions: []Question{
			{Name: "example.com", Type: TypeA, Class: ClassIN},
		},
		Answers: []ResourceRecord{
			{Name: "example.com.", Type: TypeA, Class: ClassIN, TTL: 300, RData: []byte{192, 168, 1, 1}},
		},
		Additionals: []ResourceRecord{
			{Name: "", Type: TypeOPT, Class: 1232},
			{Name: "", Type: TypeTSIG, Class: 0, TTL: 0, RDLength: uint16(len(rdata)), RData: rdata},
		},
	}

	extracted := ExtractTSIG(msg)
	if extracted == nil {
		t.Fatal("expected TSIG record")
	}
	if extracted.Algorithm != AlgHMACSHA256 {
		t.Errorf("Algorithm: got %q, want %q", extracted.Algorithm, AlgHMACSHA256)
	}

	RemoveTSIG(msg)
	if msg.Header.ARCount != 1 {
		t.Errorf("ARCount: got %d, want 1", msg.Header.ARCount)
	}
	if ExtractTSIG(msg) != nil {
		t.Fatal("expected no TSIG after removal")
	}
}

func TestSignMessageWithAnswers(t *testing.T) {
	key := []byte("signing-key-with-answers")

	msg := &Message{
		Header: Header{
			ID:      200,
			Flags:   0x8580,
			QDCount: 1,
			ANCount: 2,
		},
		Questions: []Question{
			{Name: "example.com", Type: TypeA, Class: ClassIN},
		},
		Answers: []ResourceRecord{
			{Name: "example.com", Type: TypeA, Class: ClassIN, TTL: 300, RData: []byte{93, 184, 216, 34}},
			{Name: "example.com", Type: TypeAAAA, Class: ClassIN, TTL: 300, RData: []byte{0x26, 0x06, 0x28, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		},
		Authorities: []ResourceRecord{
			{Name: "example.com", Type: TypeNS, Class: ClassIN, TTL: 300, RData: appendName(nil, "ns1.example.com")},
		},
	}

	tsig := &TSIG{
		Algorithm:  AlgHMACSHA256,
		Fudge:      300,
		OriginalID: msg.Header.ID,
		Error:      TSIGErrNoError,
	}

	if err := SignMessage(msg, tsig, key); err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}

	parsedTSIG := ExtractTSIG(msg)
	if parsedTSIG == nil {
		t.Fatal("expected TSIG record in message")
	}

	if err := VerifyTSIG(msg, parsedTSIG, key); err != nil {
		t.Fatalf("VerifyTSIG failed: %v", err)
	}

	if msg.Header.ANCount != 2 {
		t.Errorf("ANCount changed: got %d, want 2", msg.Header.ANCount)
	}
}

func TestVerifyEmptyMAC(t *testing.T) {
	tsig := &TSIG{
		Algorithm:  AlgHMACSHA256,
		Fudge:      300,
		MAC:        nil,
		OriginalID: 0,
		Error:      TSIGErrNoError,
	}

	err := VerifyTSIG(&Message{}, tsig, []byte("key"))
	if err == nil {
		t.Fatal("expected error for empty MAC")
	}
}

func TestVerifyBadTime(t *testing.T) {
	key := []byte("time-test-key")

	msg := &Message{
		Header: Header{
			ID:      300,
			Flags:   0x0100,
			QDCount: 1,
		},
		Questions: []Question{
			{Name: "example.com", Type: TypeA, Class: ClassIN},
		},
	}

	tsig := &TSIG{
		Algorithm:  AlgHMACSHA256,
		Fudge:      1,
		TimeSigned: 1000,
		OriginalID: msg.Header.ID,
		Error:      TSIGErrNoError,
	}

	if err := SignMessage(msg, tsig, key); err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}

	parsedTSIG := ExtractTSIG(msg)
	if parsedTSIG == nil {
		t.Fatal("expected TSIG record in message")
	}

	err := VerifyTSIG(msg, parsedTSIG, key)
	if err == nil {
		t.Fatal("expected error for bad time (outside fudge window)")
	}
}

func TestTSIGErrorCodeNonZero(t *testing.T) {
	key := []byte("error-code-test")

	msg := &Message{
		Header: Header{
			ID:      400,
			Flags:   0x0100,
			QDCount: 1,
		},
		Questions: []Question{
			{Name: "example.com", Type: TypeA, Class: ClassIN},
		},
	}

	tsig := &TSIG{
		Algorithm:  AlgHMACSHA256,
		Fudge:      300,
		OriginalID: msg.Header.ID,
		Error:      TSIGErrBadKey,
	}

	if err := SignMessage(msg, tsig, key); err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}

	parsedTSIG := ExtractTSIG(msg)
	if parsedTSIG == nil {
		t.Fatal("expected TSIG record in message")
	}

	err := VerifyTSIG(msg, parsedTSIG, key)
	if err == nil {
		t.Fatal("expected error for non-zero TSIG error code")
	}
}

func TestCanonicalAlgorithmName(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"hmac-sha256.", false},
		{"hmac-sha256", false},
		{"hmac-md5.sig-alg.reg.int.", false},
		{"hmac-md5", false},
		{"HMAC-SHA256.", true},
		{"hmac-sha1.", false},
		{"hmac-sha512.", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			hf, err := TSIGHashForAlgorithm(tt.input)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tt.wantErr && hf == nil {
				t.Error("expected hash function, got nil")
			}
		})
	}
}

func TestSignVerifyResponseWithTSIG(t *testing.T) {
	key := []byte("response-test-key")

	req := &Message{
		Header: Header{
			ID:      500,
			Flags:   0x0100,
			QDCount: 1,
		},
		Questions: []Question{
			{Name: "example.com", Type: TypeA, Class: ClassIN},
		},
	}

	reqTSIG := &TSIG{
		Algorithm:  AlgHMACSHA256,
		Fudge:      300,
		OriginalID: req.Header.ID,
		Error:      TSIGErrNoError,
	}

	if err := SignMessage(req, reqTSIG, key); err != nil {
		t.Fatalf("SignMessage (request) failed: %v", err)
	}

	parsedReqTSIG := ExtractTSIG(req)
	if parsedReqTSIG == nil {
		t.Fatal("expected TSIG in request")
	}

	if err := VerifyTSIG(req, parsedReqTSIG, key); err != nil {
		t.Fatalf("verify request TSIG failed: %v", err)
	}

	resp := &Message{
		Header: Header{
			ID:      req.Header.ID,
			Flags:   0x8580,
			QDCount: 1,
			ANCount: 1,
		},
		Questions: req.Questions,
		Answers: []ResourceRecord{
			{Name: "example.com.", Type: TypeA, Class: ClassIN, TTL: 300, RData: []byte{93, 184, 216, 34}},
		},
	}

	respTSIG := &TSIG{
		Algorithm:  AlgHMACSHA256,
		Fudge:      300,
		OriginalID: req.Header.ID,
		Error:      TSIGErrNoError,
	}

	if err := SignMessage(resp, respTSIG, key); err != nil {
		t.Fatalf("SignMessage (response) failed: %v", err)
	}

	parsedRespTSIG := ExtractTSIG(resp)
	if parsedRespTSIG == nil {
		t.Fatal("expected TSIG in response")
	}

	if err := VerifyTSIG(resp, parsedRespTSIG, key); err != nil {
		t.Fatalf("verify response TSIG failed: %v", err)
	}
}

func TestHMACRFC4635Vectors(t *testing.T) {
	key, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	expected, _ := hex.DecodeString("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")

	hf, err := TSIGHashForAlgorithm(AlgHMACSHA256)
	if err != nil {
		t.Fatalf("TSIGHashForAlgorithm: %v", err)
	}

	mac := hmac.New(hf, key)
	mac.Write([]byte("Hi There"))
	computed := mac.Sum(nil)

	if !hmac.Equal(computed, expected) {
		t.Errorf("HMAC-SHA256 RFC 4231 test vector 1 mismatch")
	}
}

func TestEmptyKey(t *testing.T) {
	msg := &Message{
		Header: Header{
			ID:      999,
			Flags:   0x0100,
			QDCount: 1,
		},
		Questions: []Question{
			{Name: "example.com", Type: TypeA, Class: ClassIN},
		},
	}

	tsig := &TSIG{
		Algorithm:  AlgHMACSHA256,
		Fudge:      300,
		OriginalID: msg.Header.ID,
		Error:      TSIGErrNoError,
	}

	err := SignMessage(msg, tsig, nil)
	if err == nil {
		t.Fatal("expected error with nil key")
	}
}

func TestExtractTSIGFromNoTSIG(t *testing.T) {
	msg := &Message{
		Header:    Header{ID: 1, QDCount: 1},
		Questions: []Question{{Name: "example.com.", Type: TypeA, Class: ClassIN}},
		Additionals: []ResourceRecord{
			{Name: "", Type: TypeOPT, Class: 1232},
		},
	}
	msg.Header.ARCount = 1

	if tsig := ExtractTSIG(msg); tsig != nil {
		t.Fatal("expected nil for message without TSIG")
	}
}

func TestRemoveTSIGFromNoTSIG(t *testing.T) {
	msg := &Message{
		Header:    Header{ID: 1, QDCount: 1},
		Questions: []Question{{Name: "example.com.", Type: TypeA, Class: ClassIN}},
		Additionals: []ResourceRecord{
			{Name: "", Type: TypeOPT, Class: 1232},
		},
	}
	msg.Header.ARCount = 1
	before := msg.Header.ARCount
	RemoveTSIG(msg)
	if msg.Header.ARCount != before {
		t.Errorf("ARCount changed after removing from message without TSIG")
	}
}
