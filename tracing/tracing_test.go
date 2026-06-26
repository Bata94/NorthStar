package tracing

import (
	"context"
	"testing"
)

func TestNewDisabled(t *testing.T) {
	tracer, err := New(Config{
		Enable:      false,
		Endpoint:    "localhost:4317",
		ServiceName: "northstar",
		SampleRate:  0.1,
		InstanceID:  "test-instance",
		NodeName:    "test-node",
	})
	if err != nil {
		t.Fatalf("New with Enable=false should not error: %v", err)
	}
	if tracer == nil {
		t.Fatal("tracer should not be nil")
	}

	tr := tracer.Tracer()
	if tr == nil {
		t.Error("Tracer() should not return nil")
	}

	shutdownCtx := context.Background()
	if err := tracer.Shutdown(shutdownCtx); err != nil {
		t.Errorf("Shutdown should not error when disabled: %v", err)
	}
}

func TestNewNilSafety(t *testing.T) {
	var nilTracer *Tracing
	tr := nilTracer.Tracer()
	if tr == nil {
		t.Error("Tracer() should not return nil on nil receiver")
	}

	shutdownCtx := context.Background()
	if err := nilTracer.Shutdown(shutdownCtx); err != nil {
		t.Errorf("Shutdown should not error on nil receiver: %v", err)
	}
}

func TestNewEnabledInvalidEndpoint(t *testing.T) {
	_, err := New(Config{
		Enable:      true,
		Endpoint:    "invalid:",
		ServiceName: "northstar",
		SampleRate:  0.1,
		InstanceID:  "test-instance",
		NodeName:    "test-node",
	})
	if err != nil {
		t.Logf("Expected error or connection failure: %v", err)
	}
}
