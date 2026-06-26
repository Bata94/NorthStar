package tracing

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

type Config struct {
	Enable      bool
	Endpoint    string
	ServiceName string
	SampleRate  float64
	InstanceID  string
	NodeName    string
}

type Tracing struct {
	provider *sdktrace.TracerProvider
	tracer   trace.Tracer
}

func New(cfg Config) (*Tracing, error) {
	if !cfg.Enable {
		return &Tracing{}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(cfg.Endpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}

	res := resource.NewWithAttributes(
		"https://opentelemetry.io/schemas/1.26.0",
		attribute.String("service.name", cfg.ServiceName),
		attribute.String("service.instance.id", cfg.InstanceID),
		attribute.String("node.name", cfg.NodeName),
	)

	var sampler sdktrace.Sampler
	switch {
	case cfg.SampleRate >= 1.0:
		sampler = sdktrace.AlwaysSample()
	case cfg.SampleRate <= 0:
		sampler = sdktrace.NeverSample()
	default:
		sampler = sdktrace.TraceIDRatioBased(cfg.SampleRate)
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sampler)),
	)

	tracer := provider.Tracer(cfg.ServiceName)

	otel.SetTracerProvider(provider)

	return &Tracing{
		provider: provider,
		tracer:   tracer,
	}, nil
}

func (t *Tracing) Tracer() trace.Tracer {
	if t == nil || t.tracer == nil {
		return noop.NewTracerProvider().Tracer("")
	}
	return t.tracer
}

func (t *Tracing) Shutdown(ctx context.Context) error {
	if t == nil || t.provider == nil {
		return nil
	}
	return t.provider.Shutdown(ctx)
}
