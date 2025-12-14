package utils

import (
	"context"
	"log/slog"
)

type logCtxKey struct{}

// LogToContext returns a copy of the context with a slog logger attached
func LogToContext(ctx context.Context, log *slog.Logger) context.Context {
	return context.WithValue(ctx, logCtxKey{}, log)
}

// LogFromContext returns the Logger associated with the context
// Alternatively, returns the default logger
func LogFromContext(ctx context.Context) *slog.Logger {
	l, ok := ctx.Value(logCtxKey{}).(*slog.Logger)
	if ok {
		return l
	}

	return slog.Default()
}
