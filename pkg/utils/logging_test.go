package utils

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogToContext(t *testing.T) {
	log := slog.New(slog.DiscardHandler)

	ctx := LogToContext(t.Context(), log)

	assert.Same(t, log, LogFromContext(ctx))
}

func TestLogFromContextWithoutLogger(t *testing.T) {
	assert.Same(t, slog.Default(), LogFromContext(context.Background()))
}
