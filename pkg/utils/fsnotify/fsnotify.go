package fsnotify

import (
	"context"
	"log/slog"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/italypaleale/traefik-forward-auth/pkg/utils"
)

// WatchFolder returns a channel that receives a notification when a file is changed in a folder.
func WatchFolder(ctx context.Context, folder string) (<-chan struct{}, error) {
	log := utils.LogFromContext(ctx)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	msgChan := make(chan struct{}, 1)
	batcher := make(chan struct{}, 1)

	// Watch for FS events in background
	go func() {
		defer watcher.Close()
		defer close(msgChan)

		for {
			select {
			case <-ctx.Done():
				// Stop the watcher on context cancellation
				return

			case event := <-watcher.Events:
				// Only listen to events where a file is created (included renamed files) or written to
				if !event.Has(fsnotify.Write) && !event.Has(fsnotify.Create) {
					continue
				}

				// Batch changes so we don't send notifications when multiple operations are happening at once
				select {
				case batcher <- struct{}{}:
					go func() {
						time.Sleep(500 * time.Millisecond)
						<-batcher

						// If the channel is full, do not block
						select {
						case msgChan <- struct{}{}:
							// Nop - signal sent
						default:
							// Nop - channel is full
						}
					}()
				default:
					// Nop - there's already a signal batched
				}

			case watchErr := <-watcher.Errors:
				// Log errors only
				log.WarnContext(ctx, "Error while watching for changes to files on disk",
					slog.Any("error", watchErr),
					slog.String("folder", folder),
				)
			}
		}
	}()

	err = watcher.Add(folder)
	if err != nil {
		return nil, err
	}

	return msgChan, nil
}
