package filters

import "log/slog"

// slog.Any("key", value) has a route's shape and is not one.
func Log(isRestricted bool) {
	slog.Debug("filter", slog.Any("isRestricted", isRestricted))
}
