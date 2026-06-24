package assets

import "embed"

//go:embed templates configs
var EmbeddedFS embed.FS
