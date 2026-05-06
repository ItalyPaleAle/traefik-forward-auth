# gen-config

This utility updates the [`config.sample.yaml`](../../config.sample.yaml) file based on the `Config` struct defined in [`pkg/config/config.go`](../../pkg/config/config.go).

Additionally, it writes all configuration options in the (Git-ignored) file `config.md` and updates the section in the [`all-configuration-options.md`](../../docs/content/advanced/all-configuration-options.md) between `<!-- BEGIN CONFIG TABLE -->` and `<!-- END CONFIG TABLE -->`.

To run:

```sh
# Execute form the root directory of the project
go run ./tools/gen-config
```
