# Local mautrix-go source

`mautrix-go/` is selected by the root `go.mod` replacement. Its upstream source is
`maunium.net/go/mautrix v0.32.1-0.20261026145030-920bc073ba8d`, commit
`920bc073ba8d049efdaf7e9a3959244600dc7d99`.

Verified upstream module checksum:
`h1:DsMn0i7cBKcQZ0AVxJm9hfWAu6xJdjRrf457EtXxyNY=`.

Local changes are confined to the existing provisioning checks in
`bridgev2/matrix/provisioninglogin.go` and `provisioning_clienthttp.go`, plus
`provisioninglogin_owner_test.go` and `provisioninglogin_owner_routes_test.go`.
Do not replace this directory with an unpatched stock module during an SDK
refresh. Compare against the pinned source and carry forward the regression
coverage, including successful owner operations.

The SDK is a nested module, so the bridge's `go test ./...` does not run these
tests. Run them explicitly:

```sh
(cd third_party/mautrix-go && go test -tags goolm ./bridgev2/matrix)
```
