# M4 smoke run

Built the Linux container image from a Linux/arm64 binary (`portl-agent:local`) and verified host-to-container exec using the host debug CLI on macOS.

```text
$ ./target/debug/portl id new
created identity: 86d76e0ab1faff388fb42eac5ec5c11270a25f4e4fac0df082c2af6d29fffeef

$ ./target/debug/portl docker container add demo --image portl-agent:local
portlafwm2rrmxwhp2zkbk5wka6vo4lh3buyxp2hzgklav7aqjjoaw7ppoaabaeaacaiaaaaaaaaaabwm2rrmxwhp2zkbk5wka6vo4lh3buyxp2hzgklav7aqjjoaw7ppoafgxsj46bvg22y5abqbq3lw4cvr7l7trd5uf2wf5robcjykex2oj6wa34ecykxw2kp773xqav2uq4admwq4byaaarfbxp4b4tpop3eilbyl2wupeutuwas6b64fywlautlcgrjt7kd72dobl44fn7g4ligvlvx77ysm7tm5d7kzcxe6xh2e5ottrxgtgaca

$ ./target/debug/portl exec demo -- echo "hello from m4"
hello from m4

$ ./target/debug/portl docker container rm demo
```

## 2026-04-19 post-fix re-run

The requested exact release-mode smoke path now needs `--force` on removal, but the
`exec demo -- echo hi` step was not green in this macOS environment.

Observed results:

```text
$ ./target/release/portl docker container add demo
# initially failed to pull ghcr.io/knickknacklabs/portl-agent:latest with HTTP 403

$ docker build -t ghcr.io/knickknacklabs/portl-agent:latest ...
# built a local replacement image under the default tag

$ ./target/release/portl docker container add demo
# succeeded and printed a ticket

$ ./target/release/portl exec demo -- echo hi
discovery failed: Service 'pkarr' failed; Service 'dns' failed

$ ./target/release/portl docker container rm demo --force
# cleanup succeeds when the alias exists; manual docker cleanup was needed after the failed exec path
```

This leaves the post-fix smoke **blocked by endpoint discovery in this environment**, not by
container provisioning or forced removal.

Image build steps used for the smoke:

```text
$ docker run --rm --platform linux/arm64 -v "$PWD":/src -w /src -e CARGO_TARGET_DIR=/src/target-linux-arm64 rust:1.89-slim bash -c 'apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates cmake && cargo build --release --bin portl'
$ cp target-linux-arm64/release/portl adapters/docker-portl/images/bin/portl-arm64
$ docker build --platform linux/arm64 --build-arg TARGETARCH=arm64 -t portl-agent:local -f adapters/docker-portl/images/Dockerfile.reference adapters/docker-portl/images/
```
