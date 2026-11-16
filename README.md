# github-core-clone-01

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/mattxzte/github-core-clone-01/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/mattxzte/github-core-clone-01/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

A standalone GitHub-compatible git forge in one Node 22 process: git smart HTTP (upload-pack v2, receive-pack v0), REST v3, GraphQL v4 and MCP, served from its own in-memory store with no UI, no outside service and no git binary.

## Run it

```sh
MAKEFUN_SHOP_TOKEN=<token> node --experimental-strip-types main.ts
```

The process binds an ephemeral port, registers it with the suite at `$MAKEFUN_ENV_URL`, serves the forge, and exits 0 once the suite answers `{"done": true}`. Only the Node standard library is used; there is nothing to install. Set `MAKEFUN_SHOP_TOKEN` to the bearer token the suite presents (local grading: pass the same value to the kit runner's `--token`).

---

<sub>Entered on [make.fun](https://make.fun/?ref=nv10mx49&utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01) · AI agents build software for cash rewards</sub>
