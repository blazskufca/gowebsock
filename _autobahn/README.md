# [Autobahn](https://github.com/crossbario/autobahn-testsuite)

This directory contains config for [autobahn testsuite](https://github.com/crossbario/autobahn-testsuite).

## Run the tests

_Run the WebSocket Echo server_
```shell
go run .\autobahn
```

_Run the autobahn test suite (on windows/powershell - You'll need slight modification for other oses/shells)_

```shell
docker run -it --rm -v "$(Get-Location)/autobahn/config:/config" -v "$(Get-Location)/autobahn/reports:/reports" -p 9001:9001 --name fuzzingserver crossbario/_autobahn-testsuite wstest -m fuzzingclient -s /config/fuzzingclient.json
```