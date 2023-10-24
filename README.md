# pySigma-backend-dictquery

![GitHub](https://img.shields.io/github/license/unqork-external/pySigma-backend-dictquery)
![Static Badge](https://img.shields.io/badge/Status-release-green)
![Dynamic TOML Badge](https://img.shields.io/badge/dynamic/toml?url=https%3A%2F%2Fraw.githubusercontent.com%2Funqork-external%2FpySigma-backend-dictquery%2Fmain%2Fpyproject.toml&query=%24.tool.poetry.version&label=Version)



[![Run pytest](https://github.com/unqork-external/pySigma-backend-dictquery/actions/workflows/test.yml/badge.svg)](https://github.com/unqork-external/pySigma-backend-dictquery/actions/workflows/test.yml)
[![Build WHLs](https://github.com/unqork-external/pySigma-backend-dictquery/actions/workflows/build.yml/badge.svg)](https://github.com/unqork-external/pySigma-backend-dictquery/actions/workflows/build.yml)

---

[pySigma](https://github.com/SigmaHQ/pySigma) plugin to output a [dictquery](https://github.com/cyberlis/dictquery) from a given sigma


## Examples

### Simple

```yaml
detection:
    sel:
        fieldA: valueA
        fieldB: valueB
    condition: sel
```

converts to

```string
fieldA=='valueA' AND fieldB=='valueB'
```

### Complex (abbreviated sigma)

```yaml
detection:
    users_1:
        username|contains: 
        - 'test.user1'
        - 'test.user2'
        - 'test.user5'
    event_1:
        eventname|re: 
        - \S+\w{3,5}\S+
        - \S+\w{9,}\S+
    event_2:
        eventname|endswith:
        - barbaz
        - foo
    user_special:
        username|contains: 'test.user7'
    event_special:
        eventname:
        - eventone
        - eventtwo
        process.name|startswith:
        - proc1
        - proc2
    exclude_proc:
        process.pid|lt: 10

    condition: (any of event_* and users_1) or (user_special and event_special and not exclude_proc)
```

converts to

```string
(((eventname MATCH /\\S+\\w{3,5}\\S+/ OR eventname MATCH /\\S+\\w{9,}\\S+/) OR (eventname LIKE '*barbaz' OR eventname LIKE '*foo') OR ((eventname IN ['eventone', 'eventtwo']) AND (`process.name` LIKE 'proc1*' OR `process.name` LIKE 'proc2*'))) AND (username LIKE '*test.user1*' OR username LIKE '*test.user2*' OR username LIKE '*test.user5*')) OR (username LIKE '*test.user7*' AND ((eventname IN ['eventone', 'eventtwo']) AND (`process.name` LIKE 'proc1*' OR `process.name` LIKE 'proc2*')) AND (NOT `process.pid`<10))
```
