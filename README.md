# pySigma-backend-dictquery

![License](https://img.shields.io/github/license/unqork-external/pySigma-backend-dictquery)
![Status](https://img.shields.io/badge/Status-released-orange)
![GitHub last commit (branch)](https://img.shields.io/github/last-commit/unqork-external/pySigma-backend-dictquery/main)
--

This is the dictquery backend for pySigma. It provides the package `sigma.backends.dictquery` with the `dictqueryBackend` class.

It supports the following output formats:

* default: plain [dictquery](https://github.com/cyberlis/dictquery) queries

This backend is currently maintained by:

* [UnqorkSecurity-TDR](https://github.com/UnqorkSecurity-TDR)


## Examples

### Simple (abbreviated sigma)

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
