# 33 — Shipping logs: to a log server, Splunk, or a SIEM

PVFS and PVOS write every log line as a record ([doc 32](32-log-events.md)):
a severity, a stable event name, a category, an outcome, a UTC time, and
named fields, each with a privacy class. There are two ways to get those
records off a box, and both can run at once:

- **Built in** (PVOS D222d, D222e): the daemons send to the destinations
  you configure. Nothing else to install, and each destination has its own
  privacy level:
  - Loki;
  - Splunk HEC;
  - syslog (RFC 5424 as text, JSON, CEF or LEEF, or RFC 3164, over TLS,
    TCP or UDP);
  - Graylog (GELF over UDP, TCP or HTTP);
  - Elasticsearch / OpenSearch (`_bulk`, ECS);
  - OpenTelemetry (OTLP/HTTP);
  - any HTTPS endpoint that takes JSON (PVFS's own records, ECS or OCSF).
- **Bring your own collector**: the records are in the journal with their
  fields, so a collector you already run (Splunk Universal Forwarder, Elastic
  Agent, Vector, rsyslog, Grafana Alloy) can read them.

## Built-in destinations

### Setting them up

On a PVFS box, run:

```bash
pvfs log destinations
```

It lists what is configured, then asks whether to add, test or remove one.
Adding asks one question at a time: the type, where it goes, a token if the
receiver needs one, how to check the receiver's certificate, the privacy
level, the least severe record to send and the categories. It offers to send
a test event at the end. `pvfs log destinations add|test|remove|list` are the
same steps for scripts.

The answers go to `~/.config/pvfs/log-destinations.json` (or
`/etc/pvfs/log-destinations.json` if that exists, or the file
`$PVFS_LOG_DESTINATIONS` names). Tokens go in their own files beside it,
readable only by their owner. A running pvfsd picks up a change within 30
seconds.

On PVOS the same settings live in **Settings → Logging**, or `pvos logging`.
Tokens are kept in the PVOS keychain.

### The file

```json
{
  "v": 1,
  "pseudonym_key_file": "pseudonym.key",
  "destinations": [
    { "name": "logs", "type": "loki", "url": "http://192.168.1.83:3100", "privacy": "full" },
    { "name": "splunk", "type": "splunk_hec", "url": "https://splunk.corp:8088",
      "index": "pvfs", "secret": "splunk.token",
      "tls": { "pin_sha256": "AB:CD:…" } },
    { "name": "siem", "type": "syslog", "address": "siem.corp:6514",
      "transport": "tls", "format": "cef", "categories": ["audit", "security"] },
    { "name": "hook", "type": "https_json", "url": "https://collector.corp/ingest",
      "secret": "hook.token", "header": "Authorization" }
  ]
}
```

| Key | Means | Default |
|---|---|---|
| `name` | letters, digits, `-`, `_` | — |
| `type` | `loki`, `splunk_hec`, `syslog`, `https_json`, `gelf`, `elasticsearch`, `otlp` | — |
| `url` | `http(s)://host[:port][/path]` (Loki, HEC, HTTPS JSON); the path defaults to `/loki/api/v1/push`, `/services/collector/event`, `/` | — |
| `address` | `host:port` (syslog; GELF over udp/tcp) | — |
| `transport` | syslog: `tls` (RFC 5425), `tcp` (RFC 6587 octet counting), `udp`; GELF: `udp`, `tcp` (NUL-delimited), `http` | syslog `tls`, GELF `udp` |
| `format` | syslog: `rfc5424` (the line, fields as structured data), `json` (the record), `cef`, `leef`, `rfc3164`; https_json: `schema1`, `ecs`, `ocsf` | `rfc5424`, `schema1` |
| `index`, `sourcetype` | HEC (index, sourcetype); Elasticsearch (index or data stream) | token's index, `pvfs:json`; `logs-pvfs-default` |
| `header` | the header the token goes in. For `Authorization` the token is sent as `Bearer <token>` (Elasticsearch: `ApiKey <token>`) unless it names its own scheme (`Basic …`) | `Authorization` |
| `secret` | a file holding the token (relative to this file), or `keychain:<name>`: the Mac companion's Keychain item (`pvfs-companion-log` / `<name>`), which only the companion reads (PVOS D226) | none |
| `doc_ids` | Elasticsearch only (PVOS D228): `true` sends each record's id as `_id`, so a resent batch is not stored twice (a 409 for it counts as delivered). Off by default: Elastic advises leaving `_id` unset on LogsDB data streams (`logs-*-*`); use it with a plain index or a stream that takes ids | `false` |
| `labels` | Loki only: extra stream labels on every push, `{"env": "prod"}`. Names are label names, not `job`, `host`, `service`, `level` or `category`; values 1–128 characters. Fixed values only: each distinct set is a Loki stream | none |
| `tls.ca_file` | trust only this CA bundle (PEM) | the public roots |
| `tls.pin_sha256` | trust only this certificate (`openssl x509 -fingerprint -sha256`) | — |
| `privacy` | `minimal`, `identified`, `full` | `minimal` |
| `min_severity` | `error`, `warning`, `notice`, `info` | `info` |
| `categories` | any of `system`, `audit`, `security` | all |
| `services` | only these (`pvfsd`, `pvfs-mount`, `pvosd`, `app:iac`, …) | all |
| `spool_mb` | the most this destination may queue on disk | 256 |
| `enabled` | `false` keeps it configured but stopped | `true` |

There is no setting to skip certificate checks. A receiver with a
self-signed certificate is trusted by its pin.

### How delivery works

- **At least once.** A record goes into the destination's spool on disk
  first (`<data dir>/log-spool/<name>/`). A sender thread sends what is
  queued, in batches of up to 500, and only then moves its cursor. If the
  receiver is down, records wait and are sent when it is back, in order.
  The record's `id` lets a receiver drop a resent duplicate.
- **Bounded.** Over `spool_mb`, the oldest queued records are dropped and
  counted.
- **Private at send time.** The spool holds the full record on the box's own
  disk (as the journal does). Each batch is rendered at the destination's
  privacy level when it is sent, so a stricter level set later also applies
  to what was already queued.
- **Where to see it** (PVOS D228): `pvfs serve status` lists each
  destination: sent, queued, dropped, the last delivery, the last error,
  and FAILING. The owner reads every box's on its health pass and sends a
  fleet event (`log_destination_failing`, `log_destination_recovered`), so a
  box whose only destination is down — the NAS, shipping to the log server —
  still reaches a person.
- **Health.** A destination failing for 15 minutes logs
  `pvfs.log.destination_failing` (not to itself), and
  `pvfs.log.destination_recovered` when it is back. PVOS also shows the
  health in Settings and posts a notification.

| Name | Severity | Category | Meaning |
|---|---|---|---|
| `pvfs.log.destination_failing` | warning | system | A destination has not delivered for 15 minutes. |
| `pvfs.log.destination_recovered` | notice | system | It delivered again. |
| `pvfs.log.destinations_loaded` | notice | system | The destinations file was read (how many). |
| `pvfs.log.destination_problem` | warning | system | A destination in the file was left out, or the file could not be read (the running ones are kept). |
| `pvfs.log.test` | notice | system | A test event (`pvfs log destinations test`). |

### On a Mac (PVOS D226)

The companion app's **Settings → Logging** lists, adds, tests and removes
this Mac's destinations (`pvfs-companion log`, which also asks its
questions bare). They live in the same `~/.config/pvfs/log-destinations.json`
the `pvfs` CLI uses. A token entered there goes to the Keychain (`secret:
"keychain:<name>"`), not a file. The agent (`pvfs-companion serve`) ships
its own records: approvals and refusals (`pvfs.agent.audit`), its start and
any panic. The `pvfs` CLI reports a Keychain token as one it cannot read.

### What each receiver gets

- **Loki**: a push with labels `job="pvlog"`, `host`, `service`, `level`,
  `category` on audit/security lines, and the destination's own `labels`
  (PVOS D224: the fleet gives the NAS `env="prod"`, the label our alert
  rules select, which Alloy gives the journal streams). The line is the
  text a person reads. `event`, `outcome` and `id` are structured
  metadata.
- **Splunk HEC**: one event per record, with `time`, `host`, `source` (the
  service) and `sourcetype`. The `event` is the record as JSON (schema 1,
  [doc 32](32-log-events.md)). Search with
  `index=<index> sourcetype=pvfs:json event.event="pvfs.access.denied"`.
- **syslog**: RFC 5424.
  - `APP-NAME` is the service and `MSGID` the event name (cut at 32
    characters; the full name is in the data).
  - Facility is authpriv for audit/security records and daemon for the rest.
  - `rfc5424` puts the fields in `[pvlog@32473 event="…" …]`; `json` sends
    the record as the message; `cef` sends `CEF:0|PhraseVault|PVFS|…`:
    - `act` is the event, `outcome`, `cat` is the category;
    - `src`/`spt` come from the client's address, and `suser` from the
      principal or member;
    - other fields go in `cs1`–`cs6` with their labels.
  - 32473 is IANA's documentation enterprise number until PhraseVault has
    its own.
- **HTTPS JSON**: newline-delimited records, POSTed in batches, as
  schema 1 (default), ECS or OCSF (`format`).
- **syslog LEEF** (IBM QRadar): `LEEF:2.0|PhraseVault|PVFS|<version>|<event>|x09|`
  then tab-separated `devTime` (epoch ms), `sev` (1–10), `cat`,
  `src`/`srcPort`, `usrName`, `outcome`, `pv_<field>` and `msg`.
- **syslog RFC 3164**: `<PRI>Mmm dd hh:mm:ss HOST TAG[PID]: <line>`. The time
  is UTC, because the format cannot name a zone; prefer RFC 5424.
- **Graylog (GELF 1.1)**: `short_message` is the line, `level` the syslog
  severity; `_event`, `_category`, `_outcome`, `_service`, `_record_id`, and
  each field as `_<name>` (a field named `id` as `_f_id`: GELF reserves
  `_id`). Over UDP a record that would not fit one 8 KiB datagram is sent
  with its sentence cut and without its extra fields.
- **Elasticsearch / OpenSearch**: `POST <url>/_bulk`, a `create` into the
  index (or data stream) and an ECS document per record. A reply with
  `"errors":true` counts as a failure, so the whole batch is resent: the
  documents Elasticsearch had already taken are then stored twice, with
  the same `event.id` (collapse on it to see each once).
  - The default index, `logs-pvfs-default`, follows Elastic's
    `logs-<dataset>-<namespace>` naming, so Elasticsearch's built-in `logs`
    template makes it a **data stream** with ECS mappings, and Kibana's
    `logs-*` view finds it. Any other name not matched by a template is a
    plain index (OpenSearch has no such template: a plain index there).
  - Checked live on 2026-10-08 against Elasticsearch 9.5.2 (security on,
    its own HTTPS certificate, an API key; D222e).
- **OpenTelemetry**: `POST <url>/v1/logs`, OTLP/HTTP JSON.
  - Resource attributes: `service.name`, `host.name`, `process.pid`.
  - Record attributes: `pvfs.event`, `pvfs.category`, `pvfs.outcome`,
    `pvfs.id` and the fields.
  - `severityNumber`: debug 5, info 9, notice 10, warning 13, error 17,
    critical 21.
  - Point it at an OpenTelemetry Collector, and from there Datadog, New
    Relic, Honeycomb, Grafana Cloud or Splunk Observability.

### ECS and OCSF, as mapped

| Record | ECS | OCSF |
|---|---|---|
| `ts` | `@timestamp` | `time` (ms) |
| the line | `message` | `message` |
| `event` | `event.action` | `metadata.log_name`, `unmapped.pvfs_event` |
| `id` | `event.id` | `metadata.uid` |
| `severity` | `log.level`, `log.syslog.severity.{code,name}`, `event.severity` | `severity_id` (1 info … 6 fatal) |
| `outcome` | `event.outcome` | `status_id` (1 success, 2 failure) |
| `category` | `event.kind` (`alert` for security) | the class, below |
| `peer_addr` | `source.ip`, `source.port` | `src_endpoint.ip`, `.port` |
| `principal` / `member` | `user.id` | `actor.user.uid` |
| `host`, `service`, `pid` | `host.name`, `service.name`, `process.pid` | `device.hostname`, `unmapped.pvfs_service` |
| other fields | `labels.<name>` | `unmapped.<name>` |

ECS `event.category` and `event.type`, by the event's name:
- `authentication` for `*.auth.*`, `*.signin.*` and `*.session.*`;
- `iam` for authority, grants, members, invites, shares, keychain, access,
  control and desktop;
- `network` for `*.tls.*`;
- `web` for `*.web.*` (pvosd's web plane: a refused cross-origin websocket);
- `process` for the daemon lifecycle;
- `host` otherwise.

The type is `denied` for a refused security event, `change` for an audit
event, `error` for an error, and `info` otherwise.

OCSF classes:
- **3002** Authentication (activity 1) for security and audit events about
  auth, sign-in, access, control or TLS;
- **3005** User Access Management (activity 1) for other audit events;
- **0** Base Event (activity 99) otherwise.

`metadata.version` is 1.1.0. These mappings are a best effort; a SIEM that
needs another can take schema 1 and map it.

### Privacy

A destination's level decides what leaves the box ([doc 32](32-log-events.md)
§Privacy). `minimal`, the default:

- people are pseudonyms (`a:…`, keyed per install);
- paths, file names, titles and error texts are hashed placeholders
  (`h:…`, and `‹path›` in the sentence);
- names and emails are left out;
- client addresses are kept only on security and audit events.

`identified` adds names, emails and addresses (for a SIEM that maps actions
to employees). `full` sends everything. Choosing either asks first.

To turn a pseudonym back into a key, on the box:

```bash
pvfs log whois a:3f9a12bc04de
```

It uses the same key as the destinations, so the answer comes only from a
box that has it.

## Bring your own collector

Every daemon line is in the journal with its fields:

- `MESSAGE` is the text a person reads.
- `PRIORITY` is the severity.
- `PV_SCHEMA=1`, `PV_ID`, `PV_EVENT`, `PV_CATEGORY`, `PV_OUTCOME`,
  `PV_SERVICE`, `PV_COMPONENT` and `PV_VIA`.
- One `PV_<NAME>` per field: `PV_PEER_ADDR`, `PV_PRINCIPAL`, `PV_JOB`, ….

The journal keeps everything (`full`). A collector that ships it decides what
leaves. To ship less from the journal itself, set `PVFS_LOG_PRIVACY=minimal`
in the daemon's unit.

- **Grafana Alloy** (what our log server uses, HomeLab `roles/alloy`):
  `loki.source.journal` → relabel `__journal_pv_event` etc. to temporary
  labels → `loki.process` `stage.structured_metadata` → drop the labels;
  `category` as a label for audit/security (HomeLab `docs/LOGGING.md`).
- **Splunk Universal Forwarder**: a `journald://` input (Splunk 8.1+) with
  `journalctl-include-fields = PRIORITY,MESSAGE,PV_*` and
  `journalctl-filter = PV_SCHEMA=1`; sourcetype `pvfs:journal`. The `PV_*`
  fields arrive as indexed fields.
- **Elastic Agent / Filebeat**: the `journald` input with
  `include_matches: ["PV_SCHEMA=1"]`. An ingest pipeline maps `PV_EVENT` →
  `event.action`, `PV_CATEGORY` → `event.category`, `PV_OUTCOME` →
  `event.outcome`, `PV_PEER_ADDR` → `source.address`, `PV_PRINCIPAL` →
  `user.id`, and `PRIORITY` → `log.syslog.severity.code`.
- **Vector**: a `journald` source with `include_matches.PV_SCHEMA = ["1"]` →
  `remap` (`.event = .PV_EVENT` …) → any sink (Splunk HEC, Elasticsearch,
  Datadog, S3, Kafka, …).
- **rsyslog**: `module(load="imjournal")` with the default template to
  forward the text. For the fields, use a template over `$!PV_EVENT` etc.
  with `omfwd` RFC 5424, or `mmjsonparse` if `PVFS_LOG_FORMAT=json` is set
  for the unit.
- **syslog-ng**: `systemd-journal()` source; the fields are
  `${.journald.PV_EVENT}` and so on.

The NAS has no journal: its daemon writes `pvfsd.log` (PVOS D222c), which a
collector can tail, and it can use a built-in destination.
