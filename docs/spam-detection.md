# Spam detection

eNode scores every file a client offers, and every session on what its share looks like.
It **only observes**: nothing is refused, withheld or banned because of a score. The
operator reads the list and decides, with a button per file that puts its hash on a list
(see [Acting on the list](#acting-on-the-list)).

The list is the **Spam** tab of the [admin dashboard](admin-status-dashboard.md)
(`GET /api/spam`). A file goes to the server log once when it first scores 50 or more,
and a session once when its share is flagged; the [verdict log](#verdict-log) has every
listed file.

Scoring and the verdict log each have their own switch (`filter.spam.enableScore` and
`filter.spam.enableLog`, see [Configuration](#configuration)).

The scale and the reason names are those of eMuleQt's fake file detector, so a verdict
reads the same on the server and in the client. The server sees less of a single file
than a client does — it never has the file's bytes, ratings or comments — and more of
the publisher: the whole share of a session.

## What is scored

Every record of an `OP_OFFERFILES` that the content filter (`filter.keywords` and the hash lists) let
through. A file past `files.softLimit` is scored too: what a publisher offers says what
its share is, whether or not the server indexes all of it.

## File reasons

From what the publisher says about the one file.

| Reason | Rule | Points |
|---|---|---|
| `claimed_type_mismatch` | the type tag says audio or video and the extension is a program or archive, or the reverse | 15 |
| `implausible_media_length` | a video of 50 MiB or more that runs under a minute, or an audio file of 1 MiB or more under two seconds; or a length over 12 h (video) or 24 h (audio) that the size cannot pay for | 10 |
| `implausible_media_bitrate` | a video bitrate below 40 or above 500,000 kbit/s, an audio bitrate below 16 or above 2,000 kbit/s | 10 |
| `media_size_mismatch` | the size is more than three times, or less than a third of, what length × bitrate gives | 10 |
| `bad_signal_name` | the name holds the word `fake`, `corrupt`, `wrong file`, `password protected`, `virus`, `trojan` or `malware` (whole words, case and accents ignored), or ends in `.mp4.exe` or `.avi.scr` | 25 |

The media rules apply to a file that is audio or video by its type tag or its extension,
and only to the tags the publisher sent. Rules and points are those of eMuleQt's
`FakeFileDetector` (`assessMedia`, `FakeFileRules::defaults`).

The media reasons are weak on purpose. Some clients send the bitrate tag of an old AVI or
WMV in another unit, which earns `implausible_media_bitrate` and `media_size_mismatch`
from the one tag: 20 points, still clean. In the first ten days of a live log the media
reasons, then at 15 points each, put about 2,300 ordinary releases in caution and found
nothing else.

Words that put a file on a blocklist are `filter.keywords`' job, not this one's: a name
the content filter refuses is never scored.

## Publisher reasons

From the share of one session, judged once it has offered 10 files. A reason counts
against **every** file the session offers from then on, including the offer that gave
the share away.

| Reason | Rule | Points |
|---|---|---|
| `publisher_bait_programs` | half the share or more is programs or archives between 100 KiB and 10 MiB whose names carry a video release word (`1080p`, `BluRay`, `XviD`, …) | 30 |
| `publisher_name_template` | four fifths of the share ends in the same three words, starts with a different word nearly every time, and is the same size within a tenth: one name with the keyword swapped | 30 |

Two shares that look similar are deliberately not flagged: the episodes of a series end
alike but start alike too, and one release group's files end alike but differ in size.

The session keeps counters, never the names. A file offered twice is counted twice; a
client re-offers a file once, when its download completes.

## Bands

Each reason counts once per file, and the score is capped at 100.

| Band | Score | Listed | Logged |
|---|---|---|---|
| clean | below 25 | no | no |
| caution | 25–49 | yes | no |
| suspect | 50–74 | yes | once per file |
| spam | 75 and above | yes | once per file |

A file keeps the highest score it was offered with: a later offer from an ordinary share
does not clear what a spam share said about it.

## Acting on the list

Detection decides nothing; the operator does, and the decision goes into a hash list the
content filter already reads. With `filter.localLists.enabled` each listed file has three
buttons:

| Button | The hash goes into | Effect |
|---|---|---|
| Filter | `localLists.filterFile` | refused on publish and withheld from answers; nobody is sanctioned |
| Ban list | `localLists.banlistFile` | refused, and each publisher's offer counts toward `filter.banThreshold` |
| It is fine | `localLists.whitelistFile` | overrides every list and the keywords, and the file is never listed here again |

The entry is written as `<hash> ; <name>` and applies at once. The file then leaves the
Spam tab. `POST /api/spam/files/{hash}/{list}` with `list` one of `filter`, `banlist`,
`whitelist` does the same.

The local lists are the operator's own. They add to the downloaded lists of the same
kind, are in the same format, and `filter.update` never replaces them — which is why the
buttons do not write to `hashFilter.file` and its siblings. They apply whether or not the
downloaded list is enabled, are re-read every `filter.reloadMinutes`, and may be edited by
hand.

A flagged publisher has a **Ban 24 h** button, which bans its address through the Bans
tab's own endpoint.

## Verdict log

`filter.spam.logFile` receives one line of JSON for each of:

| `type` | Written when | Fields |
|---|---|---|
| `file` | a file is first listed, and again whenever its score rises above what was logged | `hash`, `name`, `size`, `score`, `band`, `reasons`, the tags it was scored on (`fileType`, `lengthSec`, `bitrateKbps`, `codec`, each left out when not sent), and the `userHash` and `address` of the offer |
| `publisher` | a session's share is flagged | `userHash`, `address`, `files`, `reasons` |
| `decision` | a button above is pressed | `hash`, `decision` (the list), and the `name`, `score`, `band` and `reasons` the file was listed with |

Every line has a `time`. Unlike the list, the log outlasts 24 hours and a restart, so the
decisions can be held against the scores later: a reason that is mostly answered with
"It is fine" scores too high. A file whose detection expired and that comes back with the
same score is not logged again.

`filter.spam.logRotate` bounds the file, with the same keys and defaults as the top-level
`logRotate`. At `maxSizeMB` (500) the log is renamed to `spam_verdicts-<time>.jsonl` and a
new one started, keeping `maxBackups` (1) old files, gzipped with `compress`. With
`enabled: false` the file is emptied in place instead, and its first line is
`{"type":"truncated"}`. `maxSizeMB: -1` removes the limit. SIGHUP reopens the file, for an
external logrotate. Changing it needs a restart.

A ban from the publisher's button is not written to the log; it is in `filter.banFile`.

## Configuration

```yaml
filter:
  localLists:
    enabled: true
    banlistFile: "data/local_banlist.txt"
    filterFile: "data/local_filter.txt"
    whitelistFile: "data/local_whitelist.txt"
  spam:
    enabled: true
    enableScore: true
    enableLog: true
    logFile: "data/spam_verdicts.jsonl"
    logRotate:
      maxSizeMB: 500
      enabled: true
      maxBackups: 1
      compress: false
```

All are off by default.

| Key | Off means |
|---|---|
| `spam.enabled` | no detector: nothing is scored and the Spam tab is not shown |
| `spam.enableScore` | the tab is shown, with its buttons, but offers are not scored and nothing is listed; the tab says scoring is off |
| `spam.enableLog` | nothing is written to `logFile`, operator decisions included |
| `localLists.enabled` | the tab has no buttons |

`localLists` turns the content filter on by itself, so the Bans tab is then available
too. The keys are read at startup.

## Cost and limits

- A record costs one pass over its name and a few comparisons; an offer takes one mutex
  for the whole packet.
- A session tracks at most 64 name endings. At most 10,000 files and 1,000 publishers are
  listed; the dashboard shows the 500 highest scores. A detection is dropped 24 hours
  after it was last seen and is gone after a restart.
- A listed file is not proof. The reasons are weak on their own on purpose, and the
  thresholds are a first guess to be tuned against what the list shows.
