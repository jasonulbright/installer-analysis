# Network

This page lists every outbound call of Installer Analysis.

## What it does

The analysis of a file needs no network. When the tool is installed by the suite installer, it also checks GitHub once a day for a newer suite version. It sends no user data and no telemetry.

## When to use it

Use it to open the firewall for the tool, or to check the traffic.

## Requirements

| Call | Target | When | Content |
|---|---|---|---|
| `https://api.github.com/repos/<repository>/releases/latest` | HTTPS to GitHub. | At the start of the window, at most once in 24 hours, only when the tool is installed by the suite installer. The cache refreshes only after a successful lookup. A failed check can be retried at a later start before 24 hours have passed. | The check for a newer suite version. The result goes to the log. |


## Steps

None.

## Limits

- A plain extract of the zip (no `suite-manifest.json`) makes no call to GitHub. A failed update check is ignored. The tool does not change a proxy setting.

## Troubleshooting

None.

## Links

- [Permissions](permissions.md)
- [Options dialog](../core/options.md)
