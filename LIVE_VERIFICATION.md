# Live verification — 2026-10-07

One explicitly authorized standard scan completed through the authenticated Harness Security panel using native Harness authentication and exactly `opencode-go/deepseek-v4.1-flash`. No provider/model fallback, private provider-error capture, additional paid retry, source mutation or isolation relaxation was used.

| Check | Verified result |
| --- | --- |
| Activated Host runtime | `7ded20d86a6cbef9` |
| Authorized ceiling / deadline | 500 model requests / 30 minutes |
| Native SDK and Harness terminal status | `completed` |
| Elapsed transport time | 1,652,874 ms (27m32.874s) |
| Gateway outcomes, independent of retained logs | 214 completed / 0 failed / 0 cancelled |
| Attempted / admitted / dispatched requests | 214 / 214 / 214 |
| Peak active / pending requests | 4 / 2 |
| Cumulative queued requests | 101 |
| Peak queued bytes / maximum queue wait | 1,473,029 / 33,744 ms |
| Retained diagnostics / dropped entries | 128 / 87; terminal engine diagnosis retained |
| SDK-reported coverage | `complete`; 9 surfaces; 0 deferred |
| Native manifest | Completed and sealed; findings/coverage scan IDs match |
| Sealed artifact integrity | Both referenced artifacts independently matched their manifest SHA-256 digests |
| Reported findings | 7; accuracy not independently validated |

## Native export verification

The existing authenticated panel's **Export JSON**, **Export CSV** and **Export SARIF** actions were exercised. Their download Blobs were captured locally for validation rather than triggering file-save dialogs. All exports contain seven records/results. JSON and CSV finding IDs match the completed native result; SARIF parses with version `2.1.0` and valid tool/results structure. Complete gateway counters were unchanged after all three exports: no additional model inference.

| Format | Bytes | MIME type |
| --- | ---: | --- |
| JSON | 45,868 | `application/json` |
| CSV | 5,617 | `text/csv` |
| SARIF | 31,764 | `application/json` |

Only bounded status, counts, durations and configuration are published here. Scanned repository source, target paths, findings, reports, receipts, credentials, provider error text and private scan state are not published. The SDK's `complete` coverage assertion is not independent proof of exhaustive analysis or finding correctness, nor does one successful route establish compatibility with every Harness model.

The latest full serial container-enabled regression suite passed 211 tests, with zero failures or skips. The authorized paid retry is complete; no further paid scan or finding-validation action was started.
