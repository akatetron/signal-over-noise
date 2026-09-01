# 🗄️ SQL Security

**Track:** Google Cybersecurity Professional Certificate · **Course:** Assets, Threats, and Vulnerabilities · **Tables:** `log_in_attempts`, `employees`

## What this lab was about

SQL filtering is a core skill for pulling exactly the right rows out of security-relevant data during an investigation. This exercise works through six queries against two tables — `log_in_attempts` and `employees` — using `AND`, `OR`, `NOT`, and `LIKE` with wildcards to investigate suspicious login patterns and to scope which employees' machines needed a targeted security update.

## Files in this folder

| File | Description |
|---|---|
| [`Study_Guide.pdf`](./Study_Guide.pdf) | Full write-up of all six queries with the reasoning behind each filter. Quick reference on the last page. |
| `source-files/Apply filters to SQL queries_.docx` | Original lab worksheet (given) |

## Complete walkthrough

The first three queries investigate login activity: pulling every failed login after 18:00 using `AND` to require both the time and failure conditions together; pulling all activity across two specific dates around a suspicious event using `OR`; and excluding all login attempts originating from Mexico using `NOT LIKE 'MEX%'`, where the `%` wildcard catches both "MEX" and "MEXICO" as they appear in the data.

The remaining three queries scope which employees needed a system update: Marketing employees in the East building specifically, combining `AND` with a `LIKE` wildcard on the office field; Finance or Sales employees together using `OR`; and finally every employee outside IT using `NOT LIKE`. Across all six, the same four operators do all the work — `AND` requires every condition, `OR` accepts any one of them, `NOT` excludes a match, and `LIKE` with `%` enables partial/pattern matching instead of requiring an exact string.

---

*Chayan Panchal · [github.com/akatetron](https://github.com/akatetron) · Google Cybersecurity Professional Certificate*
