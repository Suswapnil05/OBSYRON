# OBSYRON API — Error Codes & Handling

| HTTP Code | Error Reason | Typical Cause | Resolution |
|---|---|---|---|
| `400 Bad Request` | Unsupported file extension | Uploading files other than `.json` or `.csv` | Upload valid `.json` or `.csv` log files |
| `400 Bad Request` | Blank passcode / callsign | Submitting empty username or password during registration | Provide valid callsign and 4+ character password |
| `401 Unauthorized` | Invalid operator credentials | Incorrect passcode for registered operator | Use `obsyron2026` or registered password |
| `401 Unauthorized` | Invalid or expired token | Accessing protected endpoint without valid Bearer token | Authenticate via `/api/auth/login` |
| `404 Not Found` | Evidence DNA not found | Requesting `log_id` not present in active telemetry | Check evidence ID against active ledger |
| `422 Unprocessable` | Pydantic validation failure | Invalid JSON field types in request payload | Ensure payload matches Pydantic schema |
| `500 Server Error` | Unexpected backend error | Corrupted log format or parsing failure | Inspect server log output |
