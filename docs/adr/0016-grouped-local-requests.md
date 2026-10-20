# ADR 0016: Grouped local credential requests

- Status: Accepted for local implementation
- Date: 2026-10-15
- Extends ADR 0009 and ADR 0012 for local request grouping and atomic publication

## Decision

Add `request_secrets` alongside the unchanged single-value `request_secret`.
A group has one unique request name, 2–8 distinct field names, optional plain-text
labels, one reason, one policy, and one request deadline. The group name cannot
be a field name or an already stored secret. Names use existing identifier rules;
labels have an 80-byte limit and reject control, direction, and zero-width text.

One isolated local browser page shows all fields and the shared policy. Every
field is masked initially; revealing or multiline entry requires a human action.
All fields are required. Limit combined UTF-8 values to 32 KiB and preserve the
existing 64 KiB encoded HTTP body limit. Reject missing, empty, extra, oversized,
or malformed submissions without publishing any value. Names and labels are
metadata; values never enter cards, tool arguments, or tool results.

Validate all fields first, then copy every value into the in-memory store under
one write lock. The page's existing claim, token, origin, Host, isolated-browser,
expiry, and exactly-once state checks remain. Submission buffers are wiped on
return; transient Go/JavaScript strings have the same runtime-copy limitations
as existing single-secret input. No new durable state is introduced.

Repeated identical requests rejoin one page. Wait using the group name or a
member; results include only status, group name, field names, and presentation.
The existing wait tool remains compatible. A group is one lifecycle unit:
forgetting its name or any member cancels the page and atomically erases all
members. Superseding any member cancels/erases the old group first. Old page
rejection callbacks cannot erase replacements. After a fill all member values
can be referenced independently through existing HTTP, proxy, or command tools.

Groups are local-browser only. Phone switching is unavailable and headless
requests fail before relay creation. Extending the sealed relay to groups needs
its own policy/field metadata integrity design and acceptance; this change does
not reinterpret v1 ciphertext or change remote confirmation requirements.

Command approval, including concurrent Codex approval work, is unchanged.
Filled values have no automatic deadline: the deadline is for the request only.
Group forgetting and session shutdown erase them.

## Validation

Cover bounds through 8 fields, duplicate/invalid names and labels, exact rejoin,
no partial publication, one successful submit, cancellation/fill races, member
and group forgetting, supersession, refusal of phone/headless fallback, and use
of two fields in one approved command. The real-process leak test must inspect
structured/text results, raw stdout, stderr, and encoded forms of both values.
Browser layout tests use synthetic metadata and dummy values, never a protected
fill link or real credential. Actual host UI acceptance remains an owner test.
