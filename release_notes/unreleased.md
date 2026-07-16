**Unreleased**

* Security: Enable TLS certificate verification by default while preserving an explicit opt-out.
* Security: Escape attacker-controlled IOC widget values before embedding them in JavaScript handlers.
* Security: Encode endpoint GUIDs before inserting them into request paths.
* Security: Classify the state-changing scan endpoint action as generic and not read-only.
* Security: Normalize upstream IOC levels and fail safely to high severity for unknown values.
* Security: Advance scheduled-poll checkpoints only after every record for an IOC is saved successfully.
