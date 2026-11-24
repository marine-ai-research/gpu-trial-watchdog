# Initial target authorisation and later cleanup

Initial name equality is not deletion authority. Binding now validates name, ID, creation clock and the complete approved configuration before constructing an approved cleanup receipt. If any policy field differs or is missing, bind raises and the caller's cleanup receipt remains null. The finally block issues no DELETE. The operator must inspect and resolve that resource manually.

After a successful binding, the original exact ID remains authorised for cleanup. Later configuration drift, API failure, interruption or deadline expiry therefore still attempts deletion of that ID, followed by absence verification and reconciliation. No later mismatch authorises deleting a different ID.

Negative integration tests include same-name wrong image, cloud, GPU, data centre, ports, mounts, disk, cost and global networking. Each must stop with zero DELETE calls. Separate tests retain exact-target cleanup after successful binding and later drift, interruption or API failure.

Nullable or incomplete provisioning metadata is not silently accepted. Until a complete approved response matches, no target is bound. A provisioning/schema stop requires manual console inspection; do not proceed on the assumption that the timer owns that Pod. This conservative behaviour and live response compatibility require supervised commissioning.

Startup was previously outside the policy, so a same-name otherwise matching Pod with different ENTRYPOINT/CMD could be authorised. The policy now includes an exact startup fingerprint and the shared validator checks it both before the first receipt and during monitoring. Raw startup representations must be consistent, with no inference from a shell string. Negative integration matrices require zero initial DELETEs for missing, malformed or changed arrays/args. Later startup/creation/mapping drift exercises original-ID cleanup.
