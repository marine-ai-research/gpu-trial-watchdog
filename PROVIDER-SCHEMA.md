# Provider schema qualification

These are documentation-derived offline fixtures, not captured account responses. No authenticated API call has been executed. Live compatibility is UNVERIFIED until separately approved read-only inspection.

The official API v2 documentation describes direct Pod objects from GET /pods/{id}, and a pods list plus required pagination from GET /pods. Both expose image, disk, configured ports, mounts, gpu.id/count, cloud, dataCenterId, cost, globalNetworking and createdAt. Runtime may be null in list results; the watchdog does not use runtime utilization fields. Pod creation time, not startedAt, sets expiry. Cost is hourly COMPUTE rate, not the displayed total with storage/taxes. Policy still requires a separately reviewed total quote and exact ephemeral disk size. No API field here proves an all-inclusive spending ceiling.

Sources:
- https://docs.runpod.io/api-reference-v2/pods/get-a-pod
- https://docs.runpod.io/api-reference-v2/pods/list-pods

List envelopes used by reconciliation: pods, queuedPods, networkVolumes, globalVolumes, endpoints, clusters. Each must have pagination.hasNextPage and nextCursor. Missing, malformed, repeated or incompatible pagination stops; no empty-output shortcut.

Sources:
- https://docs.runpod.io/api-reference-v2/pods/list-queued-pods
- https://docs.runpod.io/api-reference-v2/network-volumes/list-network-volumes
- https://docs.runpod.io/api-reference-v2/global-volumes/list-global-volumes
- https://docs.runpod.io/api-reference-v2/serverless/list-serverless-endpoints
- https://docs.runpod.io/api-reference-v2/clusters/list-clusters

Empty configuration restrictions remain deliberately strict: ports must be [], mounts must be {}, globalNetworking.enabled must be false. The documentation exposes mounts as an object but does not conclusively demonstrate every empty-account serialization variant in the accessible examples. Null fields or an object containing inactive-looking members are not silently treated as empty. Such live readback requires inspection and separate source review; it never grants deletion authority. Extra non-policy metadata is retained only in memory and never logged.

Termination is DELETE /pods/{id}; documented success is HTTP 204. Exact-target absence is separately checked using GET and HTTP 404. No other ID is deleted; resource counts do not establish complete billing cleanup.

https://docs.runpod.io/api-reference-v2/pods/terminate-a-pod

The private operator route (not shipped here) uses the documented exec API. This public package has no POST/exec transport or workload files.

https://docs.runpod.io/api-reference-v2/pods/run-a-command-in-a-pod

The public OpenAPI JSON and Markdown endpoints could not be retrieved in this preparation environment. Schema claims above are limited to the accessible official rendered documentation; no assertion of full machine-schema certification or live response verification is made.

The official Pod response also exposes `entrypoint` and `cmd` as deconstructed exec-form arrays, while `args` is the stored representation. This controller requires native arrays and does not reconstruct them from a shell string. Nonempty args must be explicit JSON for both arrays and agree with native metadata. Startup fingerprints use these exact arrays. The approved readback shape still needs live commissioning; absent/inherited/ambiguous forms stop without initial deletion authority.
