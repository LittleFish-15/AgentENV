# Native CoW experimental relay

Latest: A_prepare_native_service_builtin_v3.py prepare with the already-built
Runtime, builtin-FC and runtime-tools reports. V2 stopped on EADDRINUSE during
the new-service port probe before starting any service or Guest.

V3 selects the first bindable IPv4 loopback port in 18082..18089. It does not
connect to, inspect or stop existing listeners. Non-EADDRINUSE errors and range
exhaustion stop preparation. The selected port is saved in the immutable new
service definition and used by Runtime, proxies, CLI credentials, root block
and health reporting. Root rechecks availability immediately before submission;
a concurrent new occupant stops activation. Existing partial deployments remain
preserved. There is no cleanup, overwrite or silent migration of an installation.

The actual builtin-FC Guest acceptance and all old-service identity checks are
retained. Root creates only the new isolated Runtime unit with the previously
reviewed process groups/capabilities/private namespaces and 2 GiB memlock limit.
Without a source-matched rootfs binding, readiness is explicitly sharing-disabled.
No SDK calls, Guests or existing-service changes occur during preparation.
No core/main modifications, credentials, active manifests or binaries published.

SHA256: 7151a01eb7259cc20162cd6ab8f38d01df00325d8ca114ad0a919833ef7c0525
