# Reverse-proxy example

`nginx-darkwatch.conf.example` is a starting point for deployment-specific edge controls. It is intentionally not wired into the application or a deployment pipeline.

Before use:

1. Confirm Nginx is the only network path to the ASGI service; bind the application to loopback or a private interface and enforce firewall rules.
2. Configure TLS certificates and an HTTP-to-HTTPS redirect in your environment. The example uses a placeholder hostname and does not enable certificate paths by default.
3. Validate the configuration with `nginx -t` and inspect effective configuration before reload.
4. Test oversized request rejection (413), rate limiting (429), connection caps, timeout behavior, and log redaction in a non-production environment.
5. Tune limits against expected ingestion traffic. The sample is IP-based; clients behind shared NAT may share a quota.
6. If Nginx sits behind another proxy or load balancer, configure trusted proxy ranges deliberately. Do not trust arbitrary forwarded headers.
7. Keep the upstream inaccessible from the public network. Never treat this example as proof that the deployed edge is configured securely.

The sample uses illustrative defaults (`5` requests/second with a burst of `10`, up to `10` concurrent connections per source IP, and a 16 KiB request cap). Adjust these only after testing expected collector and analyst traffic.
