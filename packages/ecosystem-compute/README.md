# ecosystem-compute

Multi-provider GPU broker and cloud compute failover for `appEcosystem`.

## Invariants

1. **Local first, cloud optional:** Default state is `enabled: false`. Local and LAN compute always function with zero external network connectivity.
2. **Unified ComputeProvider Protocol:** Seamless failover across `local`, `lan_node`, `skypilot`, `runpod`, and `generic_openai`.
3. **Data Classification & Release Gate:** Workloads tagged `classification: sensitive` (router logs, scan results, camera frames, private evidence) are prohibited from cloud egress unless an authenticated operator grants a policy-signed `data_release`.
4. **Budget Enforcement:** Hard monthly USD cap and per-job limits.

