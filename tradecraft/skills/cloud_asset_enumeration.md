When identifying external attack surfaces for an organization, multi-cloud storage and infrastructure discovery (`cloudenum`) complements DNS and host-level enumeration:

- **Organization-Level Scoping:**
  Cloud storage containers (AWS S3 buckets, Azure Blobs, GCP Cloud Storage buckets) and cloud apps are namespaced globally by company keyword rather than per-host. Run `cloudenum` once per target organization using the apex domain or company keyword; there is no need to repeat it per subdomain because all subdomains derive the same organization keyword.
- **Triage and Public Exposure:**
  Discovered cloud assets marked `public` represent unauthenticated storage access or publicly reachable databases/apps that should be prioritized for inspection. Assets marked `protected` or `disabled` confirm cloud provider presence without direct unauthenticated access.
- **Active Subdomain Enumeration Sequencing (`amass`):**
  Run `amass` when passive discovery (`subfinder`) alone looks thin or yields few subdomains — active DNS brute-forcing and cert grabs are slower and noisier, justified when passive sources found little rather than as an unconditional pairing on every target.
- **Kubernetes Cluster Inspection (`kubectl`):**
  When network scanning (`nmap_scan`, `httpx_probe`) discovers an exposed Kubernetes API server (typically port 6443) and service account credentials or bearer tokens are surfaced (from `trufflehog`, repository leaks, or cloud metadata), sequence `kubectl` with `target` and `token`. `kubectl` checks cluster authorization boundaries (`auth can-i --list`), detects overprivileged service accounts, and enumerates readable secrets without mutating cluster state.
