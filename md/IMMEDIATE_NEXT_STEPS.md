# Immediate Next Steps to Reach 100/100

This is a focused 30-day action plan. Tasks are ordered by impact and dependency. 

## Week 1 (Target 85/100)
1) Real-Time Entropy Streaming
   - Add a low-overhead file watcher that samples entropy on write streams (per PID + path).
   - Thresholds: rolling window (2-3s), flag if entropy >7.5 and write rate spikes.
   - Output: alert event with PID, path, entropy, bytes/sec.
2) ML Behavioral Anomaly Model
   - Build feature vector per process: CPU spikes, file writes/sec, entropy flag, registry edits, network bursts.
   - Start with unsupervised (Isolation Forest) to avoid labels; retrain daily.
   - Persistence: save model to disk; warm-start on boot.
3) Ransomware Family Classification
   - Add lightweight signature/heuristic layer: file extension patterns, note artifacts, mutex/pipe names.
   - Store per-family rules in JSON; emit family tag in events.
4) Adaptive Whitelist Learning
   - Maintain per-host whitelist from stable processes/services.
   - Decay scores over time; require recurrence before trusting.

## Week 2 (Target 90/100)
5) Incident Response Automation
   - Playbooks: (a) suspend/kill PID, (b) isolate NIC, (c) snapshot key dirs before kill, (d) disable persistence keys.
   - Add dry-run mode and rate limits to avoid over-isolation.
6) File Recovery Integration
   - Hook VSS: create snapshot on alert; expose quick-restore for recent files.
   - Include guardrails: size cap, path allowlist.
7) ML C&C Detection
   - Behavioral network model: burstiness, uncommon ports, DNS entropy, failed connect rate.
   - Start with rules + simple anomaly (z-scores) before heavier ML.
8) Encryption Key Recovery
   - On alert, dump process memory (where permitted) and scan for key material patterns.
   - Protect and encrypt dumps; auto-delete after TTL.

## Week 3-4 (Target 100/100)
9) Threat Intelligence Integration
   - Pull curated IP/domain feeds; cache locally; enrich alerts with TI hits.
   - Add update scheduler and TTL; avoid blocking UI.
10) Dark Web Monitoring (optional)
   - Consume API-based intel; map leaked data indicators to alerts.
11) ML Explainability (optional)
   - Log top contributing features per decision; show in UI details pane.
12) Multi-Tenant & Advanced Analytics (optional)
   - Add per-tenant policy, RBAC, and usage dashboards.

## Engineering Checklist
- Telemetry schema: extend events with entropy, model score, family tag, TI hits, playbook actions.
- Performance: keep agents <5% CPU; batch writes; use async I/O.
- Safety: circuit breakers on auto-kill/iso; dry-run flags; audit log for every action.
- Testing: unit + integration for entropy sampler, model loader, playbooks, VSS restore, TI fetcher.

## Delivery Order (pragmatic)
- Day 1-2: Entropy streaming + alert plumbing
- Day 3-4: Isolation Forest baseline + scoring pipeline
- Day 5: Family heuristics + adaptive whitelist
- Day 6-7: Playbooks (suspend/kill/isolate) + guardrails
- Day 8: VSS snapshot/restore MVP
- Day 9-10: Network anomaly rules
- Day 11-12: Memory key scan
- Day 13-15: TI feed integration

## Notes
- Existing repo does NOT include the ML/model code or the 12 audit files; these need to be added.
- Focus on low-friction wins first (entropy + anomaly model + playbooks) to jump from ~75 to ~90 quickly.
