## 2024-05-15 - [Initial setup]
**Learning:** Evaluator uses  for initial device insertions and  for subsequent updates.
**Action:** Can optimize how the database is read to reduce memory allocation during the hot paths.
## 2024-05-15 - [Evaluator performance bottleneck]
**Learning:** Evaluator uses `execute_read` to query the device by `src_mac` to see if it exists. Since the evaluator worker loop runs on every packet payload from the queue, a db lookup for every single packet to check if device exists is very expensive.
**Action:** Use an in-memory set (e.g. `_known_devices`) to cache seen MAC addresses in `evaluator.py`. This will prevent hitting the database for device existence on every single packet.
## 2024-05-15 - [Evaluator performance bottleneck]
**Learning:** Evaluator uses `execute_read` to query the device by `src_mac` to see if it exists. We can't skip the entire device processing block for known devices since `fingerprint_device` needs to process every packet to build accurate state.
**Action:** Use an in-memory set (e.g. `_known_devices`) to cache seen MAC addresses. Only skip the `SELECT` existence check using the set. Let `fingerprint_device` run on every packet. Only throttle the database `UPDATE` query.
