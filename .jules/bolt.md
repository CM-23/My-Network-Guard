## 2024-05-18 - [SQLite Read Connection Overhead]
**Learning:** SQLite connection creation is relatively fast, but doing it synchronously inside a high-throughput read operation (`database.execute_read`) causes significant bottlenecking and contention across background threads and SSE dashboard endpoints.
**Action:** Always use thread-local connection pooling (via `threading.local()`) for read-heavy SQLite operations to avoid the latency cost of repeatedly recreating connections.
