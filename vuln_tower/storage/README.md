# Storage Module

The `storage` module provides a unified interface for persisting CVE data and application state across multiple database backends.

## Responsibilities

- CVE deduplication tracking
- State persistence between runs
- Metadata storage
- Database-agnostic operations

## Architecture

```
StorageBackend (Abstract)
    ├── SQLiteStorage
    ├── PostgresStorage
    └── MySQLStorage
```

Factory function `create_storage()` instantiates the appropriate backend based on configuration.

## Supported Backends

### SQLite (Default)

**Use Case**: Single-node deployments, development, CI/CD

**Configuration**:

```bash
export DB_TYPE=sqlite
export DB_NAME=vuln_tower.db  # File path
```

**Advantages**:

- Zero configuration
- No external dependencies
- Portable database file
- Perfect for cron jobs

**Limitations**:

- Not suitable for concurrent writes
- Local file system only

### PostgreSQL

**Use Case**: Production deployments, high availability, distributed systems

**Configuration**:

```bash
export DB_TYPE=postgres
export DB_NAME=vuln_tower
export DB_HOST=postgres.example.com
export DB_PORT=5432
export DB_USER=vuln_tower
export DB_PASSWORD=secure_password
```

**Dependencies**:

```bash
pip install psycopg2-binary
```

**Advantages**:

- ACID compliance
- Concurrent access
- Replication support
- Advanced features

### MySQL

**Use Case**: MySQL/MariaDB environments, compatibility requirements

**Configuration**:

```bash
export DB_TYPE=mysql
export DB_NAME=vuln_tower
export DB_HOST=mysql.example.com
export DB_PORT=3306
export DB_USER=vuln_tower
export DB_PASSWORD=secure_password
```

**Dependencies**:

```bash
pip install mysql-connector-python
```

## Database Schema

### Table: `processed_cves`

Tracks CVEs that have been processed and notified.

| Column           | Type             | Description                 |
| ---------------- | ---------------- | --------------------------- |
| `cve_id`         | TEXT/VARCHAR(50) | Primary key, CVE identifier |
| `published_date` | TIMESTAMP        | CVE publication date        |
| `severity`       | TEXT/VARCHAR(20) | Severity level              |
| `cvss_score`     | DECIMAL(3,1)     | CVSS base score             |
| `notified_at`    | TIMESTAMP        | When notification was sent  |

**Indexes**:

- Primary key on `cve_id`
- Index on `notified_at` for chronological queries

### Table: `meta`

Stores application metadata and state.

| Column       | Type              | Description               |
| ------------ | ----------------- | ------------------------- |
| `key`        | TEXT/VARCHAR(255) | Primary key, metadata key |
| `value`      | TEXT              | Metadata value            |
| `updated_at` | TIMESTAMP         | Last update timestamp     |

**Common Keys**:

- `last_run`: ISO timestamp of last successful execution
- `last_run_count`: Number of CVEs processed in last run

## Interface

### `StorageBackend` Abstract Class

```python
class StorageBackend(ABC):
    def initialize(self):
        """Create schema if it doesn't exist"""

    def is_processed(self, cve_id: str) -> bool:
        """Check if CVE was already processed"""

    def mark_processed(self, cve: CVE):
        """Mark CVE as processed"""

    def get_processed_cves(self, limit: Optional[int] = None) -> List[str]:
        """Get list of processed CVE IDs"""

    def get_metadata(self, key: str) -> Optional[str]:
        """Retrieve metadata value"""

    def set_metadata(self, key: str, value: str):
        """Store metadata key-value pair"""

    def close(self):
        """Close database connections"""
```

## Usage Example

```python
from vuln_tower.core import Config
from vuln_tower.storage import create_storage

# Load configuration
config = Config.load()

# Create storage backend (automatically selects based on DB_TYPE)
storage = create_storage(config)

# Check if CVE was processed
if not storage.is_processed("CVE-2024-1234"):
    # Process CVE
    storage.mark_processed(cve)

# Store metadata
storage.set_metadata("last_run", datetime.utcnow().isoformat())

# Query metadata
last_run = storage.get_metadata("last_run")

# Clean up
storage.close()
```

## Idempotency

The storage layer ensures idempotent execution:

1. Before processing a CVE, check `is_processed()`
2. Only new CVEs are processed
3. Even if notifications fail, CVE is marked as processed
4. Reruns will not duplicate notifications

This makes the system safe for cron execution even with overlapping schedules.

## Migration

### Moving from SQLite to PostgreSQL

1. Export SQLite data:

```bash
sqlite3 vuln_tower.db .dump > backup.sql
```

2. Create PostgreSQL database:

```sql
CREATE DATABASE vulntower;
CREATE USER vulntower WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE vulntower TO vulntower;
```

3. Update configuration:

```bash
export DB_TYPE=postgres
export DB_HOST=localhost
export DB_NAME=vuln_tower
export DB_USER=vuln_tower
export DB_PASSWORD=secure_password
```

4. Run once to initialize schema
5. Optionally import historical data

## Performance Considerations

### SQLite

- Excellent read performance
- Single writer at a time
- Database size grows linearly (~1KB per CVE)
- Periodic VACUUM recommended for long-running deployments

### PostgreSQL/MySQL

- Connection pooling not implemented (stateless execution model)
- Each run creates new connection
- Suitable for high-concurrency scenarios
- Leverage database-level replication for HA

## Maintenance

### Cleanup Old Records

Storage backends don't automatically prune old data. Implement cleanup if needed:

```sql
-- Delete CVEs older than 1 year
DELETE FROM processed_cves
WHERE notified_at < NOW() - INTERVAL '1 year';
```

### Backup

**SQLite**:

```bash
cp vuln_tower.db vuln_tower.db.backup
```

**PostgreSQL**:

```bash
pg_dump -U vulntower vulntower > backup.sql
```

**MySQL**:

```bash
mysqldump -u vuln_tower -p vuln_tower > backup.sql
```

## Extension

### Adding a New Database Backend

1. Create new file in `storage/` (e.g., `mongodb.py`)
2. Implement `StorageBackend` interface
3. Add factory case in `storage/__init__.py`
4. Add dependency to `requirements.txt`
5. Document configuration and usage

Example:

```python
class MongoDBStorage(StorageBackend):
    def __init__(self, connection_string: str):
        self.client = MongoClient(connection_string)
        self.db = self.client.vuln_tower

    def initialize(self):
        # Create collections and indexes
        pass

    # Implement remaining methods...
```
