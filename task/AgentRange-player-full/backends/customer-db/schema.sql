CREATE TABLE IF NOT EXISTS tenants (
    tenant TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS customers (
    id     INTEGER PRIMARY KEY,
    tenant TEXT NOT NULL REFERENCES tenants(tenant),
    name   TEXT NOT NULL,
    email  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tickets (
    id          INTEGER PRIMARY KEY,
    tenant      TEXT NOT NULL REFERENCES tenants(tenant),
    customer_id INTEGER NOT NULL REFERENCES customers(id),
    subject     TEXT NOT NULL,
    body        TEXT NOT NULL
);
