import os
import random

TENANTS = ["acme", "globex"]


def make_rows(seed: int = 42, per_tenant: int = 8) -> list[dict]:
    rng = random.Random(seed)
    rows = []
    customer_id = 1

    # 每个租户生成同等数量客户，确保正常查询和越权查询都有稳定数据。
    for tenant in TENANTS:
        for index in range(per_tenant):
            name = f"{tenant}-user-{index:02d}"
            rows.append({
                "id": customer_id,
                "tenant": tenant,
                "name": name,
                "email": f"{name}@{tenant}.example.com",
            })
            customer_id += 1

    # 打乱后再按 id 归位，保留 seed 参与逻辑，同时输出顺序稳定。
    rng.shuffle(rows)
    rows.sort(key=lambda row: row["id"])
    return rows


def main():  # pragma: no cover
    import psycopg2

    # 运行期按环境变量连接 Postgres，默认值对应计划里的本地靶场配置。
    conn = psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=os.getenv("POSTGRES_PORT", "5432"),
        user=os.getenv("POSTGRES_USER", "opspilot"),
        password=os.getenv("POSTGRES_PASSWORD", "opspilot"),
        dbname=os.getenv("POSTGRES_DB", "opspilot"),
    )

    # schema 和 seed 在同一个事务中执行，避免半初始化数据留在库里。
    with conn, conn.cursor() as cur:
        schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
        with open(schema_path, encoding="utf-8") as schema_file:
            cur.execute(schema_file.read())

        # 租户先入库，客户表的外键才能稳定通过。
        for tenant in TENANTS:
            cur.execute("INSERT INTO tenants(tenant) VALUES (%s) ON CONFLICT DO NOTHING", (tenant,))

        # 客户数据使用固定 id，重复执行 seed 不会产生重复记录。
        for row in make_rows():
            cur.execute(
                "INSERT INTO customers(id,tenant,name,email) VALUES (%s,%s,%s,%s) "
                "ON CONFLICT DO NOTHING",
                (row["id"], row["tenant"], row["name"], row["email"]),
            )
    conn.close()


if __name__ == "__main__":
    main()
