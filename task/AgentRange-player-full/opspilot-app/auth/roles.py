from auth.jwt_auth import Identity

ROLES = {"rd-dev", "ops-engineer", "sec-analyst", "support-agent", "ops-admin"}


def in_scope(identity: Identity, resource_tenant: str) -> bool:
    # ops-admin 是靶场里的跨租户运维身份，允许访问全部租户。
    if identity.role == "ops-admin":
        return True

    # 其他角色按 JWT 中的 tenant scope 限制，形成正常业务基线。
    return identity.scope.get("tenant") == resource_tenant
