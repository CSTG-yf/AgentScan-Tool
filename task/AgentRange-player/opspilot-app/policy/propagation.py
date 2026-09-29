import json

from auth.jwt_auth import Identity


def propagate(identity: Identity, mode: str, service_token: str) -> dict:
    # on-behalf-of 模式把发起用户和 scope 交给下游，支持下游继续做越权拦截。
    if mode == "on-behalf-of":
        return {
            "X-Acting-User": identity.sub,
            "X-Acting-Role": identity.role,
            "X-Acting-Scope": json.dumps(identity.scope),
        }

    # service-account 模式隐藏用户 scope，是 confused deputy 攻击链的脆弱基线。
    return {"Authorization": f"Bearer {service_token}"}


def trace_headers(trace_id: str) -> dict:
    # Trace ID 只服务于链路串联，不携带身份和权限语义。
    return {"X-Trace-Id": trace_id}
