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


def trace_headers(trace_id: str, identity: Identity | None = None) -> dict:
    # Trace ID 用于链路串联；当应用调用内部工具时，同时携带已经由
    # JWT 校验得到的最小授权上下文，供下游通用策略做 scope 检查。
    headers = {"X-Trace-Id": trace_id}
    if identity is not None:
        headers.update(
            {
                "X-Acting-User": identity.sub,
                "X-Acting-Role": identity.role,
                "X-Acting-Scope": json.dumps(identity.scope, ensure_ascii=False, separators=(",", ":")),
            }
        )
    return headers
