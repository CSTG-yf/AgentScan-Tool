import time
from dataclasses import dataclass, field

import jwt

ALGORITHM = "HS256"


@dataclass(frozen=True)
class Identity:
    sub: str
    role: str
    team: str
    scope: dict = field(default_factory=dict)


def issue_token(identity: Identity, secret: str, ttl: int = 3600, now: int | None = None) -> str:
    # iat/exp 由调用方可注入时间，方便单测稳定覆盖过期逻辑。
    issued_at = int(now if now is not None else time.time())
    payload = {
        "sub": identity.sub,
        "role": identity.role,
        "team": identity.team,
        "scope": identity.scope,
        "iat": issued_at,
        "exp": issued_at + ttl,
    }

    # 计划里的身份基线使用 HS256，弱密钥风险由配置层保留给靶场场景。
    return jwt.encode(payload, secret, algorithm=ALGORITHM)


def verify_token(token: str, secret: str, now: int | None = None) -> Identity:
    # 运行路径使用 PyJWT 的真实时钟校验 exp，避免过期 token 被 API 接受。
    if now is None:
        payload = jwt.decode(token, secret, algorithms=[ALGORITHM])
    else:
        # 单测传入 now 时关闭真实时钟，按可控时间覆盖过期分支。
        payload = jwt.decode(token, secret, algorithms=[ALGORITHM], options={"verify_exp": False})
        if payload["exp"] < now:
            raise jwt.ExpiredSignatureError("token expired")

    # 只把业务需要的身份字段还原为 Identity，避免 API 层直接依赖 JWT payload。
    return Identity(
        sub=payload["sub"],
        role=payload["role"],
        team=payload["team"],
        scope=payload.get("scope", {}),
    )
