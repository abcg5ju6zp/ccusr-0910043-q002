"""转发头解析：RFC 7239 Forwarded 与 X-Forwarded-*。

与 ``sanic.headers`` 中服务于旧版 ``FORWARDED_SECRET`` 机制的解析不同，
这里保留链上的*全部*元素，并为无法解析的元素保留错误标注，
供裁决器给出可解释结论。"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import unquote


@dataclass
class ForwardedElement:
    """Forwarded 头中的一个转发元素（一个代理跳点）。"""

    pairs: dict[str, str]
    raw: str
    error: str | None = None

    def get(self, key: str) -> str | None:
        return self.pairs.get(key)


def split_header_list(values: list[str]) -> list[str]:
    """合并多行头部并按顶层逗号切分（忽略引号内逗号）。"""
    items: list[str] = []
    for value in values:
        buf: list[str] = []
        quoted = False
        escaped = False
        for ch in value:
            if escaped:
                buf.append(ch)
                escaped = False
                continue
            if ch == "\\":
                buf.append(ch)
                escaped = quoted
                continue
            if ch == '"':
                quoted = not quoted
                buf.append(ch)
                continue
            if ch == "," and not quoted:
                token = "".join(buf).strip()
                if token:
                    items.append(token)
                buf = []
                continue
            buf.append(ch)
        token = "".join(buf).strip()
        if token:
            items.append(token)
    return items


_TOKEN_CHARS = set(
    "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
)


def parse_forwarded_elements(values: list[str]) -> list[ForwardedElement]:
    """解析所有 Forwarded 头，逐元素返回，畸形元素带 ``error``。"""
    result: list[ForwardedElement] = []
    for chunk in split_header_list(values):
        pairs, error = _parse_forwarded_element(chunk)
        result.append(ForwardedElement(pairs=pairs, raw=chunk, error=error))
    return result


def _parse_forwarded_element(chunk: str) -> tuple[dict[str, str], str | None]:
    pairs: dict[str, str] = {}
    saw_pair = False
    i = 0
    n = len(chunk)
    while i < n:
        while i < n and chunk[i] in " \t;":
            i += 1
        if i >= n:
            break
        # key
        start = i
        while i < n and chunk[i] in _TOKEN_CHARS:
            i += 1
        key = chunk[start:i].lower()
        if not key or i >= n or chunk[i] != "=":
            return pairs, f"malformed forwarded element: {chunk!r}"
        i += 1  # skip '='
        # value: quoted-string or token
        if i < n and chunk[i] == '"':
            i += 1
            val_chars: list[str] = []
            closed = False
            while i < n:
                ch = chunk[i]
                if ch == "\\":
                    if i + 1 < n:
                        val_chars.append(chunk[i + 1])
                        i += 2
                        continue
                    i += 1
                    continue
                if ch == '"':
                    closed = True
                    i += 1
                    break
                val_chars.append(ch)
                i += 1
            if not closed:
                return pairs, f"unterminated quoted value: {chunk!r}"
            value = "".join(val_chars)
        else:
            start = i
            while i < n and chunk[i] in _TOKEN_CHARS:
                i += 1
            value = chunk[start:i]
            if not value:
                return pairs, f"missing forwarded value: {chunk!r}"
        pairs[key] = value
        saw_pair = True
        # 期待 ';' 或结束
        while i < n and chunk[i] in " \t":
            i += 1
        if i < n and chunk[i] != ";":
            return pairs, f"unexpected character at {i}: {chunk!r}"
    if not saw_pair:
        return pairs, f"malformed forwarded element: {chunk!r}"
    return pairs, None


def parse_xforwarded_for(values: list[str]) -> list[str]:
    """解析 X-Forwarded-For 的全部条目（客户端 -> 应用方向）。"""
    return [item.strip() for item in split_header_list(values)]


def pick_xforwarded_value(headers, name: str, *, leftmost: bool = False):
    """取 X-Forwarded-* 单值头。

    多行头合并后按跳点排列；``leftmost=True`` 取最靠近原始客户端的
    一跳所写值（如客户端可见协议/主机），否则取最近一跳。
    """
    values = headers.getall(name, None)
    if not values:
        return None
    items = split_header_list(list(values))
    if not items:
        return None
    return items[0] if leftmost else items[-1]


def normalize_node(value: str | None) -> str | None:
    """RFC 7239 节点名归一化：去括号 IPv6、unknown、_obfuscated 原样。"""
    if value is None:
        return None
    value = value.strip()
    if value.lower() == "unknown":
        return "unknown"
    if value.startswith("_"):
        return value
    if value.startswith("["):
        end = value.find("]")
        if end != -1:
            return value[1:end].lower()
        return None
    # IPv4 带端口
    if value.count(".") == 3 and ":" in value:
        value = value.rpartition(":")[0]
    return value.lower() or None


def normalize_proto(value: str | None) -> str | None:
    return value.strip().lower() if value else None


def normalize_path(value: str | None) -> str | None:
    return unquote(value) if value else None
