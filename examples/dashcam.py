"""Read-only DVR protocol helpers. No sockets, HTTP calls or device access.

Reference firmware: JC_703T25_V02.26.02.02.60. See the DVR document and
its evidence index; normalization is not proof of real-device playback.
"""
from dataclasses import dataclass
from datetime import date as Date
import json
import re
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

BASE_URL = "http://192.168.3.1:7686/"
CAMERAS = ("front", "rear")
KNOWN_HOSTS = ("192.168.3.1", "192.168.2.1")


def _camera(camera: str) -> None:
    if camera not in CAMERAS:
        raise ValueError("camera must be front or rear")


def _date(value: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
        raise ValueError("date must be YYYY-MM-DD")
    Date.fromisoformat(value)


def _body(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def dates_request(camera: str = "front") -> bytes:
    _camera(camera)
    return _body({"METHOD": "VIDEO.DATE", "previewType": camera})


def recordings_request(camera: str, date: str, *, index: int = 0,
                       num: int = 50, sort: str = "des") -> bytes:
    _camera(camera)
    _date(date)
    if type(index) is not int or index < 0:
        raise ValueError("index must be a nonnegative page number")
    # A client policy, not a discovered firmware maximum.
    if type(num) is not int or not 1 <= num <= 100:
        raise ValueError("client page size must be 1..100")
    if (index + 1) * num - 1 > 2_147_483_647:
        raise ValueError("pagination arithmetic must fit a firmware signed 32-bit integer")
    if sort not in ("asc", "des"):
        raise ValueError("firmware sorting only supports asc and des")
    return _body({"METHOD": "VIDEO.INFO.LIST", "previewType": camera,
                  "date": date, "index": index, "num": num,
                  "sort": sort, "time": "NULL"})


def normalize_media_url(value: str | None) -> str | None:
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw or any(ord(c) < 32 or ord(c) == 127 for c in raw):
        return None
    if any(raw.startswith(f"{host}:7686/") for host in KNOWN_HOSTS):
        raw = "http://" + raw
    elif ":" in raw.split("/", 1)[0] and not raw.lower().startswith("http://"):
        return None
    try:
        url = urlsplit(urljoin(BASE_URL, raw))
        if (url.scheme.lower() != "http" or url.hostname not in KNOWN_HOSTS
                or url.port != 7686 or url.username is not None or url.password is not None):
            return None
    except ValueError:
        return None
    # Encode path characters for HTTP without double-encoding existing % escapes.
    path = quote(url.path, safe="/%:@!$&'()*+,;=-._~")
    return urlunsplit(("http", "192.168.3.1:7686", path, url.query, ""))


def _response(body: bytes, method: str) -> dict:
    value = json.loads(body)
    if not isinstance(value, dict) or value.get("METHOD") != method:
        raise ValueError("unexpected DVR response METHOD")
    code = value.get("code")
    if type(code) is not int or code != 0:
        raise ValueError("DVR command did not report code=0")
    return value


def parse_dates(body: bytes) -> list[str]:
    values = _response(body, "VIDEO.DATE").get("dateList")
    if not isinstance(values, list):
        raise ValueError("dateList is missing or is not an array")
    dates = set()
    for value in values:
        try:
            _date(value)
        except (TypeError, ValueError):
            continue
        dates.add(value)
    return sorted(dates, reverse=True)


@dataclass(frozen=True)
class Recording:
    title: str
    name: str
    record_time: str
    play_url: str | None
    thumbnail_url: str | None
    raw: dict


def parse_recordings(body: bytes) -> list[Recording]:
    values = _response(body, "VIDEO.INFO.LIST").get("videoBeanList")
    if not isinstance(values, list) or any(not isinstance(v, dict) for v in values):
        raise ValueError("videoBeanList must be an array of objects")
    records = []
    for index, value in enumerate(values):
        name = value.get("name") if isinstance(value.get("name"), str) else ""
        title = value.get("title") if isinstance(value.get("title"), str) else ""
        time = value.get("recordTime") if isinstance(value.get("recordTime"), str) else ""
        records.append(Recording(title or name or f"Recording {index + 1}", name, time,
                                 normalize_media_url(value.get("playUrl")),
                                 normalize_media_url(value.get("thumbUrl")), dict(value)))
    return records
