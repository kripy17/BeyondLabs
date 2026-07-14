import re
import xml.etree.ElementTree as ET
from typing import Any

SYSMON_EVENT_NAMES = {
    1: "Process creation",
    2: "Process changed a file creation time",
    3: "Network connection",
    4: "Sysmon service state changed",
    5: "Process terminated",
    6: "Driver loaded",
    7: "Image loaded",
    8: "CreateRemoteThread detected",
    9: "RawAccessRead detected",
    10: "Process accessed",
    11: "FileCreate",
    12: "RegistryEvent (Object create/delete)",
    13: "RegistryEvent (Value set)",
    14: "RegistryEvent (Key/Value rename)",
    15: "FileCreateStreamHash",
    16: "Sysmon config state changed",
    17: "PipeEvent (Pipe created)",
    18: "PipeEvent (Pipe connected)",
    19: "WmiEventFilter",
    20: "WmiEventConsumer",
    21: "WmiEventConsumerToFilter",
    22: "DNSEvent",
    23: "FileDelete",
    24: "ClipboardChange",
    25: "ProcessTampering",
    26: "FileDeleteDetected",
    27: "FileBlockExecutable",
    28: "FileBlockShredding",
    29: "FileExecutableDetected",
    255: "Error",
}

SYSMON_EVENT_SEVERITY = {
    1: "medium",
    3: "medium",
    7: "low",
    8: "high",
    9: "high",
    10: "medium",
    11: "low",
    12: "low",
    13: "low",
    14: "low",
    15: "low",
    17: "low",
    18: "low",
    19: "medium",
    20: "medium",
    21: "medium",
    22: "medium",
    23: "low",
    24: "low",
    25: "high",
    26: "medium",
    27: "high",
    28: "high",
    29: "medium",
}


def parse_evtx_xml(text: str) -> list[dict[str, Any]]:
    events = []
    try:
        root = ET.fromstring(text)
        ns = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}
        event_elems = root.findall(".//evt:Event", ns)
        if not event_elems:
            if root.tag.endswith("}Event") or root.tag == "Event":
                event_elems = [root]
        for event_elem in event_elems:
            events.append(_parse_event_elem(event_elem))
    except ET.ParseError:
        events = _parse_text_lines(text)
    return events


def _parse_event_elem(elem: ET.Element) -> dict[str, Any]:
    def _q(tag: str) -> str:
        if elem.tag.startswith("{"):
            ns_uri = elem.tag.split("}")[0].lstrip("{")
            return f"{{{ns_uri}}}{tag}"
        return tag

    evt = {}
    system = elem.find(_q("System"))
    if system is not None:
        evt["provider"] = _get_attr_simple(system, _q("Provider"), "Name")
        evt["event_id"] = int(_get_text_simple(system, _q("EventID")) or 0)
        evt["version"] = _get_text_simple(system, _q("Version"))
        evt["level"] = int(_get_text_simple(system, _q("Level")) or 0)
        evt["task"] = int(_get_text_simple(system, _q("Task")) or 0)
        evt["opcode"] = int(_get_text_simple(system, _q("Opcode")) or 0)
        evt["keywords"] = _get_text_simple(system, _q("Keywords"))
        evt["time_created"] = _get_attr_simple(system, _q("TimeCreated"), "SystemTime")
        evt["event_record_id"] = _get_text_simple(system, _q("EventRecordID"))
        evt["computer"] = _get_text_simple(system, _q("Computer"))

    event_data = elem.find(_q("EventData"))
    if event_data is not None:
        data = {}
        for d in event_data.findall(_q("Data")):
            name = d.get("Name", "")
            if name:
                data[name] = d.text or ""
        evt["event_data"] = data

    if evt.get("event_id") in SYSMON_EVENT_NAMES:
        evt["sysmon_name"] = SYSMON_EVENT_NAMES[evt["event_id"]]
        evt["severity"] = SYSMON_EVENT_SEVERITY.get(evt["event_id"], "info")

    return evt


def _get_text_simple(elem: ET.Element | None, tag: str) -> str | None:
    if elem is None:
        return None
    child = elem.find(tag)
    if child is None:
        return None
    return child.text


def _get_attr_simple(elem: ET.Element | None, tag: str, attr: str) -> str | None:
    if elem is None:
        return None
    child = elem.find(tag)
    if child is None:
        return None
    return child.get(attr)


def _parse_text_lines(text: str) -> list[dict[str, Any]]:
    events = []
    current = {}
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"Event\s*(ID|Type):\s*(\d+)", line, re.IGNORECASE)
        if m:
            if current:
                events.append(current)
            current = {"source": "text_parse", "event_id": int(m.group(2))}
            continue
        m = re.match(r"(\w+(?:\s+\w+)*):\s*(.+)", line)
        if m and current:
            key = m.group(1).strip().lower().replace(" ", "_")
            current[key] = m.group(2).strip()
    if current:
        events.append(current)
    for evt in events:
        eid = evt.get("event_id", 0)
        if eid in SYSMON_EVENT_NAMES:
            evt["sysmon_name"] = SYSMON_EVENT_NAMES[eid]
            evt["severity"] = SYSMON_EVENT_SEVERITY.get(eid, "info")
    return events
