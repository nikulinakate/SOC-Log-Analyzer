import json

from app.parsers.windows_json import WindowsJsonParser


def test_windows_parser_supports_common_export_shape():
    payload = [
        {
            "EventID": 4688,
            "TimeCreated": "2026-07-11T10:00:00Z",
            "Computer": "WIN-01",
            "EventData": {
                "SubjectUserName": "alice",
                "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -EncodedCommand SQBFAFgA",
            },
        }
    ]

    events = WindowsJsonParser().parse_text(json.dumps(payload))

    assert len(events) == 1
    assert events[0].event_type == "process_started"
    assert events[0].event_id == 4688
    assert events[0].hostname == "WIN-01"


def test_windows_parser_accepts_newline_delimited_json():
    content = "\n".join(
        [
            json.dumps({"EventID": 4625, "EventData": {"TargetUserName": "admin"}}),
            json.dumps({"EventID": 4720, "EventData": {"TargetUserName": "operator"}}),
        ]
    )

    events = WindowsJsonParser().parse_text(content)

    assert [event.event_type for event in events] == ["auth_failure", "user_created"]
