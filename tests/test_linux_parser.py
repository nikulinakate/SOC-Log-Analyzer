from app.parsers.linux_auth import LinuxAuthParser


def test_linux_parser_normalizes_security_events():
    content = "\n".join(
        [
            "Jul 11 10:00:00 web-01 sshd[100]: Failed password for invalid user admin "
            "from 203.0.113.10 port 51200 ssh2",
            "Jul 11 10:01:00 web-01 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; "
            "USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
            "Jul 11 10:02:00 web-01 useradd[200]: new user: name=backup, UID=1002, "
            "GID=1002, home=/home/backup",
        ]
    )
    events = LinuxAuthParser().parse_text(content)

    assert [event.event_type for event in events] == [
        "auth_failure",
        "sudo_command",
        "user_created",
    ]
    assert events[0].src_ip == "203.0.113.10"
    assert events[1].command_line == "/usr/bin/cat /etc/shadow"
    assert events[2].username == "backup"
