"""check-your-pulse log analyzer. Will scan your pulse secure logs for signs of CVE-2019-11510 compromise."""

# Standard Python Libraries
import argparse
import csv
import datetime
import glob
from hashlib import sha3_256 as sha
import json
import os
import re

# cisagov Libraries
from src.display import Animation, Color, ascii_art
from src.indicators import maliciousIPs, maliciousstrings, malicioususeragents

unauthenticated_logging = 0


class ChYP_Exception(Exception):
    """Exception class for check-your-pulse."""

    pass


class Connection(object):
    """Handles our individual connections in log files."""

    def __init__(self, time, ip, user, summary):
        """
        Instantiate a Connection() object.

        :param time:
        :param ip:
        :param user:
        :param summary:
        """
        self.time: str = time
        self.ip: str = ip
        self.user: str = user
        self.summary: str = summary.strip()
        self.begin_time: datetime.datetime or None = None
        self.end_time: datetime.datetime or None = None
        self.of_interest: bool = False
        self.reason: set = set()
        self.events: list = []
        self.type: str = ""

    @property
    def _UID(self):
        try:
            return sha((self.user + self.ip).encode("utf8")).hexdigest()

        except KeyError:
            return False

    @property
    def _connection_time(self):
        try:
            return self.end_time - self.begin_time

        except TypeError:
            return ""

    @property
    def _date_time(self):
        try:
            if "/" in self.time:
                return datetime.datetime.strptime(self.time, "%Y/%m/%d %H:%M:%S")

            elif "-" in self.time:
                return datetime.datetime.strptime(self.time, "%Y-%m-%d %H:%M:%S")

        except ValueError:
            return False

    def _json(self):
        return {
            "UID": str(self._UID),
            "user": str(self.user),
            "ip": str(self.ip),
            "connection_time": str(self._connection_time),
            "events": [(x.strftime("%d-%b-%Y %H:%M:%S"), y) for x, y in self.events],
            "reason": [str(x) for x in self.reason],
        }

    def __repr__(self):
        """Return a __repr__ representation of Connection()."""
        return (
            f"Connection('UID':'{self._UID}', 'type': '{self.type}', 'connection_time':'{self._connection_time}', "
            f"'ip':'{self.ip}', 'user':'{self.user}', 'events':'{self.events}') "
        )

    def __str__(self):
        """Return a __str__ representation of Connection()."""
        return (
            f"Connection('UID':'{self._UID}', 'type': '{self.type}', 'connection_time':'{self._connection_time}', "
            f"'ip':'{self.ip}', 'user':'{self.user}', 'events':'{self.events}') "
        )


def format_line(line: str):
    """
    Split and format the lines of the .access and .events log files.

    :param line: Line to format.
    :return: None
    """
    s = line.split(" - ")
    try:
        ip, user, date_time, summary = (
            s[1].strip("[]"),
            s[2],
            s[3],
            " - ".join(s[4:]),
        )

        if not date_time:
            date_time, ip, user, summary = (
                s[0],
                s[2].split(" ")[0].strip("[]"),
                " ".join(s[2].split(" ")[1:]),
                " - ".join(s[3:]),
            )

        connection = Connection(date_time, ip, user, summary)

        return connection

    except IndexError:
        pass


def process_lines(line: str, type: str) -> None:
    """
    Process the lines, create objects and look for specific items we want. (like begin time, end time, and indicators).

    :param line: Line to process.
    :param type: File type (.access or .event)
    :return: None
    """
    global unauthenticated_logging
    login = ["ogin succeeded"]
    logout = ['" closed .', "ogout from "]

    try:
        formatted_line = format_line(line)
        formatted_line.type = type

        if formatted_line._UID in connections:
            connections[formatted_line._UID].events.append(
                (formatted_line._date_time, formatted_line.summary)
            )
        else:
            connections[formatted_line._UID] = formatted_line
            connections[formatted_line._UID].events.append(
                (formatted_line._date_time, formatted_line.summary)
            )

        if formatted_line.ip in maliciousIPs:
            connections[formatted_line._UID].of_interest = True
            connections[formatted_line._UID].reason.add(
                "Found malicious IP: %s" % formatted_line.ip
            )

        for x, y in zip(maliciousstrings, malicioususeragents):
            if re.search(x, formatted_line.summary):
                connections[formatted_line._UID].of_interest = True
                connections[formatted_line._UID].reason.add(
                    "Known malicious string: %s" % x
                )
                maliciousIPs.append(formatted_line.ip)

            if re.search(y, formatted_line.summary):
                connections[formatted_line._UID].of_interest = True
                connections[formatted_line._UID].reason.add(
                    "Known malicious useragent: %s" % y
                )
                maliciousIPs.append(formatted_line.ip)

        if any(item in formatted_line.summary for item in login):
            connections[formatted_line._UID].begin_time = formatted_line._date_time

        elif any(item in formatted_line.summary for item in logout):
            connections[formatted_line._UID].end_time = formatted_line._date_time
            hash = sha(
                (
                    formatted_line.user
                    + formatted_line.ip
                    + str(formatted_line.end_time)
                ).encode("utf8")
            ).hexdigest()
            connections[hash] = connections[formatted_line._UID]
            del connections[formatted_line._UID]

        if "not authenticated" in formatted_line.summary:
            unauthenticated_logging += 1

    except AttributeError or TypeError:
        pass


# Source: https://www.tutorialspoint.com/How-can-I-remove-the-ANSI-escape-sequences-from-a-string-in-python
def escape_ansi(line: str) -> str:
    """
    Remove ANSI escape characters we add with the Color class from the display.py file.

    :param line: Line to process.
    :return: Stripped line.
    """
    ansi_escape = re.compile(r"(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", line)


def _argument_parser():
    args = argparse.ArgumentParser()
    args.add_argument("-r", "--raw", help="Dumps the output to STDOUT.")
    args.add_argument(
        "-c",
        "--csv",
        help="Writes output to a .csv file. Needs to be provided the name to save as.",
    )
    args.add_argument(
        "-j",
        "--json",
        help="Writes output to a .json file. Needs to be provided the name to save as.",
    )
    args.add_argument(
        "-p",
        "--path",
        help="Path to the folder containing .access and .events.",
        default="./",
    )
    args.add_argument(
        "-n",
        "--numevents",
        help="Number of events to print in the quick summary (default 10)",
        default=10,
        type=int,
    )
    return args.parse_args()


def main(animation: Animation) -> dict:
    """
    Fire off the functions to process our .event and .access files.

    :param animation: Animation() object used for our spinner.
    :return: connections dictionary.
    """
    global connections
    connections = dict()

    animation.start(f"Parsing {file_event}")
    for line in log_contents_event:
        process_lines(line, "event")
    animation.done()

    maliciousIPs.extend([x.ip for x in connections.values() if x.of_interest])

    animation.start(f"Parsing {file_access}")
    for line in log_contents_access:
        process_lines(line, "access")
    animation.done()

    return connections


def _summary(
    connections: list,
    animation: Animation,
    windows: bool,
    numevents: int,
    unauthenticated_logging: int,
) -> None:
    summary_output = ""
    summary_output += Color._blue(ascii_art)

    if not connections:
        summary_output += Color._green(
            f"""\ncheck-your-pulse did not find any activity based on the IOCs. This does not mean there was no """
            f"""compromise."""
        )

    else:
        first = connections[0]
        bad = connections[0:numevents]
        last = connections[-1]

        if not unauthenticated_logging:
            summary_output += Color._red(
                "CHECK-YOUR-PULSE DID NOT FIND ANY UNAUTHENTICATED REQUESTS. PLEASE ENSURE YOU HAVE "
                "UNAUTHENTICATED LOGGING TURNED ON.\n"
            )

        summary_output += (
            f"""\nBased on the IOCs in conf.py, The first exploitation attempt occurred by """
            f"""{Color._green(first.ip)} on {Color._green(first._date_time)}. The indicator alerted on was: \n\n"""
            f"""{Color._red(str(first.reason).strip("{}'"))}\n\nIn total there were {len(connections)} attempts and """
            f"""the final one occurred on {str(last._date_time)}\n\nMore observed events are available in the """
            f"""outfile. \n\nBased on the indicator and other IOCs in conf.py, you should investigate whether the """
            f"""following connections were legitimate. If they were not, you should investigate what those users did """
            f"""and look for lateral movement and persistence. Please enact your incident response plan if necessary."""
            f"""\n\nThere were {len(set([conn.user.split('(')[0] for conn in connections if conn.type == 'access']))}"""
            f"""{len(set([conn.user.split('(')[0] for conn in connections if conn.type == 'access']))} unique users """
            f"""that were suspicious and the first connection occurred {first._date_time} and the final on """
            f"""{last._date_time}\n\nMore information is available in the outfile. The first ten suspicious """
            f"""connections are: \n"""
        )

        conn_list = [
            (
                conn._date_time,
                conn._UID,
                f"Log: {conn.type}\tInfo: {Color._green(conn.user)} was connected from {Color._green(conn.begin_time)}"
                f"to {Color._green(conn.end_time)} from {Color._green(conn.ip)}",
            )
            for conn in bad
            if conn.type == "access" and conn.end_time and conn.begin_time
        ]

        if len(conn_list) < numevents:
            conn_list.extend(
                [
                    (
                        conn._date_time,
                        conn._UID,
                        f"Log: {conn.type}\tInfo: {Color._green(conn.user)} was connected around "
                        f"{Color._green(conn._date_time)} from {Color._green(conn.ip)}",
                    )
                    for conn in bad
                    if conn._UID not in [x[0] for x in conn_list]
                ]
            )

        conn_list = sorted(
            conn_list, key=lambda x: x[0] if x else datetime.datetime.now()
        )

        for item in conn_list[0:numevents]:
            summary_output += "\n" + item[2]

    with open("check-your-pulse.summary", "w+") as writeout:
        writeout.write(escape_ansi(summary_output))

    if windows:
        print(escape_ansi(summary_output))

    else:
        print(summary_output)


if __name__ == "__main__":
    args = _argument_parser()
    animation = Animation()

    if args.path:
        file_event = glob.glob(os.path.join(args.path, "") + "*.events")
        file_access = glob.glob(os.path.join(args.path, "") + "*.access")

        try:
            log_contents_event = open(
                file_event[0], "r", encoding="utf-8", errors="ignore"
            ).readlines()
        except IndexError:
            raise ChYP_Exception(
                f"Could not find .event file at {args.path}, please specify the correct directory "
                f"with -p or copy your files to the local directory"
            )

        try:
            log_contents_access = open(
                file_access[0], "r", encoding="utf-8", errors="ignore"
            ).readlines()
        except IndexError:
            raise ChYP_Exception(
                f"Could not find .access file at {args.path}, please specify the correct directory "
                f"with -p or copy your files to the local directory"
            )

    connections = main(animation)
    _summary(
        [connection for connection in connections.values() if connection.of_interest],
        animation,
        os.name == "nt",
        args.numevents,
        unauthenticated_logging,
    )

    if args.raw:
        raw_output = ""
        for key, value in connections.items():
            if value.of_interest:
                raw_output += (
                    "\n-----\nIP: %s   User: %s   Connection Time: %s   Reason: %s\n"
                    % (
                        value.ip,
                        value.user,
                        value._connection_time,
                        str(value.reason).strip("{}"),
                    )
                )
                for time, event in value.events:
                    raw_output += f"{time} {event}\n"
        with open(args.raw, "w+") as writeout:
            writeout.write(raw_output)

    elif args.json:
        with open(args.json, "w+") as writeout:
            for key, value in connections.items():
                if value.of_interest:
                    writeout.write(json.dumps(value._json(), indent=4) + ",\n\n")

    elif args.csv:
        with open(args.csv, "w+") as writeout:
            fieldnames = [
                "UID",
                "user",
                "ip",
                "connection_time",
                "time",
                "event",
                "reason",
            ]
            writer = csv.DictWriter(writeout, fieldnames=fieldnames)
            writer.writeheader()
            for key, value in connections.items():
                if value.of_interest:
                    for line in value.events:
                        writer.writerow(
                            {
                                "UID": value._UID,
                                "user": value.user,
                                "ip": value.ip,
                                "connection_time": value._connection_time,
                                "time": line[0].strftime("%d-%b-%Y %H:%M:%S"),
                                "event": str(line[1]),
                                "reason": value.reason,
                            }
                        )

    else:
        print(
            Color._red(
                "\nNo output file was specified. If you would like an outfile, rerun and specify --raw, --json, or "
                "--csv"
            )
        )
