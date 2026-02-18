/* session_collector.py
 *
 * Copyright (c) 2013-2025 Inango Systems LTD.
 *
 * Author: Inango Systems LTD. <support@inango-systems.com>
 * Creation Date: Jul 2025
 *
 * The author may be reached at support@inango-systems.com
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Subject to the terms and conditions of this license, each copyright holder
 * and contributor hereby grants to those receiving rights under this license
 * a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable
 * (except for failure to satisfy the conditions of this license) patent license
 * to make, have made, use, offer to sell, sell, import, and otherwise transfer
 * this software, where such license applies only to those patent claims, already
 * acquired or hereafter acquired, licensable by such copyright holder or contributor
 * that are necessarily infringed by:
 *
 * (a) their Contribution(s) (the licensed copyrights of copyright holders and
 * non-copyrightable additions of contributors, in source or binary form) alone;
 * or
 *
 * (b) combination of their Contribution(s) with the work of authorship to which
 * such Contribution(s) was added by such copyright holder or contributor, if,
 * at the time the Contribution is added, such addition causes such combination
 * to be necessarily infringed. The patent license shall not apply to any other
 * combinations which include the Contribution.
 *
 * Except as expressly stated above, no rights or licenses from any copyright
 * holder or contributor is granted under this license, whether expressly, by
 * implication, estoppel or otherwise.
 *
 * DISCLAIMER
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * NOTE
 *
 * This is part of a traffic capture software tool that was developed by Inango Systems Ltd.
 *
 * Please contact us on support@inango-systems.com if you would like to hear more about this tool.
 */
 
import os
import time
import psutil
import signal
import traceback
import tarfile
import re
from sys import exit
from scapy.all import (
    sniff,
    wrpcap,
    IP,
    TCP,
    UDP,
    resolve_iface,
    DefaultSession,
    conf,
    IPv6,
)
from functions import (
    get_local_interfaces,
    is_local_traffic,
    is_local_ip,
    send_file_over_email,
    send_file_over_http,
)


class SessionCollectorConfig:
    """A configuration object for SessionCollector."""

    min_packets_per_session: int
    """Sessions with less packets than this value will be discarded."""

    max_packets_per_session: int
    """Sessions will not store more packets than this value."""

    session_timeout_sec: int
    """
    The number of seconds a session needs to have no new packets
    for it to be considered ended.
    """

    cleanup_timer: int
    """
    The period in seconds for the cleanup routine to run.
    The cleanup routine to checks for ended sessions and saves or discards them.
    """

    process_check_timer: int
    """
    The period in seconds for regular checks of the running processes and matching
    of sessions to their processes.
    """

    process_by_pid_check_timer: int
    """
    The period in seconds for regular checks if any new connections have been made
    by already tracked processes.
    """

    process_list: list
    """
    The list of process names for which sessions need to be saved. If empty,
    all sessions will be saved unless filtered out by min_packets_per_session attribute.
    """

    web_app_list: list
    """
    The list of web application names for which sessions need to be saved.
    Should match a part of the URL used in the web app's browser shortcut.
    """

    browser_list: list
    """
    The list of web browser processes that are supported and might be used.
    For example, "firefox,chrome,chromium,edge,zen".
    """

    pcap_dir: str
    """The directory in which pcap files will be stored locally."""

    proto: str
    """
    The protocol for which sessions will be collected.
    Currently only udp and tcp are supported.
    """

    interface_list: list
    """The system network interfaces on which packets will be collected."""

    debug: bool
    """If true, debug logs will be printed."""

    ignore_local_traffic: bool
    """If true, traffic local to the current machine will be ignored."""

    send_timer: int
    """The interval between emails or PUT requests with new pcaps in seconds."""

    send_method: str
    """The method used for sending pcap files: http or email."""

    server_url: str
    """URL of the server to send pcap files to."""

    server_auth: str
    """Authentication token used for the HTTP server."""

    sender_email: str
    """Email address to send pcaps from."""

    receiver_email_list: list
    """Email address list to send pcaps to."""

    sender_email_password: str
    """Password for sender email."""

    smtp_server: str
    """SMTP server to use with sender email."""

    smtp_port: str
    """SMTP port to use with sender email."""

    delete_pcaps_after_send: bool
    """If true, pcaps will be deleted from the current machine after sending them to receiver email."""

    max_archive_size: int
    """Maximum size of archives to send over email, in bytes."""

    socket_buffer_size: int
    """Size of the L2 capturing socket's buffer, in bytes"""

    def __init__(
        self,
        min_packets_per_session: int = 4,
        max_packets_per_session: int = 200,
        session_timeout_sec: int = 60,
        cleanup_timer: int = 1,
        process_check_timer: int = 5,
        process_by_pid_check_timer: int = 1,
        process_list: list = [],
        web_app_list: list = [],
        browser_list: list = [],
        pcap_dir: str = "pcaps",
        proto: str = "udp",
        interface_list: list = [],
        debug: bool = False,
        ignore_local_traffic: bool = True,
        send_timer: int = -1,
        send_method: str = "http",
        server_url: str = "",
        server_auth: str = "",
        sender_email: str = "",
        receiver_email_list: list = [],
        sender_email_password: str = "",
        smtp_server: str = "",
        smtp_port: int = -1,
        delete_pcaps_after_send: bool = True,
        max_archive_size: int = 30000000,
        socket_buffer_size: int = 2**26,
    ):
        self.min_packets_per_session = min_packets_per_session
        self.max_packets_per_session = max_packets_per_session
        self.session_timeout_sec = session_timeout_sec
        self.cleanup_timer = cleanup_timer
        self.process_check_timer = process_check_timer
        self.process_by_pid_check_timer = process_by_pid_check_timer
        process_list.sort(key=len, reverse=True)
        self.process_list = [p.lower() for p in process_list]
        self.socket_buffer_size = socket_buffer_size

        def construct_regex(process):
            # examples of paths that will match if process_list="ms-teams,telegram,discord,Microsoft Teams WebView Helper (GPU)":
            # /Applications/Microsoft Teams.app/Contents/Helpers/Microsoft Teams WebView.app/Contents/Frameworks/Microsoft Edge Framework.framework/Versions/133.0.3065.82/Helpers/Microsoft Teams WebView Helper (GPU).app/Contents/MacOS/Microsoft Teams WebView Helper (GPU)
            # /Applications/Telegram.app/Contents/MacOS/Telegram
            # /snap/discord/236/usr/share/discord/Discord
            # C:\Program Files\WindowsApps\MSTeams_25060.205.3499.6849_x64__8wekyb3d8bbweє\ms-teams.exe
            # C:\Users\Admin\AppData\Roaming\Telegram Desktop\Telegram.exe
            # mixing / and \ is currently allowed, as well as adding more slashes than 1 consecutively.
            return f"^[\"']?([\\\\\\/]+)?([\\w.:\\- ()]+[\\\\\\/]+)*{re.escape(process)}(.exe)?[\"' ]?$"

        self.process_regex_list = [
            re.compile(construct_regex(process), re.UNICODE)
            for process in self.process_list
        ]
        web_app_list.sort(key=len, reverse=True)
        self.web_app_list = [w.lower() for w in web_app_list]
        browser_list.sort(key=len, reverse=True)
        self.browser_list = [b.lower() for b in browser_list]
        self.browser_regex_list = [
            re.compile(construct_regex(process), re.UNICODE)
            for process in self.browser_list
        ]
        self.pcap_dir = pcap_dir
        os.makedirs(self.pcap_dir, exist_ok=True)
        self.proto = proto
        if len(interface_list) == 0:
            interface_list = [
                iface.nice_name
                for iface in get_local_interfaces()
                if not str(iface.nice_name).startswith("lo")
            ]
        self.interface_list = interface_list
        self.debug = debug
        self.ignore_local_traffic = ignore_local_traffic
        self.send_timer = send_timer
        self.send_method = send_method
        self.server_url = server_url
        self.server_auth = server_auth
        self.sender_email = sender_email
        self.receiver_email_list = receiver_email_list
        self.sender_email_password = sender_email_password
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.delete_pcaps_after_send = delete_pcaps_after_send
        self.max_archive_size = max_archive_size
        # Some network interfaces fail to work with scapy. Filter them out.
        good_interface_list = []
        for iface in self.interface_list:
            try:
                resolve_iface(iface)
                good_interface_list.append(iface)
            except ValueError:
                print(f"Exclude network interface '{iface}' as it is not recognized")
        self.interface_list = good_interface_list


class SessionKey:
    """
    Session key is a pair of IP:port pairs.
    The order of IP:port pairs is enforced automatically, so that
    SessionKey(ip1, port1, ip2, port2) is always equal to SessionKey(ip2, port2, ip1, port1).
    lip:lport is always going to be a local IP found in local_interfaces argument.
    """

    lip: str
    lport: int
    rip: str
    rport: int

    def __init__(self, lip: str, lport: int, rip: str, rport: int):
        (self.lip, self.lport, self.rip, self.rport) = (lip, lport, rip, rport)

    def __hash__(self):
        return (self.lip + str(self.lport) + self.rip + str(self.rport)).__hash__()

    def __eq__(self, o):
        return (self.lip, self.lport, self.rip, self.rport) == (
            o.lip,
            o.lport,
            o.rip,
            o.rport,
        )

    def __str__(self):
        return f"{self.lip}:{self.lport} <=> {self.rip}:{self.rport}"


class SessionCollector:
    """
    A sniffer for TCP/UDP sessions that groups them by session keys
    (ip:port pairs), associates with running processes on the system,
    and saves to pcap files.
    """

    def __init__(self, config: SessionCollectorConfig):
        self.config = config

        conf.use_pcap = True
        # nt -- Windows
        if os.name == "nt":
            conf.use_npcap = True
            conf.use_bpf = False
        conf.bufsize = self.config.socket_buffer_size
        self.local_interfaces = get_local_interfaces()
        self.sessions: dict = dict()
        self.pid_list = [set() for _ in config.process_list]

        self.process_pid_check_prev_time = time.time()
        self.process_check_prev_time = time.time()
        self.cleanup_prev_time = time.time()
        self.email_prev_time = time.time()

        self.terminated = False
        signal.signal(signal.SIGINT, self.sigint_handler)

    def sigint_handler(self, signum, frame):
        print("INFO: SIGINT caught; terminating...")
        self.terminated = True

    def match_application(self, process):
        """Receives a process and tries to match it with an application (standalone or in-browser)"""

        try:
            cmdline = process.cmdline()
            for i, regex in enumerate(self.config.process_regex_list):
                if regex.match(cmdline[0].lower()) is not None:
                    self.pid_list[i].add(process.pid)
                    return self.config.process_list[i]
            for i, regex in enumerate(self.config.browser_regex_list):
                if regex.match(cmdline[0].lower()) is not None:
                    for web_app in self.config.web_app_list:
                        # FIXME: make matching by application more robust so that webex.com doesn't match x.com
                        if web_app in " ".join(cmdline).lower():
                            self.pid_list[i].add(process.pid)
                            return web_app
        except Exception as _:
            pass

        return None

    def check_parents(self, pid):
        """
        Checks the passed PID and it's parents for matches with PROCESS_LIST process
        names. If found, returns the corresponding name from PROCESS_LIST. Otherwise
        returns the default.
        """

        traversed = []
        while True:
            try:
                process = psutil.Process(pid)
            except Exception as _:
                break

            application = self.match_application(process)
            if application is not None:
                return application

            pid = process.ppid()
            if pid == 0:
                break

            # seems like windows can have cycles in process tree
            if pid in traversed:
                break
            else:
                traversed.append(pid)

        return None

    def check_process_conn(self, pid, conn):
        """
        Checks if the passed connection and PID correspond to a stored session and
        adds the process name to the corresponding session with "process" key.
        """

        # look for saved sessions for the provided connection
        matching_keys = []
        (lip, lport) = conn.laddr
        if conn.raddr == ():
            # this socket is only bound to a local ip:port, try to match with sessions in memory
            if lip == "0.0.0.0" or lip == "::":
                for key in self.sessions:
                    if lport == key.lport:
                        matching_keys.append(key)
            else:
                for key in self.sessions:
                    if (lip, lport) == (key.lip, key.lport):
                        matching_keys.append(key)

            if len(matching_keys) == 0:
                if self.config.debug:
                    print(
                        f"DEBUG: for {(lip, lport)} no corresponding remotes were found"
                    )
                return
        else:
            # this is a socket bound to both local and remote ip:port pairs
            # the lip can still be 0.0.0.0 or ::
            (rip, rport) = conn.raddr
            if lip == "0.0.0.0" or lip == "::":
                for key in self.sessions:
                    if (lport, rip, rport) == (key.lport, key.rip, key.rport):
                        matching_keys.append(key)
            else:
                matching_keys.append(SessionKey(lip, lport, rip, rport))

        # go over the sessions and associate process names with them if possible
        for key in matching_keys:
            if key not in self.sessions:
                if self.config.debug:
                    print(
                        f"DEBUG: session {key} exists but is not found in the buffers"
                    )
                continue

            session = self.sessions[key]
            name = self.check_parents(pid)

            if name is None:
                continue

            if "process" not in session:
                session["process"] = name
                session["need_to_save"] = True
                print(f"INFO: associated {key} with PID {pid} ({name})")
                continue

            # sanity check
            if (
                self.config.debug
                and "process" in session
                and session["process"] != name
            ):
                print(
                    f"WARNING: process name for {key} changed from {session['process']} to {name}"
                )
                session["process"] = name

    def check_processes_by_pid(self):
        """
        Iterates over captured PIDs and checks for new connections made by the
        corresponding processes.
        """

        for i, pidset in enumerate(self.pid_list):
            pids_to_delete = []
            for pid in pidset:
                try:
                    p = psutil.Process(pid)

                    for conn in p.net_connections(kind=self.config.proto):
                        self.check_process_conn(pid, conn)
                except Exception as _:
                    pids_to_delete.append(pid)
                    continue
            for pid in pids_to_delete:
                pidset.remove(pid)

    def check_processes(self):
        """
        Iterates over all processes on the system and their connections. Updates sessions
        with the corresponding process names accordingly.
        """

        for proc in psutil.process_iter(["pid"]):
            pid = proc.info["pid"]
            try:
                connections = proc.net_connections(kind=self.config.proto)
            except Exception as _:
                continue

            if connections is None:
                continue

            for conn in connections:
                self.check_process_conn(pid, conn)

        # sanity check
        if self.config.debug:
            for key in self.sessions:
                session = self.sessions[key]
                if "process" not in session:
                    print(
                        f"WARNING: session {key} exists, but no corresponding process has been found"
                    )

    def cleanup_sessions(self):
        """
        Checks if any sessions have timed out and writes them to corresponding pcap files.
        Any sessions with less than MIN_SESSION_PACKETS will be discarded.
        Only the first MAX_SESSION_PACKETS packets will be written for each session.
        Any sessions that do not correspond to any process in PROCESS_LIST will be discarded,
        unless PROCESS_LIST is empty.
        """

        sessions_to_save = []
        sessions_to_delete = []
        for key in self.sessions:
            session = self.sessions[key]
            t = (time.time_ns() - session["last_packet_ts"]) / 1000000000

            # find timed out sessions
            if self.terminated or t > self.config.session_timeout_sec:
                if len(session["packets"]) < self.config.min_packets_per_session:
                    reason = "not enough packets"
                elif session["need_to_save"]:
                    reason = "timeout"
                    if not session["saved"]:
                        sessions_to_save.append(key)
                else:
                    reason = "irrelevance"
                sessions_to_delete.append((key, reason))
            # find sessions that can and should be written to a pcap already
            elif (
                session["need_to_save"]
                and not session["saved"]
                and len(session["packets"]) >= self.config.max_packets_per_session
            ):
                sessions_to_save.append(key)

        for key in sessions_to_save:
            session = self.sessions[key]
            pcap_name = f"{session['process'] if 'process' in session else 'unknown'}-{session['last_packet_ts']}-{key.lip}-{key.lport}-{key.rip}-{key.rport}.pcap"
            pcap_path = os.path.join(self.config.pcap_dir, pcap_name)
            wrpcap(pcap_path, session["packets"])
            session["saved"] = True
            print(f"INFO: session {key} saved to {pcap_path}")

        for pair in sessions_to_delete:
            (key, reason) = pair
            session = self.sessions[key]
            self.sessions.pop(key)
            if self.config.debug:
                print(f"DEBUG: session {key} deleted due to {reason}")

    def check_email(self):
        # estimate archive size and collect files list
        files = []
        size = 0
        for file in os.listdir(self.config.pcap_dir):
            if file.startswith("sent_") or not file.endswith(".pcap"):
                continue
            files.append(file)
            file_path = os.path.join(self.config.pcap_dir, file)
            sz = os.stat(file_path).st_size
            size += sz
            if size > self.config.max_archive_size:
                files.remove(file)
                size -= sz

        # if empty, return
        if len(files) == 0:
            return

        # create archive
        archive = os.path.join(self.config.pcap_dir, f"{str(time.time())}.tar.bz2")
        with tarfile.open(archive, "w:bz2") as tar:
            for file in files:
                file_path = os.path.join(self.config.pcap_dir, file)
                tar.add(
                    file_path,
                    arcname=os.path.relpath(file_path, start=self.config.pcap_dir),
                )

        # send archive
        try:
            if self.config.send_method == "email":
                send_file_over_email(
                    archive,
                    self.config.sender_email,
                    self.config.sender_email_password,
                    self.config.receiver_email_list,
                    self.config.smtp_server,
                    self.config.smtp_port,
                )
            else:
                send_file_over_http(
                    archive,
                    self.config.server_url,
                    self.config.server_auth,
                )
            os.remove(archive)

            # delete/rename sent files
            for file in files:
                if self.config.delete_pcaps_after_send:
                    os.remove(os.path.join(self.config.pcap_dir, file))
                else:
                    os.rename(
                        os.path.join(self.config.pcap_dir, file),
                        os.path.join(self.config.pcap_dir, "sent_" + file),
                    )
        except Exception as _:
            os.remove(archive)

    def process_packet_(self, p):
        """
        Takes a new packet and adds it to the corresponding session in memory. If no corresponding
        sessions exist, they will be created. Runs regular checks for process matching if enough
        time has passed since the last check.
        """

        if self.terminated:
            raise KeyboardInterrupt()

        # filter out packets with no IP layer
        if not p.haslayer(IP) and not p.haslayer(IPv6):
            return

        if p.haslayer(IP):
            ip_src = p[IP].src
            ip_dst = p[IP].dst
        else:
            ip_src = p[IPv6].src
            ip_dst = p[IPv6].dst

        # filter out packets by protocol
        if self.config.proto == "udp" and not p.haslayer(UDP):
            return

        if self.config.proto == "tcp" and not p.haslayer(TCP):
            return

        # filter out packets that are not communicating with the current machine directly
        # (uPnP, routed traffic etc.)
        if not is_local_ip(ip_src, self.local_interfaces) and not is_local_ip(
            ip_dst, self.local_interfaces
        ):
            return

        # filter out broadcast packets
        if ip_src == "255.255.255.255" or ip_dst == "255.255.255.255":
            return

        # filter out network initialization packets with 0.0.0.0 or ::
        if (
            ip_src == "0.0.0.0"
            or ip_src == "::"
            or ip_dst == "0.0.0.0"
            or ip_dst == "::"
        ):
            return

        # filter out local traffic
        if self.config.ignore_local_traffic and is_local_traffic(
            ip_src, ip_dst, self.local_interfaces
        ):
            return

        # get session key
        if self.config.proto == "tcp":
            key = SessionKey(ip_src, p[TCP].sport, ip_dst, p[TCP].dport)
        elif self.config.proto == "udp":
            key = SessionKey(ip_src, p[UDP].sport, ip_dst, p[UDP].dport)
        else:
            print(f"ERROR: unsupported protocol: {self.config.proto}")
            exit(1)

        # order key so that lip is always the local ip
        if is_local_ip(key.rip, self.local_interfaces):
            (key.lip, key.lport, key.rip, key.rport) = (
                key.rip,
                key.rport,
                key.lip,
                key.lport,
            )

        if self.config.debug:
            print(f"DEBUG: received packet {p} (length {len(p.payload)})")

        # get or create session
        if key in self.sessions:
            session = self.sessions[key]
        else:
            session = dict()
            session["packets"] = []
            session["saved"] = False
            session["need_to_save"] = False
            print(f"INFO: session {key} established")

        # update session
        if len(session["packets"]) < self.config.max_packets_per_session:
            session["packets"].append(p)

        session["last_packet_ts"] = time.time_ns()
        self.sessions[key] = session

        # run regular checks
        if time.time() - self.process_check_prev_time > self.config.process_check_timer:
            self.check_processes()
            self.process_check_prev_time = time.time()

        if time.time() - self.cleanup_prev_time > self.config.cleanup_timer:
            self.cleanup_sessions()
            self.cleanup_prev_time = time.time()

        if (
            time.time() - self.process_pid_check_prev_time
            > self.config.process_by_pid_check_timer
        ):
            self.check_processes_by_pid()
            self.process_pid_check_prev_time = time.time()

        if (
            self.config.send_timer != -1
            and time.time() - self.email_prev_time > self.config.send_timer
        ):
            self.check_email()
            self.email_prev_time = time.time()

    def process_packet(self, p):
        """Wraps process_packet_ function with a try-except block and logs errors."""

        try:
            self.process_packet_(p)
        except KeyboardInterrupt as k:
            raise k
        except Exception as e:
            print("ERROR: Exception caught")
            traceback.print_exception(e)

    def collect(self):
        """Starts sniffing and collecting sessions. Does not return."""

        try:
            print(
                f"Listening on interfaces {self.config.interface_list} for protocol {self.config.proto}"
            )

            # Capture packets and buffer in the packet queue
            sniff(
                iface=self.config.interface_list,
                filter=self.config.proto,
                prn=self.process_packet,
                store=False,
                session=DefaultSession,
                promisc=True,
                monitor=False,
            )
        except KeyboardInterrupt as _:
            pass
        except Exception as e:
            print("ERROR: Exception caught")
            traceback.print_exception(e)
            pass

        self.cleanup_sessions()
