/* main.py
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
 * Please contact  us on support@inango-systems.com if you would like to hear more about this tool.
 */
 
import os
import argparse
from functions import is_admin, int_or_none, validate_args
from session_collector import SessionCollector, SessionCollectorConfig
from dotenv import load_dotenv
from sys import exit


def print_help():
    help_text = """
    Options:
      --help, -h                  Show this help message and exit.
    
    Configuration Parameters (from session-collector.cfg):
      PROCESS_LIST                 Comma-separated list of process names to track (e.g., "zoom,whatsapp").
      WEB_APP_LIST                 Comma-separated list of web-based applications to track
      BROWSER_LIST                 Comma-separated list of possible and supported browser process names
      SEND_TIMER                   Interval in seconds between sending pcap files (-1 if you don't want send them).
      SEND_METHOD                  One of http or email. Determines the method used for sending pcaps.
      SERVER_URL                   URL of the server to send pcaps over http to.
      SERVER_AUTH                  Authentication token to use with the HTTP server.
      SENDER_EMAIL                 Email address used for sending pcap files.
      SENDER_EMAIL_PASSWORD        Password for sender email.
      RECEIVER_EMAIL_LIST          Comma-separated list of recipient email addresses.
      SMTP_SERVER                  SMTP server for email sending.
      SMTP_PORT                    SMTP port (default: 465).
      DELETE_PCAPS_AFTER_SEND      If true, delete pcap files after sending.
      MAX_ARCHIVE_SIZE             Max email attachment size in bytes.
      MIN_PACKETS_PER_SESSION      Minimum number of packets per session to save.
      MAX_PACKETS_PER_SESSION      Maximum number of packets per session.
      SESSION_TIMEOUT_SEC          Inactivity timeout in seconds for a session to be considered ended.
      CLEANUP_TIMER                Interval for cleanup routine.
      PROCESS_CHECK_TIMER          Interval for checking running processes.
      PROCESS_BY_PID_CHECK_TIMER   Interval for checking new connections.
      PCAP_DIR                     Directory for storing pcap files.
      PROTO                        Protocol to capture (udp/tcp).
      INTERFACE_LIST               Network interfaces to capture packets from.
      DEBUG                        Enable debug logging (True/False).
      IGNORE_LOCAL_TRAFFIC         Ignore local machine traffic (True/False).
      SOCKET_BUFFER_SIZE           Size of the L2 socket buffer, in bytes
    
    These parameters can also be set via environment variables.
    """
    print(help_text)
    exit(0)


# parse arguments
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument(
    "-h", "--help", action="store_true", help="Show help message and exit"
)
args, unknown = parser.parse_known_args()

if args.help:
    print_help()

if not is_admin():
    print("This script must be run as root/administrator")
    exit(1)

config_file = "session-collector.cfg"

if not os.path.exists(config_file):
    print(
        f"Configuration file '{config_file}' not found. Please create '{config_file}' and try again."
    )
    exit(1)

load_dotenv(config_file)

min_packets_per_session = int_or_none(os.environ.get("MIN_PACKETS_PER_SESSION"))
max_packets_per_session = int_or_none(os.environ.get("MAX_PACKETS_PER_SESSION"))
session_timeout_sec = int_or_none(os.environ.get("SESSION_TIMEOUT_SEC"))
cleanup_timer = int_or_none(os.environ.get("CLEANUP_TIMER"))
process_check_timer = int_or_none(os.environ.get("PROCESS_CHECK_TIMER"))
process_by_pid_check_timer = int_or_none(os.environ.get("PROCESS_BY_PID_CHECK_TIMER"))
process_list = os.environ.get("PROCESS_LIST")
web_app_list = os.environ.get("WEB_APP_LIST")
browser_list = os.environ.get("BROWSER_LIST")
pcap_dir = os.environ.get("PCAP_DIR")
proto = os.environ.get("PROTO")
interface_list = os.environ.get("INTERFACE_LIST")
debug = os.environ.get("DEBUG")
ignore_local_traffic = os.environ.get("IGNORE_LOCAL_TRAFFIC")
send_timer = int_or_none(os.environ.get("SEND_TIMER"))
send_method = os.environ.get("SEND_METHOD")
server_url = os.environ.get("SERVER_URL")
server_auth = os.environ.get("SERVER_AUTH")
sender_email = os.environ.get("SENDER_EMAIL")
receiver_email_list = os.environ.get("RECEIVER_EMAIL_LIST")
sender_email_password = os.environ.get("SENDER_EMAIL_PASSWORD")
smtp_server = os.environ.get("SMTP_SERVER")
smtp_port = int_or_none(os.environ.get("SMTP_PORT"))
delete_pcaps_after_send = os.environ.get("DELETE_PCAPS_AFTER_SEND")
max_archive_size = int_or_none(os.environ.get("MAX_ARCHIVE_SIZE"))
socket_buffer_size = int_or_none(os.environ.get("SOCKET_BUFFER_SIZE"))

if process_list is None:
    print("PROCESS_LIST is a required variable.")
    exit(1)

kwargs = validate_args(
    min_packets_per_session=min_packets_per_session,
    max_packets_per_session=max_packets_per_session,
    session_timeout_sec=session_timeout_sec,
    cleanup_timer=cleanup_timer,
    process_check_timer=process_check_timer,
    process_by_pid_check_timer=process_by_pid_check_timer,
    process_list=process_list,
    web_app_list=web_app_list,
    browser_list=browser_list,
    pcap_dir=pcap_dir,
    proto=proto,
    interface_list=interface_list,
    debug=debug,
    ignore_local_traffic=ignore_local_traffic,
    send_timer=send_timer,
    server_url=server_url,
    server_auth=server_auth,
    sender_email=sender_email,
    receiver_email_list=receiver_email_list,
    sender_email_password=sender_email_password,
    smtp_server=smtp_server,
    smtp_port=smtp_port,
    delete_pcaps_after_send=delete_pcaps_after_send,
    max_archive_size=max_archive_size,
    socket_buffer_size=socket_buffer_size,
)

scc = SessionCollectorConfig(**kwargs)
sc = SessionCollector(scc)
sc.collect()
