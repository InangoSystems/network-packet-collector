 /* functions.py
 *
 * Copyright (c) 2013-2025 Inango Systems LTD.
 *
 * Author: Inango Systems LTD. <support@inango-systems.com>
 * Creation Date: Jul 2015
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
 * Please contact us at Inango at support@inango-systems.com if you would like to hear more about this tool.
 */



import os
import ctypes
import ifaddr
import ipaddress
import smtplib
import email.encoders
import requests
from email.mime.multipart import MIMEMultipart, MIMEBase


def get_local_interfaces():
    return list(ifaddr.get_adapters())


def is_local_ip(ip, interfaces):
    """Checks if the provided IP is present in the provided list of interface addresses."""

    for iface in interfaces:
        for addr_info in iface.ips:
            if type(addr_info.ip) is str and addr_info.ip == ip:
                return True
            elif addr_info.ip[0] == ip:
                return True

    return False


def is_local_traffic(ip1, ip2, interfaces):
    """
    Checks if the provided traffic is local to the network
    of one of the provided interface addresses.
    """

    for iface in interfaces:
        for addr_info in iface.ips:
            try:
                if type(addr_info.ip) is str:
                    network = ipaddress.IPv4Network(
                        f"{addr_info.ip}/{addr_info.network_prefix}", strict=False
                    )
                    if (
                        ipaddress.IPv4Address(ip1) in network
                        and ipaddress.IPv4Address(ip2) in network
                    ):
                        return True
                else:
                    network = ipaddress.IPv6Network(
                        f"{addr_info.ip[0]}/{addr_info.network_prefix}", strict=False
                    )
                    if (
                        ipaddress.IPv6Address(ip1) in network
                        and ipaddress.IPv6Address(ip2) in network
                    ):
                        return True
            except Exception as _:
                pass

    return False


def is_admin():
    """Checks if the script is run as root/admin user"""

    # nt -- Windows
    if os.name == "nt":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception as _:
            return False
    else:
        return os.geteuid() == 0


def int_or_none(str):
    if str is None:
        return None
    return int(str)


def validate_args(**kwargs) -> dict:
    filtered_kwargs = {}
    for k, v in kwargs.items():
        if v is None:
            continue

        if k.endswith("_list"):
            lst = v.split(",")
            if len(lst) == 1 and lst[0] == "":
                lst = []
            filtered_kwargs[k] = lst
        elif (
            k == "debug"
            or k == "ignore_local_traffic"
            or k == "delete_pcaps_after_send"
        ):
            if v == "1" or v.lower() == "true":
                filtered_kwargs[k] = True
            else:
                filtered_kwargs[k] = False
        else:
            filtered_kwargs[k] = v

    return filtered_kwargs


def send_file_over_http(
    file: str,
    server_url: str,
    server_auth: str,
):
    try:
        with open(file, "rb") as attachment:
            files = {
                "uploads": (
                    str(os.path.basename(file)),
                    attachment,
                    "application/x-bzip2",
                )
            }
            data = {"token": server_auth}
            response = requests.post(server_url, files=files, data=data)
            response.raise_for_status()

        print(f"File sent: {file} to {server_url}")
    except Exception as e:
        print(f"failed to send file: {e}")
        raise e


def send_file_over_email(
    file: str,
    sender: str,
    password: str,
    receivers: list,
    smtp_server: str,
    smtp_port: int,
):
    msg = MIMEMultipart()
    msg["From"] = sender
    msg["To"] = ", ".join(receivers)
    msg["Subject"] = f"Traffic Capture - {os.path.basename(file)}"

    try:
        with open(file, "rb") as attachment:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment.read())
            email.encoders.encode_base64(part)
            part.add_header(
                "Content-Disposition", f"attachment; filename={os.path.basename(file)}"
            )
            msg.attach(part)

        # context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
            # server.starttls(context=context)
            server.login(sender, password)
            server.sendmail(sender, receivers, msg.as_string())
        print(f"Email sent: {file} to {receivers}")
    except Exception as e:
        print(f"failed to send email: {e}")
        raise e
