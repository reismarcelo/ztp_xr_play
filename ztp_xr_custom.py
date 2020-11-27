#! /usr/bin/env python
"""
 ztp_xr_custom

 Copyright (c) 2020 Cisco Systems, Inc. and/or its affiliates
 @author Marcelo Reis
 @version 1.9, 27/11/2020
"""
import sys
import os
import logging
import json
import re
import urlparse
import urllib2
import socket
import base64
import time
from functools import partial

sys.path.append("/pkg/bin/")
from ztp_helper import ZtpHelpers

METADATA_URL = 'http://192.168.122.211/ztp_metadata.json'
SYSLOG_CONFIG = {
    'syslog_file': '/disk0:/ztp/ztp_python.log',
    'syslog_server': '192.168.122.211',
    'syslog_port': 514
}


def main():
    ztp_api = ZtpApi(**SYSLOG_CONFIG)

    ztp_api.log_info('Loading metadata')
    meta = ztp_api.get_metadata()

    if hasattr(meta, 'notify_url'):
        ztp_api.log_info('REST notification enabled')
        ztp_api.notify_url = meta.notify_url
        ztp_api.notify_username = meta.notify_username if hasattr(meta, 'notify_username') else None
        ztp_api.notify_password = meta.notify_password if hasattr(meta, 'notify_password') else None

    ztp_api.notify('in_progress', 'ZTP started')

    ztp_api.log_info('Checking whether software upgrade is needed')
    running_label = ztp_api.get_running_label()
    ztp_api.log_info('Running: {running}, Golden: {golden}'.format(running=running_label, golden=meta.golden_label))
    if running_label in (label.strip() for label in meta.golden_label.split(' or ')):
        ztp_api.log_info('No upgrade needed')
    elif hasattr(meta, 'use_ipxe') and meta.use_ipxe:
        ztp_api.log_info('Installing new image via iPXE boot')
        ztp_api.install_ipxe()
        # Device will reload, need to exit ZTP at this point
        ztp_api.log_info('ZTP stopped for iPXE boot')
        return
    else:
        ztp_api.log_info('Installing "{file}" image'.format(
            file=os.path.basename(urlparse.urlsplit(meta.golden_url).path))
        )
        ztp_api.install_image(meta.golden_url)

    ztp_api.log_info('Wait for any in-progress auto FPD upgrades to complete')
    ztp_api.fpd_upgrade_wait()

    day0_config_reboot = hasattr(meta, 'day0_config_reboot') and meta.day0_config_reboot

    if hasattr(meta, 'fpd_check') and meta.fpd_check:
        ztp_api.log_info('Initiating FPD upgrades')
        ztp_api.upgrade_fpd()
        ztp_api.log_info('Wait for FPD upgrades to complete')
        # Adding an extra wait in order for sh hw-module fpd to reflect the fpd upgrade status
        time.sleep(30)
        ztp_api.fpd_upgrade_wait()

        if not day0_config_reboot:
            ztp_api.router_reload()
            ztp_api.log_info('ZTP stopped for reload after FPD upgrade')
            return

    ztp_api.log_info('Loading day0 configuration')
    ztp_api.load_config(meta.day0_config_url)

    if day0_config_reboot:
        ztp_api.log_info('Custom ZTP process complete, will now reload the device')
        ztp_api.notify('complete_reload', 'ZTP completed, device will reload')
        ztp_api.router_reload()
    else:
        ztp_api.log_info('Custom ZTP process complete')
        ztp_api.notify('complete_ready', 'ZTP completed, device is ready')


class ZtpApi(ZtpHelpers):
    def __init__(self, *args, **kwargs):
        super(ZtpApi, self).__init__(*args, **kwargs)
        self.notify_url = None
        self.notify_username = None
        self.notify_password = None
        self.log_label = self.get_log_label('[{serial_number}]: ')

    def log_info(self, log_msg):
        self.syslogger.info('{label}{msg}'.format(label=self.log_label, msg=log_msg))

    def log_error(self, log_msg):
        self.syslogger.error('{label}{msg}'.format(label=self.log_label, msg=log_msg))

    def get_metadata(self, target_folder='/disk0:/ztp'):
        download = self.download_file(METADATA_URL, target_folder)
        if not succeeded(download):
            raise ZTPErrorException('Error downloading metadata')

        return ZtpMetadata.load(get_filename(download))

    def get_running_label(self):
        show_version = self.xrcmd({"exec_cmd": "show version"})
        if not succeeded(show_version):
            raise ZTPErrorException('"show version" command failed')

        regex = re.compile(r'Label\s+:\s*(.+?)\s*$')
        for line in show_version['output']:
            match = regex.match(line)
            if match:
                return match.group(1)
        else:
            raise ZTPErrorException('"show version" command parse failed')

    def get_log_label(self, format_str):
        show_inventory = self.xrcmd({"exec_cmd": "show inventory chassis"})
        if not succeeded(show_inventory):
            raise ZTPErrorException('"show inventory chassis" command failed')

        regex = re.compile(r'SN:\s+(\S+)')
        for line in show_inventory['output']:
            match = regex.search(line)
            if match:
                return format_str.format(serial_number=match.group(1))
        else:
            raise ZTPErrorException('"show inventory chassis" command parse failed')

    def load_config(self, url, target_folder='/disk0:/ztp'):
        download = self.download_file(url, target_folder)
        if not succeeded(download):
            raise ZTPErrorException('Error downloading configuration file')

        apply_config = self.xrapply(get_filename(download), 'Add ZTP configuration')
        if not succeeded(apply_config):
            raise ZTPErrorException('Error applying day0 config')

        return {"status": "success", "output": "configuration loaded successfully"}

    def install_image(self, url, target_folder='/harddisk:'):
        filename = os.path.basename(urlparse.urlsplit(url).path)
        target = os.path.join(target_folder, filename)

        if os.path.exists(target):
            self.log_info('Image already on {folder}, skipping download'.format(folder=target_folder))
        else:
            download = self.download_file(url, target_folder)
            if not succeeded(download):
                raise ZTPErrorException('Error downloading image')
            self.log_info('Image download complete')

        install = self.xrcmd({"exec_cmd": "install replace {target} noprompt commit".format(target=target)})
        if not succeeded(install):
            raise ZTPErrorException('Error installing image')

        self.log_info('Waiting for install operation to complete')
        wait_complete = self.wait_for('show install request', parse_show_install)
        if not succeeded(wait_complete):
            raise ZTPErrorException('Error installing image, {detail}'.format(detail=wait_complete['output']))
        self.log_info('Install operation completed successfully')

        return {"status": "success", "output": "image successfully installed"}

    def install_ipxe(self):
        install = self.xrcmd({"exec_cmd": "reload bootmedia network location all noprompt"})
        if not succeeded(install):
            raise ZTPErrorException('Error issuing iPXE boot command')

        return {"status": "success", "output": "ipxe boot command successfully executed"}

    def fpd_upgrade_wait(self):
        wait_complete = self.wait_for('show hw-module fpd', parse_show_hwmodule)
        if not succeeded(wait_complete):
            raise ZTPErrorException(
                'Error waiting fpd upgrades to complete, {detail}'.format(detail=wait_complete['output'])
            )

        wait_complete = self.wait_for('show platform', partial(parse_show_platform, {'IOS XR RUN', 'OPERATIONAL'}))
        if not succeeded(wait_complete):
            raise ZTPErrorException(
                'Error waiting fpd upgrades to complete, {detail}'.format(detail=wait_complete['output'])
            )
        return {"status": "success", "output": "FPD upgrade wait successful"}

    def upgrade_fpd(self):
        fpd_upgrade = self.xrcmd({"exec_cmd": "upgrade hw-module location all fpd all"})
        if not succeeded(fpd_upgrade):
            raise ZTPErrorException('Error upgrading FPDs')

        return {"status": "success", "output": "FPD upgrade successful"}

    def router_reload(self):
        device_reload = self.xrcmd({"exec_cmd": "reload location all noprompt"})
        if not succeeded(device_reload):
            raise ZTPErrorException('Error issuing the reload command')

        return {"status": "success", "output": "Reload command successful"}

    def wait_for(self, cmd, cmd_parser, budget=1800, interval=15, max_retries=3):
        time_budget = budget
        fail_retries = 0
        while True:
            cmd_result = self.xrcmd({"exec_cmd": cmd})
            if not succeeded(cmd_result):
                if fail_retries < max_retries:
                    self.log_error('"{cmd}" command failed, will retry'.format(cmd=cmd))
                    fail_retries += 1
                    continue
                raise ZTPErrorException('"{cmd}" command failed'.format(cmd=cmd))

            done_waiting, is_success = cmd_parser(cmd_result['output'])

            if done_waiting and is_success:
                return {"status": "success", "output": "'{cmd}' wait completed with success".format(cmd=cmd)}
            if done_waiting:
                return {"status": "error", "output": "'{cmd}' wait completed with error".format(cmd=cmd)}

            time_budget -= interval
            if time_budget > 0:
                self.log_info('Waiting...')
                time.sleep(interval)
            else:
                self.log_info('Wait time budget expired')
                break

        return {"status": "error", "output": "wait time budget expired"}

    def notify(self, status, message):
        if self.notify_url is None:
            return

        result = rest_callback(
            self.notify_url,
            {'status': status, 'message': '{label}{msg}'.format(label=self.log_label, msg=message)},
            self.notify_username,
            self.notify_password
        )
        if not succeeded(result):
            self.log_error('REST callback failed: {info}'.format(info=result['output']))


def parse_show_install(cmd_output):
    """
    Parse output of 'show install request'
    :param cmd_output: an iterable of lines (str) from the command output
    :return: (is_complete, is_success) tuple of bool. is_complete indicates whether the request completed,
            is_success indicates whether it was successful.
    """
    state_regex = re.compile(r'State\s*:\s*(.+?)\s*$')
    end_regex = re.compile(r'No install operation in progress')

    state = None
    is_complete = False
    for line in cmd_output:
        if state is None:
            state_match = state_regex.match(line)
            if state_match:
                state = state_match.group(1)
        elif end_regex.match(line):
            is_complete = True
            break
                
    return is_complete, state is not None and state.startswith('Success')


def parse_show_hwmodule(cmd_output):
    """
    Parse output of 'show hw-module fpd'
    :param cmd_output: an iterable of lines (str) from the command output
    :return: (is_complete, is_success) tuple of bool. is_complete indicates whether the request completed,
             is_success indicates whether it was successful.
    """
    line_regex = re.compile(
        r'\d+/\S+\s+(?P<fpd_line>.+)$'
    )

    is_complete = False
    num_matches = 0
    for cmd_line in cmd_output:
        match = line_regex.match(cmd_line)
        if match:
            num_matches += 1
            if 'UPGD PREP' in match.group('fpd_line'):
                break
    else:
        is_complete = True

    return is_complete, num_matches > 0


def parse_show_platform(desired_states, cmd_output):
    """
    Parse output of 'show platform'
    :param desired_states: Set of one or more LC state that is desired. That is, is_complete will return true
                           only if all LCs are in any of the desired states.
    :param cmd_output: an iterable of lines (str) from the command output
    :return: (is_complete, is_success) tuple of bool. is_complete indicates whether the request completed,
             is_success indicates whether it was successful.
    """
    line_regex = re.compile(
        r'(?P<node>\d+/\S+)'
        r'\s+(?P<lc>[a-zA-Z0-9\-]+)(?:\((?P<redundancy_state>[a-zA-Z]+)\))?(?:\s+(?P<plim>[a-zA-Z/]+))?'
        r'\s+(?P<state>(IOS XR RUN|OK|OPERATIONAL|FPD_UPGRADE|BOOTING|PLATFORM INITIALIZED|SHUTTING DOWN|CARD_ACCESS_DOWN|ONLINE|DATA PATH POWERED ON)+)'
        r'\s+(?P<config_state>[a-zA-Z,]+)$'
    )

    is_complete = False
    num_matches = 0
    for cmd_line in cmd_output:
        match = line_regex.match(cmd_line)
        if match:
            num_matches += 1
            if match.group('state') not in desired_states:
                break
    else:
        is_complete = True

    return is_complete, num_matches > 0


def succeeded(result, status_key='status', success_value='success'):
    return result.get(status_key, '') == success_value


def get_filename(download_result, folder_key='folder', filename_key='filename'):
    return os.path.join(download_result[folder_key], download_result[filename_key])


def rest_callback(url, payload=None, username=None, password=None, timeout=10):
    """
    Sends HTTP request to URL. If payload is provided, this will be a POST request; otherwise it is a GET request.
    If username/password are provided, HTTP basic authentication is used.
    :param url: String representing the URL target
    :param payload: (optional) Python object that can be encoded as json string.
    :param username: (optional) String
    :param password: (optional) String
    :param timeout: (optional) Timeout value in seconds
    :return: dictionary with status and output { 'status': 'error/success', 'output': ''}
    """
    request = urllib2.Request(
        url,
        json.dumps(payload) if payload is not None else None,
        {'Content-Type': 'application/json'}
    )
    if username and password:
        base64str = base64.b64encode('{user}:{password}'.format(user=username, password=password))
        request.add_header('Authorization', 'Basic {base64str}'.format(base64str=base64str))

    try:
        f = urllib2.urlopen(request, timeout=timeout)
        response = f.read()
        f.close()
    except urllib2.HTTPError as e:
        return {"status": "error", "output": "HTTP Code: {code}, {info}".format(code=e.code, info=e.reason)}
    except urllib2.URLError as e:
        return {"status": "error", "output": "{details}".format(details=e.reason)}
    except socket.timeout:
        return {"status": "error", "output": "REST callback timeout"}

    return {"status": "success", "output": "{response}".format(response=response)}


class ZtpMetadata(object):
    def __init__(self, **kwargs):
        """
        :param kwargs: key-value pairs of metadata config
        """
        self._data = kwargs

    def __getattr__(self, item):
        attr = self._data.get(item)
        if attr is None:
            raise AttributeError("'{cls_name}' object has no attribute '{attr}'".format(cls_name=type(self).__name__,
                                                                                        attr=item))
        if isinstance(attr, unicode):
            return attr.strip()

        return attr

    @classmethod
    def load(cls, filename):
        try:
            with open(filename, 'r') as read_f:
                meta_data = json.load(read_f)

            if not isinstance(meta_data, dict):
                raise TypeError('Metadata file must be a dictionary')
        except (TypeError, ValueError) as e:
            raise ZTPErrorException('Invalid metadata file: {msg}'.format(msg=e))
        else:
            return cls(**meta_data)


class ZTPErrorException(Exception):
    """ Exception ZTP errors, script will stop but still sys.exit(0) so no config rollback happens """
    pass


class ZTPCriticalException(Exception):
    """ Exception ZTP critical issues, script will stop and sys.exit(1). Any applied config will rollback """
    pass


if __name__ == "__main__":
    try:
        main()
    except ZTPErrorException as ex:
        logging.getLogger('ZTPLogger').error(ex)
        sys.exit(0)
    except ZTPCriticalException as ex:
        logging.getLogger('ZTPLogger').critical(ex)
        sys.exit(1)
    else:
        sys.exit(0)

# End
