#! /usr/bin/env python
"""
 ztp_xr_play

"""
import sys
import os
import logging
import json
import re
import urlparse
import time

# from lib.ztp_helper import ZtpHelpers
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

    # ztp_api.toggle_debug(True)
    ztp_api.syslogger.info('Loading metadata')
    meta = ztp_api.get_metadata()

    ztp_api.syslogger.info('Checking whether software upgrade is needed')
    running_label = ztp_api.get_running_label()
    ztp_api.syslogger.info('Running: {running}, Golden: {golden}'.format(running=running_label,
                                                                         golden=meta.golden_label))
    if running_label == meta.golden_label:
        ztp_api.syslogger.info('No upgrade needed')
    else:
        ztp_api.syslogger.info('Installing "{label}" image'.format(label=meta.golden_label))
        ztp_api.install_image(meta.golden_url)

    ztp_api.syslogger.info('Loading day0 configuration')
    ztp_api.load_day0_config(meta.day0_config_url)

    ztp_api.syslogger.info('Custom ZTP process complete')


class ZtpApi(ZtpHelpers):
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

    def load_day0_config(self, url, target_folder='/disk0:/ztp'):
        download = self.download_file(url, target_folder)
        if not succeeded(download):
            raise ZTPErrorException('Error downloading day0 configuration')

        apply_config = self.xrapply(get_filename(download), 'Add ZTP day0 configuration')
        if not succeeded(apply_config):
            raise ZTPErrorException('Error applying day0 config')

        return {"status": "success", "output": "day0 configuration loaded successfully"}

    def install_image(self, url, target_folder='/harddisk:'):
        filename = os.path.basename(urlparse.urlsplit(url).path)
        target = os.path.join(target_folder, filename)

        if os.path.exists(target):
            self.syslogger.info('Image already on {folder}, skipping download'.format(folder=target_folder))
        else:
            download = self.download_file(url, target_folder)
            if not succeeded(download):
                raise ZTPErrorException('Error downloading image')
            self.syslogger.info('Image download complete')

        install = self.xrcmd({"exec_cmd": "install replace {target} noprompt commit".format(target=target)})
        if not succeeded(install):
            raise ZTPErrorException('Error installing image')

        self.syslogger.info('Waiting for install operation to complete')
        wait_complete = self.wait_for('show install request', parse_show_install)
        if not succeeded(wait_complete):
            raise ZTPErrorException('Error installing image, {detail}'.format(detail=wait_complete['output']))
        self.syslogger.info('Install operation completed successfully')

        return {"status": "success", "output": "image successfully installed"}

    def wait_for(self, cmd, cmd_parser, budget=600, interval=15):
        time_budget = budget
        while True:
            cmd_result = self.xrcmd({"exec_cmd": cmd})
            if not succeeded(cmd_result):
                raise ZTPErrorException('"{cmd}" command failed'.format(cmd=cmd))

            done_waiting, is_success = cmd_parser(cmd_result['output'])

            if done_waiting and is_success:
                return {"status": "success", "output": "'{cmd}' wait completed with success".format(cmd=cmd)}
            if done_waiting:
                return {"status": "error", "output": "'{cmd}' wait completed with error".format(cmd=cmd)}

            time_budget -= interval
            if time_budget > 0:
                self.syslogger.info('Waiting...')
                time.sleep(interval)
            else:
                self.syslogger.info('Wait time budget expired')
                break

        return {"status": "error", "output": "wait time budget expired"}


def parse_show_install(show_install_output):
    """
    Parse output of 'show install request'
    :param show_install_output: an iterable of lines (str) from the command output
    :return: (is_complete, is_success) tuple of bool. is_complete indicates whether the request completed,
             is_success indicates whether it was successful.
    """
    state_regex = re.compile(r'State\s*:\s*(.+?)\s*$')
    end_regex = re.compile(r'No install operation in progress')

    state = None
    is_complete = False
    for line in show_install_output:
        if state is None:
            state_match = state_regex.match(line)
            if state_match:
                state = state_match.group(1)
        elif end_regex.match(line):
            is_complete = True
            break
                
    return is_complete, state is not None and state.startswith('Success')


def succeeded(result, status_key='status', success_value='success'):
    return result.get(status_key, '') == success_value


def get_filename(download_result, folder_key='folder', filename_key='filename'):
    return os.path.join(download_result[folder_key], download_result[filename_key])


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
