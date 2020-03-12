# ZTP XR Custom

Exploring IOS-XR ZTP python capabilities to customize ZTP steps.

This script performs the following steps:
- Downloads metadata json file from http server. The URL for this file is hardcoded in the script itself, METADATA_URL.
- Compares the "golden_label" value from the metadata file with the label from "show version" output.
- If the "golden_label" is different, then:
    - If "use_ipxe" metadata variable is defined and is true:
        - Issue command to iPXE boot
    - Otherwise:
        - Downloads ISO file from the URL specified in "golden_url",
        - Performs upgrade,
        - Router is reloaded if needed.
- If "fpd_check" metadata variable is defined and is true, then:
    - Verify whether FPD upgrade is required,
    - If needed, upgrade FPDs. Reload router once FPD upgrade is complete.
- Downloads configuration file from the URL defined in the "day0_config_url" metadata variable, load and commit the configuration.
- If "day0_config_reboot" metadata variable is defined and is true, device is reloaded after day0 config is applied.
- If metadata file contains REST callback settings, REST POST requests are sent at the beginning and end of the ZTP process.
    - "notify_url" - When defined, enable REST notifications to the URL provided.
    - "notify_username" and "notify_password" - If defined, REST POST requests are sent with HTTP Basic Authorization header.


## Forcing device to trigger ZTP

In order to have a device trigger ZTP again, issue a 'ztp clean' and wipe the configuration.

    RP/0/RP0/CPU0:ios# ztp clean
    Remove all ZTP temporary files? [confirm] [y/n] :y
    All ZTP operation files have been removed.
    ZTP logs are present in /var/log/ztp*.log for logrotate.
    Please remove manually if needed.
    If you now wish ZTP to run again from boot, do 'conf t/commit replace' followed by reload.
    
    RP/0/RP0/CPU0:ios# configure
    RP/0/RP0/CPU0:ios(config)# commit replace
    This commit will replace or remove the entire running configuration. This
    operation can be service affecting.
    Do you wish to proceed? [no]: y
    RP/0/RP0/CPU0:ios(config)# end
    RP/0/RP0/CPU0:ios# reload location all


## Variables used in the metadata file

The metadata file should be in JSON format, with a dictionary containing the variable names as keys.

- "day0_config_url": String containing the URL to download day0 config
- "golden_label": String containing the label for the golden image. It is compared against the label from "show version" output.
- "golden_url": String containing the URL to download the golden ISO.
- "fpd_check": (optional) true or false. Default is false.
- "use_ipxe": (optional) true or false. Default is false.
- "day0_config_reboot": (optional) true or false. Default is false.
- "notify_url": (optional) String containing the URL to send REST notifications. If not specified, REST notifications are disabled.
- "notify_username": (optional) String containing username for REST notifications.
- "notify_password": (optional) String containing password for REST notifications.


## Testing REST notifications using the nc utility

The following cli can be used in order to quickly spin up a listener for REST notifications for testing purposes:

    nc -o dump.txt -l 8080 -k -c 'echo -e "HTTP/1.1 200 OK\n\n $(date)"' 

The REST notification is a POST request with payload in JSON format.

Notification sent just after the metadata is loaded:
{'status': 'in_progress', 'message': 'ZTP started'}

Notification sent once ZTP is completed and reload is initiated: 
{'status': 'complete_reload', 'message': 'ZTP completed, device will reload'}

Notification sent once ZTP is completed and no reload is performed: 
{'status': 'complete_ready', 'message': 'ZTP completed, device is ready'}
