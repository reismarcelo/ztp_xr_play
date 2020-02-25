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


