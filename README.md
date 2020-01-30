# ZTP XR Play

Exploring IOS-XR ZTP python capabilities to customize ZTP steps.

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


