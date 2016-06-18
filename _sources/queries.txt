=======
Queries
=======

.. code:: bash

    $ jnt_query node --hadd 0121/0000 --host=192.168.14.65 --vuuid=all

.. code:: bash

    request_info_nodes
    ----------
    hadd       uuid                           name                      location             product_type
    0121/0003  hostsensor__uptime             Uptime                    Docker               Software component
    0121/0001  hostsensor__load               Load                      Docker               Software component
    0121/0002  hostsensor__disks              Disks                     Docker               Software component
    0121/0000  hostsensor                     Docker sensors            Docker               Default product type
    0121/0004  hostsensor__lmsensor           lm-sensors                Docker               Software

.. code:: bash

    request_info_users
    ----------
    0121/0004  hostsensor__lmsensor      voltage                        0    None                      V          3     2     49       The voltage from lm-sensors
    0121/0004  hostsensor__lmsensor      temperature                    0    53.0                      °C         3     2     49       The temperatures from lm-sensors

.. code:: bash

    request_info_configs
    ----------
    0121/0000  hostsensor                location                       0    Docker                    None       8     3     112      The location of the node
    0121/0000  hostsensor                name                           0    Docker sensors            None       8     3     112      The name of the node
    0121/0001  hostsensor__load          load_config                    1    5 minutes                 None       2     3     112      The load average index (1, 5, and 15m)
    0121/0001  hostsensor__load          load_config                    0    1 minutes                 None       2     3     112      The load average index (1, 5, and 15m)
    0121/0001  hostsensor__load          load_config                    2    15 minutes                None       2     3     112      The load average index (1, 5, and 15m)
    0121/0001  hostsensor__load          location                       0    Docker                    None       8     3     112      The location of the node
    0121/0001  hostsensor__load          load_poll                      0    60                        seconds    4     3     112      The poll delay of the value
    0121/0001  hostsensor__load          name                           0    Load                      None       8     3     112      The name of the node
    0121/0002  hostsensor__disks         partition_poll                 0    1800                      seconds    4     3     112      The poll delay of the value
    0121/0002  hostsensor__disks         free_config                    0    /opt/janitoo/etc          None       8     3     112      The partition path
    0121/0002  hostsensor__disks         partition_config               0    /opt/janitoo/etc          None       8     3     112      The partition path
    0121/0002  hostsensor__disks         name                           0    Disks                     None       8     3     112      The name of the node
    0121/0002  hostsensor__disks         total_poll                     0    900                       seconds    4     3     112      The poll delay of the value
    0121/0002  hostsensor__disks         total_config                   0    /opt/janitoo/etc          None       8     3     112      The partition path
    0121/0002  hostsensor__disks         used_poll                      0    900                       seconds    4     3     112      The poll delay of the value
    0121/0002  hostsensor__disks         free_poll                      0    900                       seconds    4     3     112      The poll delay of the value
    0121/0002  hostsensor__disks         percent_use_config             0    /opt/janitoo/etc          None       8     3     112      The partition path
    0121/0002  hostsensor__disks         used_config                    0    /opt/janitoo/etc          None       8     3     112      The partition path
    0121/0002  hostsensor__disks         location                       0    Docker                    None       8     3     112      The location of the node
    0121/0002  hostsensor__disks         percent_use_poll               0    900                       seconds    4     3     112      The poll delay of the value
    0121/0003  hostsensor__uptime        location                       0    Docker                    None       8     3     112      The location of the node
    0121/0003  hostsensor__uptime        name                           0    Uptime                    None       8     3     112      The name of the node
    0121/0003  hostsensor__uptime        uptime_poll                    0    300                       seconds    4     3     112      The poll delay of the value
    0121/0004  hostsensor__lmsensor      temperature_poll               0    60                        seconds    4     3     112      The poll delay of the value
    0121/0004  hostsensor__lmsensor      name                           0    lm-sensors                None       8     3     112      The name of the node
    0121/0004  hostsensor__lmsensor      voltage_config                 0    None                      None       8     3     112      The name of the lmsensor
    0121/0004  hostsensor__lmsensor      voltage_poll                   0    90                        seconds    4     3     112      The poll delay of the value
    0121/0004  hostsensor__lmsensor      location                       0    Docker                    None       8     3     112      The location of the node
    0121/0004  hostsensor__lmsensor      temperature_config             0    temp1                     None       8     3     112      The name of the lmsensor
    0121/0004  hostsensor__lmsensor      config_filename                0    /etc/sensors3.conf        None       8     3     112      The full path/name of config file to use

.. code:: bash

    request_info_systems
    ----------
    0121/0000  hostsensor                heartbeat                      0    60                        seconds    4     4     112      The heartbeat delay in seconds
    0121/0000  hostsensor                config_timeout                 0    3                         seconds    4     4     112      The config timeout before applying configuration and rebooting
    0121/0000  hostsensor                hadd                           0    0121/0000                            32    4     112      The Janitoo Home address
    0121/0001  hostsensor__load          heartbeat                      0    60                        seconds    4     4     112      The heartbeat delay in seconds
    0121/0001  hostsensor__load          config_timeout                 0    3                         seconds    4     4     112      The config timeout before applying configuration and rebooting
    0121/0001  hostsensor__load          hadd                           0    0121/0001                            32    4     112      The Janitoo Home address
    0121/0002  hostsensor__disks         heartbeat                      0    60                        seconds    4     4     112      The heartbeat delay in seconds
    0121/0002  hostsensor__disks         config_timeout                 0    3                         seconds    4     4     112      The config timeout before applying configuration and rebooting
    0121/0002  hostsensor__disks         hadd                           0    0121/0002                            32    4     112      The Janitoo Home address
    0121/0003  hostsensor__uptime        heartbeat                      0    60                        seconds    4     4     112      The heartbeat delay in seconds
    0121/0003  hostsensor__uptime        config_timeout                 0    3                         seconds    4     4     112      The config timeout before applying configuration and rebooting
    0121/0003  hostsensor__uptime        hadd                           0    0121/0003                            32    4     112      The Janitoo Home address
    0121/0004  hostsensor__lmsensor      heartbeat                      0    60                        seconds    4     4     112      The heartbeat delay in seconds
    0121/0004  hostsensor__lmsensor      config_timeout                 0    3                         seconds    4     4     112      The config timeout before applying configuration and rebooting
    0121/0004  hostsensor__lmsensor      hadd                           0    0121/0004                            32    4     112      The Janitoo Home address

.. code:: bash

    request_info_basics
    ----------
    0121/0001  hostsensor__load          load                           1    0.74                      None       3     1     49       The load average
    0121/0001  hostsensor__load          load                           0    0.76                      None       3     1     49       The load average
    0121/0001  hostsensor__load          load                           2    0.87                      None       3     1     49       The load average
    0121/0002  hostsensor__disks         total                          0    98294312960               Bytes      4     1     49       The total size of partitions
    0121/0002  hostsensor__disks         used                           0    27365867520               Bytes      4     1     49       The used size of partitions
    0121/0002  hostsensor__disks         percent_use                    0    27.8                      %          3     1     49       The percent_use of partitions
    0121/0002  hostsensor__disks         free                           0    65911693312               Bytes      4     1     49       The free size of partitions
    0121/0002  hostsensor__disks         partition                      0    /opt/janitoo/etc          None       8     1     49       The partition list
    0121/0003  hostsensor__uptime        uptime                         0    166423.04                 None       3     1     49       Uptime in seconds

.. code:: bash

    request_info_commands
    ----------

