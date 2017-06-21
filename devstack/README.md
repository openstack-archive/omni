** Overview **

Devstack plugin to configure Omni drivers into Openstack components.

As part of stack.sh:

1. Update .conf files as per the driver requirements for Glance, Cinder, Nova and Neutron
2. Copy Omni driver files into individual components
3. Restart devstack services

** Usage **
1. To enable plugin, update your local.conf:
enable_plugin omni https://github.com/openstack/omni.git
2. To set clouds supported by Omni:
OMNI_PROVIDER=<gce/aws/....>

Run stack.sh in your devstack tree to get started.
