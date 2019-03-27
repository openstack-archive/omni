Overview
===============

Devstack plugin to configure Omni drivers into Openstack components.

**As part of stack.sh:**

*1. Update .conf files as per the driver requirements for Glance, Cinder, Nova and Neutron*

*2. Copy Omni driver files into individual components*

*3. Restart devstack services*

Usage
===============

Following lines need to be added in local.conf to enable Omni plugin:

*1. To enable plugin:*

- enable_plugin omni https://github.com/openstack/omni.git

*2. To set clouds supported by Omni:*

- OMNI_PROVIDER=<gce/aws/....>

*3. Parameters required for Omni drivers:*

==================        =====
-------------------------------------
  AWS                     GCE
==================        =====
AWS_SECRET_KEY            ZONE
AWS_ACCESS_KEY            PROJECT_ID
AWS_REGION_NAME           REGION
AWS_AVAILABILITY_ZONE
==================        =====

Run stack.sh in your devstack tree to get started.

Assumptions
===============

- For GCE provider, service key is available in /etc/omni.json
