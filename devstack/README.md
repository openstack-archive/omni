Steps to activate plugin in devstack setup.

1. Clone devstack repo: git clone https://git.openstack.org/openstack-dev/devstack
2. Copy devstack/samples/local.conf to devstack/local.conf
3. Edit local.conf file and in [[local|localrc]] section, enable Omni plugin using:
    "enable_plugin omni https://github.com/infracloudio/omni.git"
4. run devstack setup
