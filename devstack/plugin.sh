#!/bin/bash
set -x

OMNI_DATA_DIR="/opt/stack/omni"
DIST_PACKAGES="/usr/local/lib/python2.7/dist-packages"

cp /opt/stack/omni/devstack/lib/* $TOP_DIR/lib/
sudo apt-get install crudini -y
sudo pip install -r /opt/stack/omni/requirements.txt

if [[ "$1" == "stack" && "$2" == "pre-install" ]]; then
    if [ "$OMNI_PROVIDER" != "gce" ] && [ "$OMNI_PROVIDER" != "aws" ]; then
        echo "$OMNI_PROVIDER is not supported"
        exit 1
    fi
fi

if [[ "$1" == "stack" && "$2" == "extra" ]]; then
    source $TOP_DIR/lib/omni_$OMNI_PROVIDER
    source $TOP_DIR/lib/common_functions
    if [ "$OMNI_PROVIDER" == "aws" ]; then
        sudo cp -R $OMNI_DATA_DIR/credsmgrclient $DIST_PACKAGES/
    fi
    configure_glance
    configure_cinder
    configure_nova
    configure_neutron
    copy_files
    restart_services
fi
