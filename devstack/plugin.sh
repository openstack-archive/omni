#!/bin/bash
set -x

cp /opt/stack/omni/devstack/lib/* $TOP_DIR/lib/
sudo apt-get install crudini -y
sudo pip install -r /opt/stack/omni/omni-requirements.txt

if [[ "$1" == "stack" && "$2" == "pre-install" ]] && [ "$OMNI_PROVIDER" != "" ]; then
    if [ "$OMNI_PROVIDER" != "gce" ] && [ "$OMNI_PROVIDER" != "aws" ]; then
        echo "$OMNI_PROVIDER is not supported"
        exit 1
    fi
fi

if [[ "$1" == "stack" && "$2" == "extra" ]] && [ "$OMNI_PROVIDER" != "" ]; then
    source $TOP_DIR/lib/omni_$OMNI_PROVIDER
    configure_glance
    configure_cinder
    configure_nova
    configure_neutron
fi
