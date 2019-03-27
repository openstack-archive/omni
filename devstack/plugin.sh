#!/bin/bash
set -x

cp /opt/stack/omni/devstack/lib/* $TOP_DIR/lib/
sudo apt-get install crudini -y
sudo pip install -r /opt/stack/omni/requirements.txt


if [[ "$1" == "stack" && "$2" == "pre-install" ]]; then
    if [ "$OMNI_PROVIDER" != "gce" ] && [ "$OMNI_PROVIDER" != "aws" ]; then
        echo "$OMNI_PROVIDER is not supported"
        exit 1
    fi
    if [ "$OMNI_PROVIDER" == "aws" ]; then
        if [ -z "$AWS_ACCESS_KEY" ] || [ -z "$AWS_SECRET_KEY" ]; then
            echo "AWS_ACCESS_KEY and AWS_SECRET_KEY are not provided"
            exit 1
        fi
    fi
fi

if [[ "$1" == "stack" && "$2" == "extra" ]]; then
    source $TOP_DIR/lib/omni_$OMNI_PROVIDER
    source $TOP_DIR/lib/common_functions

    if [ "$OMNI_PROVIDER" == "aws" ]; then
        source $TOP_DIR/lib/creds_mgr
        install_credsmgr
    fi

    configure_glance
    configure_cinder
    configure_nova
    configure_neutron
    copy_omni_files
    restart_services
fi

if [[ "$1" == "unstack" ]]; then
    if [ "$OMNI_PROVIDER" == "aws" ]; then
        source $TOP_DIR/lib/creds_mgr
        stop_credsmgr_service
    fi
fi
