set -x

cp /opt/stack/omni/devstack/lib/* $TOP_DIR/lib/
sudo apt-get install crudini -y
sudo pip install -r /opt/stack/omni/omni-requirements.txt

if [[ "$1" == "stack" && "$2" == "extra" ]]; then
    source $TOP_DIR/lib/omni_$OMNI_PROVIDER
    configure_glance
    configure_cinder
    configure_nova
    configure_neutron
fi
