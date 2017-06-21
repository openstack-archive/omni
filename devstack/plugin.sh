cp /opt/stack/omni/devstack/lib/omni $TOP_DIR/lib/
sudo apt-get install crudini -y
sudo pip install -r /opt/stack/omni/omni-requirements.txt
source $TOP_DIR/lib/omni

if [[ "$1" == "stack" && "$2" == "extra" ]]; then
    configure_omni_glance
    configure_omni_cinder
    configure_omni_nova
    configure_omni_neutron
fi
