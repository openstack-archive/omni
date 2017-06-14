#!/usr/bin/env bash
set -x

WORKSPACE=$(pwd)
DIRECTORY="$WORKSPACE/omnitests"
declare -A results

if [ -d "$DIRECTORY" ]; then
    rm -rf $DIRECTORY
fi

mkdir $DIRECTORY
python setup.py develop

clone_repos() {
    project=$1
    git clone -b stable/newton --depth 1 https://github.com/openstack/$project.git $DIRECTORY/$project
}

copy_cinder_files() {
    cp -R $WORKSPACE/cinder/tests/unit/volume/drivers/ $DIRECTORY/cinder/cinder/tests/unit/volume/
    cp -R $WORKSPACE/cinder/volume/drivers/ $DIRECTORY/cinder/cinder/volume/
}

copy_glance_files() {
    cp -R $WORKSPACE/glance/glance_store/tests/unit/ $DIRECTORY/glance_store/glance_store/tests
    cp $WORKSPACE/glance/gce/gceutils.py $DIRECTORY/glance_store/glance_store/_drivers/
    cp -R $WORKSPACE/glance/glance_store/_drivers/ $DIRECTORY/glance_store/glance_store/
}

copy_nova_files() {
    cp -R $WORKSPACE/nova/virt/ $DIRECTORY/nova/nova/virt/
    cp -R $WORKSPACE/nova/tests/unit/ $DIRECTORY/nova/nova/tests/
}

copy_neutron_files() {
    cp -R $WORKSPACE/neutron/neutron/common/ $DIRECTORY/neutron/neutron/
    cp -R $WORKSPACE/neutron/neutron/plugins/ml2/drivers/ $DIRECTORY/neutron/neutron/plugins/ml2/
    cp $WORKSPACE/neutron/neutron/services/l3_router/* $DIRECTORY/neutron/neutron/services/l3_router/
    cp -R $WORKSPACE/neutron/tests/common/ $DIRECTORY/neutron/neutron/tests/
    cp -R $WORKSPACE/neutron/tests/plugins/ml2/drivers/ $DIRECTORY/neutron/neutron/tests/unit/plugins/ml2/
}

run_tests() {
    project=$1
    tests=$2
    source $WORKSPACE/.tox/py27/bin/activate
    cd $DIRECTORY/$project
    python -m testtools.run $tests >> $DIRECTORY/$project.log
}

check_results() {
    project=$1
    string="FAILED"
    total_tests=$(tail -2 $DIRECTORY/$project.log | head -1)
    complete_result=$(tail -1 $DIRECTORY/$project.log | head -1)
    if test "${complete_result#*$string}" != "$complete_result"; then
        results=( ["$project"]="$string")
    else
        results=( ["$project"]="PASSED")
    fi
}

clone_repos cinder &
clone_repos nova &
clone_repos glance_store &
clone_repos neutron &
wait

copy_cinder_files
copy_glance_files
copy_nova_files
copy_neutron_files

NOVA_TESTS="nova.tests.unit.virt.ec2.test_ebs nova.tests.unit.virt.gce.test_gce"
CINDER_TESTS="cinder.tests.unit.volume.drivers.test_ebs cinder.tests.unit.volume.drivers.gce.test_gce"
GLANCE_TESTS="glance_store.tests.unit.gce.test_gce"
NEUTRON_TESTS="neutron.tests.unit.plugins.ml2.drivers.gce.test_gce"

run_tests cinder "$CINDER_TESTS" &
run_tests glance_store "$GLANCE_TESTS" &
run_tests neutron "$NEUTRON_TESTS" &
run_tests nova "$NOVA_TESTS" &
wait

check_results cinder
check_results nova
check_results neutron
check_results glance_store

echo "Cinder results: ${results[cinder]}"
echo "Glance results: ${results[glance_store]}"
echo "Neutron results: ${results[neutron]}"
echo "Nova results: ${results[nova]}"

if [ "${results[cinder]}" = "FAILED" ] || \
    [ "${results[glance_store]}" = "FAILED" ] || \
    [ "${results[neutron]}" = "FAILED" ] || \
    [ "${results[nova]}" = "FAILED" ]; then
    echo "Test cases failed"
    exit 1
fi
echo "All tests passed"
