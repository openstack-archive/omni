#!/bin/bash
# Copyright (c) 2017 Platform9 Systems Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

key="$1"

case $key in
    -j) JENKINSRUN=true;;
    -wj) JENKINSRUN=false;;
esac

WORKSPACE=$(pwd)
DIRECTORY="$WORKSPACE/openstack"
GCE_TEST="test_gce"
AWS_TEST="test_ec2"
declare -A results
declare -i fail
declare -i pass

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
    cp -R $WORKSPACE/nova/virt/ $DIRECTORY/nova/nova/
    cp -R $WORKSPACE/nova/tests/unit/virt $DIRECTORY/nova/nova/tests/unit
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
    cd $DIRECTORY/$project
    cat $WORKSPACE/omni-requirements.txt >> requirements.txt
    tox -epy27 $tests > $DIRECTORY/$project.log
}

check_results() {
    project=$1
    fail_string=$(awk '/Failed: /' $DIRECTORY/$project.log | awk -F ': ' '{print $2}')
    pass_string=$(awk '/Passed: /' $DIRECTORY/$project.log | awk -F ': ' '{print $2}')
    fail=`echo $fail_string | awk -F ' ' '{print $1}'`
    pass=`echo $pass_string | awk -F ' ' '{print $1}'`
    if [[ $fail -gt 0 ]]; then
        results+=( ["$project"]="FAILED" )
    elif [[ $pass -gt 0 ]]; then
        results+=( ["$project"]="PASSED" )
    else
        # When tests failed due to import errors, we don't get number of failed
        # or passed tests. In this case, we are assigning UNKNOWN state to tests
        results+=( ["$project"]="UNKNOWN" )
    fi
}

copy_cinder_files
copy_nova_files
copy_glance_files
copy_neutron_files

echo "============Running tests============"
run_tests cinder "$GCE_TEST" &
run_tests nova "$GCE_TEST" &
run_tests glance_store "$GCE_TEST" &
run_tests neutron "$GCE_TEST" &
wait

check_results cinder
check_results nova
check_results glance_store
check_results neutron

echo "==========================================================================================="
echo "Log files are in $DIRECTORY/. Please check log files for UNKNOWN status."
echo "Cinder results: ${results[cinder]}"
echo "Nova results: ${results[nova]}"
echo "Glance results: ${results[glance_store]}"
echo "Neutron results: ${results[neutron]}"
echo "==========================================================================================="

if [ "${results[cinder]}" != "PASSED" ] || \
    [ "${results[nova]}" != "PASSED" ] || \
    [ "${results[glance_store]}" != "PASSED" ] || \
    [ "${results[neutron]}" != "PASSED" ]; then
    echo "Test cases failed"
    exit 1
fi
