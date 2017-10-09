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


WORKSPACE=$(pwd)
DIRECTORY="$WORKSPACE/openstack"

# Openstack Repos
NOVA="nova"
CINDER="cinder"
GLANCE="glance_store"
NEUTRON="neutron"

# Tests to Run
GCE_TEST="test_gce"
AWS_TEST="test_ec2"
AWS_NOVA_TEST="test_ec2.EC2DriverTestCase"
AWS_KEYPAIR_TEST="test_keypair.KeyPairNotificationsTestCase"

declare -A results
declare -i fail
declare -i pass

copy_cinder_files() {
    cp -R $WORKSPACE/cinder/tests/unit/volume/drivers/ $DIRECTORY/$CINDER/cinder/tests/unit/volume/
    cp -R $WORKSPACE/cinder/volume/drivers/ $DIRECTORY/$CINDER/cinder/volume/
}

copy_glance_files() {
    cp -R $WORKSPACE/glance/glance_store/tests/unit/ $DIRECTORY/$GLANCE/glance_store/tests
    cp -R $WORKSPACE/glance/glance_store/_drivers/ $DIRECTORY/$GLANCE/glance_store/
}

copy_nova_files() {
    cp -R $WORKSPACE/nova/virt/ $DIRECTORY/$NOVA/nova/
    cp -R $WORKSPACE/nova/tests/unit/virt $DIRECTORY/$NOVA/nova/tests/unit
}

copy_neutron_files() {
    cp -R $WORKSPACE/neutron/neutron/common/ $DIRECTORY/$NEUTRON/neutron/
    cp -R $WORKSPACE/neutron/neutron/plugins/ml2/drivers/ $DIRECTORY/$NEUTRON/neutron/plugins/ml2/
    cp -R $WORKSPACE/neutron/neutron/services/l3_router/* $DIRECTORY/$NEUTRON/neutron/services/l3_router/
    cp -R $WORKSPACE/neutron/tests/common/ $DIRECTORY/$NEUTRON/neutron/tests/
    cp -R $WORKSPACE/neutron/tests/plugins/ml2/drivers/ $DIRECTORY/$NEUTRON/neutron/tests/unit/plugins/ml2/
    cp -R $WORKSPACE/neutron/tests/services/l3_router/* $DIRECTORY/$NEUTRON/neutron/tests/unit/services/l3_router/
}

run_tests() {
    project=$1
    tests=$2
    cd $DIRECTORY/$project
    cat $WORKSPACE/requirements.txt >> requirements.txt
    cat $WORKSPACE/test-requirements.txt >> test-requirements.txt
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
run_tests $CINDER "$GCE_TEST|$AWS_TEST" &
run_tests $NOVA "$GCE_TEST|$AWS_NOVA_TEST|$AWS_KEYPAIR_TEST" &
run_tests $GLANCE "$GCE_TEST" &
run_tests $NEUTRON "$GCE_TEST|$AWS_TEST" &
wait

check_results $CINDER
check_results $NOVA
check_results $GLANCE
check_results $NEUTRON

echo "==========================================================================================="
echo "Cinder results: ${results[$CINDER]}"
echo "Nova results: ${results[$NOVA]}"
echo "Glance results: ${results[$GLANCE]}"
echo "Neutron results: ${results[$NEUTRON]}"
echo "==========================================================================================="

for value in ${results[@]}
do
    if [ "${value}" != "PASSED" ] ; then
        echo "Test cases failed"
        exit 1
    fi
done
