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

mkdir $DIRECTORY

clone_repos() {
    project=$1
    git clone -b stable/newton --depth 1 https://github.com/openstack/$project.git $DIRECTORY/$project
}

echo "============Cloning repos============"
clone_repos cinder &
clone_repos nova &
clone_repos glance_store &
clone_repos neutron &
wait
