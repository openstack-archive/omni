set -e

PROJ=credsmgr
SVCUSER=$PROJ
SVCGROUP=$PROJ

SRCROOT=$(dirname $(readlink -f $0))
RPMBUILD=$SRCROOT/build
SPEC=$SRCROOT/tools/pkg/pf9-$PROJ.spec

PF9_VERSION=${PF9_VERSION:-3.2.0}
BUILD_NUMBER=${BUILD_NUMBER:-0}
PBR_VERSION=1.8.1
export PBR_VERSION

GITHASH=`git rev-parse --short HEAD`

# build rpm environment
[ -d $RPMBUILD ] && rm -rf $SRCROOT/rpmbuild
for i in BUILD RPMS SOURCES SPECS SRPMS tmp
do
    mkdir -p $RPMBUILD/${i}
done
cp -f $SPEC $RPMBUILD/SPECS/

# build a source tarball
tar -c --exclude='*.pyc' -f $RPMBUILD/SOURCES/$PROJ.tar \
        $PROJ \
        etc \
        tools \
        setup.py \
        setup.cfg \
        requirements.txt \
        test-requirements.txt \
        README.md \
        ../credsmgrclient

# QA_SKIP_BUILD_ROOT is added to skip a check in rpmbuild that greps for
# the buildroot path in the installed binaries. Many of the python
# binary extension .so libraries do this.
QA_SKIP_BUILD_ROOT=1 rpmbuild -ba \
         --define "_topdir $RPMBUILD"  \
         --define "_tmpdir $RPMBUILD/tmp" \
         --define "_version $PF9_VERSION"  \
         --define "_release $BUILD_NUMBER" \
         --define "_githash $GITHASH" \
         --define "_svcuser $SVCUSER" \
         --define "_svcgroup $SVCGROUP" \
         $SPEC

${SRCROOT}/tools/pkg/sign_packages.sh ${RPMBUILD}/RPMS/*/pf9-credsmgr*.rpm

