%define         project credsmgr
%define         summary Credential Manager Service

Name:           pf9-%{project}
Version:        %{_version}
Release:        %{_release}.%{_githash}
Summary:        %{summary}

License:        Apache 2.0
URL:            http://www.platform9.com

AutoReqProv:    no
Provides:       pf9-%{project}
BuildArch:      %{_arch}

Requires(pre): /usr/sbin/useradd, /usr/bin/getent
Requires(postun): /usr/sbin/userdel

%description
Distribution of the %{summary} built from %{project}@%{_githash}

%global _python_bytecompile_errors_terminate_build 0

%prep
tar xf %{_sourcedir}/%{project}.tar

%install
# Create virtualenv and install credsmgr
virtualenv %{buildroot}/opt/pf9/%{project}

PBR_VERSION=1.8.1 %{buildroot}/opt/pf9/%{project}/bin/python %{buildroot}/opt/pf9/%{project}/bin/pip install \
    -chttps://git.openstack.org/cgit/openstack/requirements/plain/upper-constraints.txt?h=stable/newton %{_builddir}

install -t %{buildroot}/opt/pf9/%{project}/lib/python2.?/site-packages/%{project}/db/sqlalchemy/migrate_repo \
%{_builddir}/%{project}/db/sqlalchemy/migrate_repo/migrate.cfg

cp -r credsmgrclient %{buildroot}/opt/pf9/%{project}/lib/python2.?/site-packages/

# patch the #!python with the venv's python
sed -i "s/\#\!.*python/\#\!\/opt\/pf9\/%{project}\/bin\/python/" \
       %{buildroot}/opt/pf9/%{project}/bin/%{project}-*
mkdir -p %{buildroot}%{_sysconfdir}
cp -r %{_builddir}%{_sysconfdir}/*  %{buildroot}%{_sysconfdir}

# copy to /usr/bin
install -d -m 755 %{buildroot}%{_bindir}
install -p -m 755 -t %{buildroot}%{_bindir} \
                     %{buildroot}/opt/pf9/%{project}/bin/%{project}-*

# Systemd
mkdir -p %{buildroot}/lib/systemd/system/
cp %{_builddir}/tools/pkg/openstack-credsmgr.service %{buildroot}/lib/systemd/system/

# log and pid directory
install -d %{buildroot}/%{_localstatedir}/log/%{project}
install -d %{buildroot}/%{_localstatedir}/run/%{project}

%files
%defattr(-,%{project},%{project},-)
%defattr(-,%{_svcuser},%{_svcgroup},-)

# the virtualenv
%dir /opt/pf9/%{project}
/opt/pf9/%{project}

%{_bindir}/%{project}-*

# /etc/project config files
%dir %{_sysconfdir}/%{project}
%config(noreplace) %attr(-, %{_svcuser}, %{_svcgroup}) %{_sysconfdir}/%{project}/*.conf
%config(noreplace) %attr(-, %{_svcuser}, %{_svcgroup}) %{_sysconfdir}/%{project}/*.ini
%config(noreplace) %attr(-, %{_svcuser}, %{_svcgroup}) %{_sysconfdir}/%{project}/*.json
%config(noreplace) %attr(-, %{_svcuser}, %{_svcgroup}) %{_sysconfdir}/rsyslog.d/credsmgr.conf
%config(noreplace) %attr(-, %{_svcuser}, %{_svcgroup}) %{_sysconfdir}/logrotate.d/credsmanager

# /var/log
%dir %attr(0755, %{_svcuser}, %{_svcgroup}) %{_localstatedir}/log/%{project}

# /var/run (for pidfile)
%dir %attr(0755, %{_svcuser}, %{_svcgroup}) %{_localstatedir}/run/%{project}

/lib/systemd/system/openstack-credsmgr.service

%pre
/usr/bin/getent group %{_svcgroup} || \
    /usr/sbin/groupadd -r %{_svcgroup}
/usr/bin/getent passwd %{_svcuser} || \
    /usr/sbin/useradd -r \
                      -d / \
                      -s /sbin/nologin \
                      -g %{_svcgroup} \
                      %{_svcuser}

%post
systemctl daemon-reload
systemctl restart rsyslog
