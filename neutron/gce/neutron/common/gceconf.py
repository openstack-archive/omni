from oslo_config import cfg

gce_group = cfg.OptGroup(name='GCE',
                         title='Options to connect to Google cloud')

gce_opts = [
    cfg.StrOpt('service_key_path', help='Service key of GCE account',
               secret=True),
    cfg.StrOpt('zone', help='GCE zone'),
    cfg.StrOpt('region', help='GCE region'),
    cfg.StrOpt('project_id', help='GCE project id'),
]

cfg.CONF.register_group(gce_group)
cfg.CONF.register_opts(gce_opts, group=gce_group)

service_key_path = cfg.CONF.GCE.service_key_path
zone = cfg.CONF.GCE.zone
region = cfg.CONF.GCE.region
project_id = cfg.CONF.GCE.project_id
