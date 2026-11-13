# Consul agent configuration with ACLs switched off.
datacenter = "dc1"
data_dir   = "/var/lib/consul"

acl {
  enabled        = false
  default_policy = "allow"
}
