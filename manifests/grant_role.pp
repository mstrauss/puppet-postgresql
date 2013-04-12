# Define postgresql::grant
#
# description
#
# == Parameters
#
#   [*namevar*]
#     A unique name.  Is not used in the manifest.
#   [*role*]
#     The name of the role to grant.
#   [*to*]
#     The name of the user being granted the role.
#
# == Examples
#
#  postgresql::grant_role( admin_role_for_tom: role => admins, to => tom )
#
# == Requires
#
#   postgresql::role { $role: }
#   postgresql::role { $to: }
#
define postgresql::grant_role(
  $role,
  $to,
) {

  if( !$role ) {
    fail( "'role' must be defined for Postgresql::Grant_role[${title}]")
  }
  if( !$to ) {
    fail( "'to' must be defined for Postgresql::Grant_role[${title}]")
  }
  postgresql_psql {"GRANT ${role} TO ${to}":
    require => [ Postgresql::Role[$role], Postgresql::Role[$to] ],
    unless  => "SELECT groname FROM pg_group WHERE (SELECT usesysid FROM pg_user WHERE usename='${to}') = ANY(grolist) AND groname='${role}'",
  }

}
