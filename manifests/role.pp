# puppet-postgresql
# For all details and documentation:
# http://github.com/inkling/puppet-postgresql
#
# Copyright 2012- Inkling Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

define postgresql::role(
    $password         = false,
    $password_hash    = false,
    $createdb         = false,
    $createrole       = false,
    $db               = 'postgres',
    $login            = false,
    $superuser        = false,
    $replication      = false,
    $noinherit        = false,
    $connection_limit = '-1',
    $username         = $title
) {
  include postgresql::params

  # Password mangling
  if( $password ) {
    if( $password_hash ) {
      fail("Either password OR password_hash can be provided. Not both.")
    } else {
      $_password_hash = postgresql_password( $title, $password )
    }
  } else {
    if( $password_hash ) {
      $_password_hash = $password_hash
    } else {
      $_password_hash = false
    }
  }

  Postgresql_psql {
    psql_user    => $postgresql::params::user,
    psql_group   => $postgresql::params::group,
    psql_path    => $postgresql::params::psql_path,
  }

  $login_sql       = $login       ? { true => 'LOGIN'       , default => 'NOLOGIN' }
  $createrole_sql  = $createrole  ? { true => 'CREATEROLE'  , default => 'NOCREATEROLE' }
  $createdb_sql    = $createdb    ? { true => 'CREATEDB'    , default => 'NOCREATEDB' }
  $superuser_sql   = $superuser   ? { true => 'SUPERUSER'   , default => 'NOSUPERUSER' }
  $replication_sql = $replication ? { true => 'REPLICATION' , default => '' }
  $noinherit_sql   = $noinherit   ? { true => 'NOINHERIT'   , default => '' }
  $password_sql    = $_password_hash ? {
    false   => '',
    default => "ENCRYPTED PASSWORD '${_password_hash}'"
  }

  # TODO: FIXME: Will not correct the superuser / createdb / createrole / login / replication status nor the connection limit of a role that already exists
  postgresql_psql {"CREATE ROLE \"${username}\" ${password_sql} ${login_sql} ${createrole_sql} ${createdb_sql} ${superuser_sql} ${replication_sql} ${noinherit_sql} CONNECTION LIMIT ${connection_limit}":
    db        => $db,
    psql_user => $postgresql::params::user,
    unless    => "SELECT rolname FROM pg_roles WHERE rolname='${username}'",
  }
}
