// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2017 Daniel Oliveira <doliveira@suse.com>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include "ldap_client.hpp"


namespace ldap_client_auth {


LDAPClientAuthentication::
LDAPClientAuthentication(const std::string& ldap_uri,
                         const ldap_utils::LDAPSSLOption& ldap_ssl_option) :
    LDAPMechanismBase(ldap_uri, ldap_ssl_option) {

}


}   //-- namespace ldap_client_auth

// ----------------------------- END-OF-FILE --------------------------------//
