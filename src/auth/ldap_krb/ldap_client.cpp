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

/* Include order and names:
 * a) Immediate related header
 * b) C libraries (if any),
 * c) C++ libraries,
 * d) Other support libraries
 * e) Other project's support libraries
 *
 * Within each section the includes should
 * be ordered alphabetically.
 */

#include "ldap_client.hpp"

#ifndef LDAP_AUTH_MECHANISM_HPP
  #error "This file may only be included from <ldap_client.hpp>"
#endif

namespace ldap_client_auth {


LDAPClientAuthentication::
LDAPClientAuthentication(const std::string& ldap_uri,
                         const ldap_utils::LDAPSSLOption& ldap_ssl_option) :
    LDAPMechanismBase(ldap_uri, ldap_ssl_option) {

}


}   //-- namespace ldap_client_auth

// ----------------------------- END-OF-FILE --------------------------------//
