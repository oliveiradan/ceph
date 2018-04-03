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

#include "auth/KrbAuthorizeHandler.hpp"

#include "common/debug.h"

#define dout_subsys ceph_subsys_auth 

auto KrbAuthorizeHandler::verify_authorizer(CephContext* ceph_ctx, 
                                            KeyStore* keys, 
                                            bufferlist& authorizer_data,  
                                            bufferlist& authorizer_reply, 
                                            EntityName& entity_name, 
                                            uint64_t& global_id,  
                                            AuthCapsInfo& caps_info, 
                                            CryptoKey& session_key, 
                                            uint64_t* auid)
{
  constexpr auto SUBSYSTEM_ID(0);
  auto itr(authorizer_data.begin()); 

  try {
    uint8_t value(1);
    decode(value, itr);
    decode(entity_name, itr);
    decode(global_id, itr);
  } 
  catch (const buffer::error& err) {
    ldout(ceph_ctx, SUBSYSTEM_ID) 
        << "Error: KrbAuthorizeHandler::verify_authorizer() failed!";
    return false;
  }
  caps_info.allow_all = true; 
  return true;
}

auto KrbAuthorizeHandler::authorizer_session_crypto()
{
  return SESSION_SYMMETRIC_AUTHENTICATE;
}


// ----------------------------- END-OF-FILE --------------------------------//

