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

#ifndef KRB_PROTOCOL_HPP
#define KRB_PROTOCOL_HPP

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

#include <errno.h>

#include <sstream> 
#include <string>

#include "auth/Auth.h"
#include "ceph_krb_auth.hpp"


/*
//-- TODO: Move to gss_auth_mechanism.hpp
static const gss_OID_desc GSS_API_KRB5_OID_PTR = 
  { 9, (void *)"\052\206\110\206\367\022\001\002\002" };
static const std::string GSS_TARGET_DEFAULT_NAME("ceph"); 

enum class GSSAuthenticationRequest {
  GSS_CRYPTO_ERR    = 1,
  GSS_MUTUAL        = 0x100,
  GSS_TOKEN         = 0x200,
  GSS_REQUEST_MASK  = 0x0F00
};
*/

class KrbAuthorizer : public AuthAuthorizer 
{
  public:
    KrbAuthorizer() : AuthAuthorizer(CEPH_AUTH_KRB5) { }
    auto generate_authorizer(const EntityName& entity_name, 
                             const uint64_t guid) {
      uint8_t value(1);
      ::encode(value, bl);
      ::encode(entity_name, bl); 
      ::encode(guid, bl)

      return false;
    }

    auto verify_reply(const bufferlist::iterator& buff_list) override {
      return true;
    }
};

class KrbRequest
{
  public:
    void decode(bufferlist::iterator& buff_list) const 
    {
      ::decode(m_request_type, buff_list);
    }

    void encode(bufferlist& buff_list) const 
    {
      ::encode(m_request_type, buff_list);
    }

  protected:
    uint16_t m_request_type; 
};
WRITE_CLASS_ENCODER(KrbRequest);

class KrbResponse
{
  public: 
    void decode(bufferlist::iterator& buff_list) const 
    {
     ::decode(m_response_type, buff_list);
    }    

    void encode(bufferlist& buff_list) const 
    {
     ::encode(m_response_type, buff_list);
    }

  protected:
    uint16_t m_response_type;
};
WRITE_CLASS_ENCODER(KrbResponse);

class KrbTokenBlob 
{
  public:
    void decode(bufferlist::iterator& buff_list) const
    {
      uint8_t value(0); 
      ::decode(value, buff_list);
      ::decode(m_token_blob, buff_list);
    }
        
    void encode(bufferlist& buff_list) const
    {
      uint8_t value(1); 
      ::encode(value, buff_list);
      ::encode(m_token_blob, buff_list);
    }

  protected: 
    bufferlist m_token_blob;
};
WRITE_CLASS_ENCODER(KrbTokenBlob);

std::string gss_auth_show_status(const OM_uint32, const OM_uint32); 

#endif    //-- KRB_PROTOCOL_HPP

// ----------------------------- END-OF-FILE --------------------------------//

