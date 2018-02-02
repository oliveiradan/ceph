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

#ifndef GSS_CLIENT_HPP
#define GSS_CLIENT_HPP

#ifndef __cplusplus
  #error "C++ Compiler is required for this library <gss_client.hpp>"
#endif

#include <netdb.h>
#include <sys/socket.h>


#include <array>
#include <functional>
#include <iostream>
#include <iterator>
#include <locale>
#include <memory>
#include <tuple>
#include <utility>

#include "gss_auth_mechanism.hpp"
#include "gss_utils.hpp"

namespace gss_client_auth {

class GSSClientAuthentication;

// Possible states for the connection
enum class GSSConnectionStatus {
  NONE,
  CALLING_NEXT_INIT,
  SENDING_NEXT_TOKEN,
  RECEIVING_NEXT_TOKEN,
  SENDING_READY,
  RECEIVING_READY,
  CONNECTED,
};

/*
  * Structure members:
  *   - socket_descriptor : The native descriptor from ::asio (TCP connection)
  *   - service_name      : The ASCII service name of the service
  *   - gss_mech_oid      : OID of the mechanism to use
  *   - gss_flags         : GSS-API delegation flag (if any)
  *   - gss_auth_flags    : whether to actually do authentication
  *   - gss_encrypt_flags : whether to do encryption while wrapping
  *   - username          : User to authenticate
  *   - password          : User password to authenticate
  *   - gss_context       : Established GSS-API context
  *   - result_flags      : Returned flags from init_sec_context()
*/
struct gss_client_context_d {
  int socket_descriptor;
  char* service_name;
  gss_OID gss_mech_oid;
  OM_uint32 gss_flags;
  bool gss_auth_flags;
  bool gss_encrypt_flags;
  char* username;
  char* password;
  gss_ctx_id_t* gss_context;
  OM_uint32* result_flags;
};

using GSSClientAuthenticationUPtr = std::unique_ptr<GSSClientAuthentication>;
using GSSClientAuthenticationSPtr = std::shared_ptr<GSSClientAuthentication>;

class GSSClientAuthentication : public GSSMechanismBase {

  using namespace gss_utils;
  using namespace auth_mechanisms;

  public:
    static gss_OID_desc m_auth_mech_krb5   = { M_AUTH_KRB5_LENGTH,   static_cast<void*>("\x2a\xce\x6e\xce\x16f\x12\x1\x2\x2") };
    static gss_OID_desc m_auth_mech_spnego = { M_AUTH_SPENGO_LENGTH, static_cast<void*>("\x2b\x06\x01\x05\x05\x02") };
    static gss_OID_set_desc m_auth_mechset_krb5   = { M_AUTH_DESC_COUNT, &m_auth_mech_krb5 };
    static gss_OID_set_desc m_auth_mechset_spnego = { M_AUTH_DESC_COUNT, &m_auth_mech_spnego };

    gss_auth_result get_server_host_info(const std::string&,
                                         const std::string&);
    gss_auth_result open_krb_server_connection(const std::string&,
                                               const std::string&);
    // Constructors
    explicit GSSClientAuthentication(const std::string&,
                                     const std::string&) noexcept;
    explicit GSSClientAuthentication(const AuthOptions&) noexcept;
    // Disable copy assignment and constructor respectively.
    GSSClientAuthentication& operator=(const GSSClientAuthentication&) = delete;
    GSSClientAuthentication(const GSSClientAuthentication&) = delete;

    // Implementing the mechanisms.
    virtual AuthenticationStatus mechanism_status() const;
    virtual gss_int32_t next_handshake_cmd(std::string&);
    virtual gss_int32_t process_handshake_cmd(std::string&);
    virtual gss_int32_t do_encode(std::string&);
    virtual gss_int32_t do_decode(std::string&);


  private:
    static constexpr auto M_AUTH_KRB5_LENGTH   = 9;
    static constexpr auto M_AUTH_SPENGO_LENGTH = 6;
    static constexpr auto M_AUTH_DESC_COUNT    = 1;

    bool m_gss_security_context_established{false};
    io_service m_ios;
    tcp_socket m_tcp_socket_v4{m_ios, tcp_prot_v4};
    tcp_resolver m_resolver{m_ios};
    data_buffer m_data_buffer;
    error_code m_ec_result;
    gss_client_context_d m_gss_client_ctx;
    GSSConnectionStatus m_gss_connection_status;

    gss_int32_t gss_initialize_context();
    gss_int32_t gss_generate_next_token(std::string&);
    gss_int32_t gss_process_next_token(std::string&);
    //str_bool_tpl gssclient_transform_oid(const std::string&);
    gss_auth_err resolve_hostname_or_address(const std::string&,
                                             const std::string&);
    tcp_socket_native get_native_socket_descriptor(tcp_socket&);


  protected:


};    //-- class GSSClientAuthentication

}   //-- namespace gss_client_auth

#endif    //-- GSS_CLIENT_HPP

// ----------------------------- END-OF-FILE --------------------------------//
