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

#include "gss_client.hpp"

#ifndef GSS_CLIENT_HPP
  #error "This file may only be included from <gss_client.hpp>"
#endif

namespace gss_client_auth {

// Creating the ios_service, socket, resolver here makes it way faster.
GSSClientAuthentication::
GSSClientAuthentication(const std::string& krb_server_address,
                      const std::string& krb_server_port = KRB_DEFAULT_PORT_STR)
    : m_ios(), m_tcp_socket_v4(m_ios, tcp_prot_v4), m_resolver(m_ios),
      m_server_host_name(krb_server_address), m_server_host_port(krb_server_port) {

  /*
  m_client_host_name  = ip_service::host_name();
  m_service_name      = KRB_SERVICE_NAME;
  m_auth_mechanism    = GSS_API_SPNEGO_OID;
  m_gss_client_ctx.socket_descriptor  = get_native_socket_descriptor(m_tcp_socket_v4);
  m_gss_client_ctx.service_name       = from_const_str_to_char(m_service_name);
  m_gss_client_ctx.gss_mech_oid       = static_cast<gss_OID>(m_gss_oid);
  m_gss_client_ctx.gss_flags          = m_gss_flags;
  m_gss_client_ctx.gss_auth_flags     = true;
  m_gss_client_ctx.gss_encrypt_flags  = true;
  m_gss_client_ctx.username           = from_const_str_to_char(m_gss_username);
  m_gss_client_ctx.password           = from_const_str_to_char(m_gss_userpasswd);
  */
}

gss_auth_err GSSClientAuthentication::resolve_hostname_or_address(
    const std::string& host_server, const std::string& host_port) {

  error_code ec_result;
  io_service ios;
  tcp_socket tcp_socket_v4(ios, tcp_prot_v4);
  tcp_resolver resolver(ios);
  resolver_query resolv_query(host_server, host_port);
  resolver_it resolv_itbeg = resolver.resolve(resolv_query, ec_result);
  std::string client_host_name(ip_service::host_name());

  std::for_each(resolver.resolve({client_host_name, ""}), {}, [](const auto& resolv) {
    std::cout << resolv.endpoint().address() << NEWLINE;
  });
  // Handling errors.
  if (ec_result.value() != GSS_AUTH_OK) {
    std::cerr << MSG_FAILED_DNS_RESOLV << host_server << MSG_ERR_CODE
              << ec_result.value() << MSG_ERR_MESSAGE << ec_result.message()
              << NEWLINE;
    // To do: doliveira
    // Log this information out:
    // log_auth_info("string_to_oid: ", gss_major_status, gss_minor_status);
    return (auth_trap_error(ec_result.value()));
  }
  //
  /*
  m_ios               = std::move(ios);
  m_tcp_socket_v4     = std::move(tcp_socket_v4);
  //m_resolver = std::move(resolver);
  m_resolv_query      = std::move(resolv_query);
  m_client_host_name  = std::move(client_host_name);
  m_ec_result         = std::move(ec_result);
  */
  /*
  resolver_it resolv_itend;
  for (; resolv_itbeg != resolv_itend; ++resolv_itbeg) {
    tcp_endpoint end_point = resolv_itbeg->endpoint();
    std::cout << end_point.size() << NEWLINE;
  }
  //tcp_endpoint(ip_address::from_string("127.0.0.1"), 88);
  }
  */
  return (auth_trap_error(GSS_AUTH_OK));
}

gss_auth_result GSSClientAuthentication::get_server_host_info(
    const std::string& host_server, const std::string& host_port) {

  auto auth_result = (resolve_hostname_or_address(host_server, host_port));
  if (auth_result != GSS_AUTH_OK) {
    // To do: doliveira
    // Log this information out:
    // log_auth_info("string_to_oid: ", gss_major_status, gss_minor_status);
    return (auth_trap_error(auth_result));
  }
  return (GSS_AUTH_OK);
}

gss_auth_result GSSClientAuthentication::
open_krb_server_connection(const std::string& host_server,
                           const std::string& host_port) {
  /*
  error_code ec_result;
  io_service ios;
  tcp_resolver resolver(ios);
  */
  resolver_query resolv_query(host_server, host_port);
  resolver_it resolv_itbegin(m_resolver.resolve(resolv_query));
  tcp_endpoint krb_server_endpoint = (*resolv_itbegin);
  // Uses member socket and connects to KRB server.
  try {
    //tcp_socket tcp_socket_v4(m_ios, tcp_prot_v4);
    //asio::connect(m_tcp_socket_v4, m_resolver.resolve(resolv_query));
    m_tcp_socket_v4.connect(krb_server_endpoint);
    //if (!m_tcp_socket_v4.is_open()) {
    //  throw("ERROR: ...");
    //}
  } catch (const system_error& se_result) {
    std::cerr << MSG_FAILED_CONNECTION << (host_server + COLON + host_port)
              << MSG_ERR_CODE     << se_result.code()
              << MSG_ERR_MESSAGE  << se_result.what() << NEWLINE;
  }

  // Once we are connected:
  constexpr gss_uint32_t NO_TIME_REQUIRED = 0;
  gss_uint32_t gss_major_status     = 0;
  gss_uint32_t gss_minor_status     = 0;
  gss_uint32_t gss_minor_sec_status = 0;
  gss_name_t gss_server_name  = GSS_C_NO_NAME;
  gss_name_t gss_user_name    = GSS_C_NO_NAME;
  gss_buffer_desc gss_send_token;
  gss_buffer_desc gss_receive_token;
  gss_buffer_desc gss_user_passwd_buff;
  auto gss_token_ptr = std::make_unique<gss_buffer_desc>();
  gss_cred_id_t gss_credentials = GSS_C_NO_CREDENTIAL;
  gss_OID_set_desc gss_spnego_mechset;
  gss_OID_set_desc gss_auth_mechset;
  auto gss_auth_mechset_ptr   = std::make_unique<gss_OID_set_desc>();
  auto gss_spnego_mechset_ptr = std::make_unique<gss_OID_set_desc>();

  // authentication flag.
  gss_auth_mechset.count    = 0;
  gss_auth_mechset.elements = nullptr;
  switch (m_gss_auth_meth) {
    case GSSAuthenticationOptions::SPNEGO:
      gss_auth_mechset.elements = &m_auth_mech_spnego;
      gss_auth_mechset.count    = M_AUTH_DESC_COUNT;
      gss_auth_mechset_ptr      = &gss_auth_mechset;
      if (m_gss_oid != GSS_C_NULL_OID) {
        gss_spnego_mechset.elements = static_cast<gss_OID>(m_gss_oid);
        gss_spnego_mechset.count    = M_AUTH_DESC_COUNT;
      }
      break;
    case GSSAuthenticationOptions::KRB5:
      gss_auth_mechset.elements = &m_auth_mech_krb5;
      gss_auth_mechset.count    = M_AUTH_DESC_COUNT;
      gss_auth_mechset_ptr      = &gss_auth_mechset;
      break;
    case GSSAuthenticationOptions::GSS_OID:
      gss_auth_mechset.elements = static_cast<gss_OID>(m_gss_oid);
      gss_auth_mechset.count    = M_AUTH_DESC_COUNT;
      gss_auth_mechset_ptr      = &gss_auth_mechset;
      break;
  }

  if (m_gss_client_ctx.username != nullptr) {
    gss_send_token.value  = static_cast<void*>(m_gss_client_ctx.username);
    gss_send_token.length = std::strlen(m_gss_client_ctx.username);

    gss_major_status = gss_import_name(&gss_minor_status,
                                       &gss_send_token,
                                       static_cast<gss_OID_desc*>
                                               (gss_nt_user_name),
                                       &gss_user_name);
    if (gss_major_status != GSS_S_COMPLETE) {
      // To do: doliveira
      // Log this information out:
      // log_auth_info("Failed parsing 'principal name:' ", gss_major_status, gss_minor_status);
      //return (auth_trap_error(GSS_AUTH_FAILED));
      m_test
    }
  }
  gss_major_status = GSS_S_COMPLETE;
  if (m_gss_client_ctx.password != nullptr) {
    gss_user_passwd_buff.value  = static_cast<void*>(m_gss_client_ctx.password);
    gss_user_passwd_buff.length = std::strlen(m_gss_client_ctx.password);

    gss_major_status = gss_acquire_cred_with_password(&gss_minor_status,
                                                      gss_user_name,
                                                      &gss_user_passwd_buff,
                                                      NO_TIME_REQUIRED,
                                                      gss_auth_mechset_ptr, //.get()
                                                      GSS_C_INITIATE,
                                                      &gss_credentials,
                                                      nullptr, nullptr);
  }
  else if (gss_user_name != GSS_C_NO_NAME) {
    gss_major_status = gss_acquire_cred(&gss_minor_status, gss_user_name,
                                        NO_TIME_REQUIRED, gss_auth_mechset_ptr, //.get()
                                        GSS_C_INITIATE, &gss_credentials,
                                        nullptr, nullptr);
  }
  if (gss_major_status != GSS_S_COMPLETE) {
    // To do: doliveira
    // Log this information out:
    // log_auth_info("Failed acquiring 'credentials:' ", gss_major_status, gss_minor_status);
    gss_release_name(&gss_minor_status, &gss_user_name);
    //return (auth_trap_error(GSS_AUTH_FAILED));
  }
  if ((m_gss_auth_meth == GSSAuthenticationOptions::SPNEGO) &&
      (gss_spnego_mechset.elements != GSS_C_NULL_OID)) {
  }

  /*
  gss_import_name(&gss_minor_status, &gss_send_token, (gss_OID)gss_nt_user_name, &gss_user_name);
  if (gss_major_status != GSS_S_COMPLETE) {
    // To do: doliveira
    // Log this information out:
    // log_auth_info("Parsing username: ", gss_major_status, gss_minor_status);
    //auth_trap_error(gss_major_status);
  }

  gss_parse_buffer.value  = static_cast<void*>(array_mech_to_parse);
  gss_parse_buffer.length = (mech_to_parse.size());
  gss_major_status = gss_str_to_oid(&gss_minor_status, &gss_parse_buffer,
                                    *gss_oid);
  if (gss_major_status != GSS_S_COMPLETE) {
  */
}


gss_int32_t GSSClientAuthentication::next_handshake_cmd(std::string& a) {
  a
  return 0;
}
gss_int32_t GSSClientAuthentication::process_handshake_cmd(std::string&) {
  return 0;
}
gss_int32_t GSSClientAuthentication::do_encode(std::string&) {
  return 0;
}
gss_int32_t GSSClientAuthentication::do_decode(std::string&) {
  return 0;
}


}   //-- namespace gss_client_auth

// ----------------------------- END-OF-FILE --------------------------------//
