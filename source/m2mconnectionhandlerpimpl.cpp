/*
 * Copyright (c) 2015 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "mbed-client-classic/m2mconnectionhandlerpimpl.h"
#include "mbed-client/m2mconnectionobserver.h"
#include "mbed-client/m2mconstants.h"
#include "mbed-client/m2msecurity.h"
#include "mbed-client/m2mconnectionhandler.h"

#include "threadwrapper.h"
#include "mbed_error.h"

#include "NetworkStack.h"
#include "UDPSocket.h"
#include "TCPSocket.h"
#include "mbed-trace/mbed_trace.h"

#define TRACE_GROUP "mClt"

M2MConnectionHandlerPimpl::M2MConnectionHandlerPimpl(M2MConnectionHandler* base, M2MConnectionObserver &observer,
                                                     M2MConnectionSecurity* sec,
                                                     M2MInterface::BindingMode mode,
                                                     M2MInterface::NetworkStack stack)
:_base(base),
 _observer(observer),
 _security_impl(sec),
 _use_secure_connection(false),
 _binding_mode(mode),
 _network_stack(stack),
 _socket(0),
 _listening(false),
 _listen_thread(0),
 _network_interface(0)
{
    memset(&_address_buffer, 0, sizeof _address_buffer);
    memset(&_address, 0, sizeof _address);
    _address._address = _address_buffer;

    if (_network_stack != M2MInterface::LwIP_IPv4) {
        error("ConnectionHandler: Unsupported network stack, only IPv4 is currently supported");
    }
    _running = true;
}

M2MConnectionHandlerPimpl::~M2MConnectionHandlerPimpl()
{
    _listening = false;
    _running = false;

    if (_listen_thread) {
        delete _listen_thread;
        _listen_thread = 0;
    }
    if (_socket) {
        delete _socket;
        _socket = 0;
    }
    _network_interface = 0;
    delete _security_impl;
}

bool M2MConnectionHandlerPimpl::bind_connection(const uint16_t listen_port)
{
    _listen_port = listen_port;
    return true;
}

bool M2MConnectionHandlerPimpl::resolve_server_address(const String& server_address,
                                                       const uint16_t server_port,
                                                       M2MConnectionObserver::ServerType server_type,
                                                       const M2MSecurity* security)
{
    bool success = false;

    if (!_network_interface) {
        return false;
    }
    if(_socket) {
        delete _socket;
        _socket = NULL;
    }

    _socket_address = new SocketAddress(_network_interface,server_address.c_str(), server_port);
    if(M2MInterface::TCP == _binding_mode ||
       M2MInterface::TCP_QUEUE == _binding_mode) {
       tr_debug("M2MConnectionHandlerPimpl::resolve_server_address - Using TCP");        
        _socket = new TCPSocket(_network_interface);
        if (((TCPSocket*)_socket)->connect(*_socket_address) < 0) {
            return false;
        } else {
            success = true;
        }
    } else {
       tr_debug("M2MConnectionHandlerPimpl::resolve_server_address - Using UDP");
        _socket = new UDPSocket(_network_interface);
        ((UDPSocket*)_socket)->bind(_listen_port);
        success = true;
    }

    if (security) {
        if (security->resource_value_int(M2MSecurity::SecurityMode) == M2MSecurity::Certificate ||
            security->resource_value_int(M2MSecurity::SecurityMode) == M2MSecurity::Psk) {
            if( _security_impl != NULL ){
                _security_impl->reset();
                _security_impl->init(security);
                tr_debug("M2MConnectionHandlerPimpl::resolve_server_address - connect DTLS");
                success = 0 == _security_impl->connect(_base);
                if( success ) {
                    _use_secure_connection = true;
                    _socket->set_timeout(0); // Block for all calls
                }
            }
        }
    }
    if(success) {
        _address._address = (void*)_socket_address->get_ip_address();
        tr_debug("IP Address %s",_socket_address->get_ip_address());
        tr_debug("Port %d",_socket_address->get_port());
        _address._length = strlen((char*)_address._address);
        _address._port = _socket_address->get_port();
        _address._stack = _network_stack;

        _observer.address_ready(_address,
                                server_type,
                                _address._port);
    }
    return success;
}

bool M2MConnectionHandlerPimpl::send_data(uint8_t *data,
                                          uint16_t data_len,
                                          sn_nsdl_addr_s *address)
{
    tr_debug("M2MConnectionHandlerPimpl::send_data");
    if (address == NULL || data == NULL) {
        return false;
    }

    bool success = false;
    if(data){
        if( _use_secure_connection ){
            if( _security_impl->send_message(data, data_len) > 0){
                success = true;
                _observer.data_sent();
            }else{
                _observer.socket_error(1);
            }
        } else {
            if(address) {
                int32_t ret = -1;
                if(M2MInterface::TCP == _binding_mode ||
                   M2MInterface::TCP_QUEUE == _binding_mode){
                    //We need to "shim" the length in front
                    uint16_t d_len = data_len+4;
                    uint8_t* d = (uint8_t*)malloc(data_len+4);

                    d[0] = (data_len >> 24 )& 0xff;
                    d[1] = (data_len >> 16 )& 0xff;
                    d[2] = (data_len >> 8 )& 0xff;
                    d[3] = data_len & 0xff;
                    memmove(d+4, data, data_len);
                    ret = ((TCPSocket*)_socket)->send(d,d_len);
                    free(d);
                }else {
                    ret = ((UDPSocket*)_socket)->sendto(*_socket_address,data, data_len);
                }
                if (ret==-1) {
                    //tr_debug("M2MConnectionHandlerPimpl::send_data - Error Code is %d\n",errno);
                    _observer.socket_error(1);
                } else {
                     success = true;
                    _observer.data_sent();
                }
            } else {
                //TODO: Define memory fail error code
                _observer.socket_error(3);
            }
        }
    }
    return success;
}

bool M2MConnectionHandlerPimpl::start_listening_for_data()
{
    _listening = true;
    _listen_thread = rtos::create_thread<
        M2MConnectionHandlerPimpl,
        &M2MConnectionHandlerPimpl::listen_handler>(this);
    return true;
}

void M2MConnectionHandlerPimpl::stop_listening()
{
    _listening = false;
    _running = false;
}

void M2MConnectionHandlerPimpl::listen_handler()
{
    tr_debug("M2MConnectionHandlerPimpl::listen_handler");
    memset(_recv_buffer, 0, sizeof(_recv_buffer));
    int rcv_size = -1;

    if (_use_secure_connection) {
        while(_listening){
             rcv_size = _security_impl->read(_recv_buffer, sizeof(_recv_buffer));
            if(rcv_size > 0) {
                _observer.data_available(_recv_buffer, rcv_size, _address);
            }
            else if(rcv_size == 0){
                //We are in initializing phase, so do nothing
            }
            else{
                _listening = false;
                _running = false;
                _observer.socket_error(1);
            }
            memset(_recv_buffer, 0, sizeof(_recv_buffer));
        }
    } else {
        while(_listening) {
            int rcv_size = -1;
            if(_binding_mode == M2MInterface::TCP ||
               _binding_mode == M2MInterface::TCP_QUEUE) {
                 rcv_size = ((TCPSocket*)_socket)->recv((char*)_recv_buffer, sizeof _recv_buffer);
            } else {
                rcv_size = ((UDPSocket*)_socket)->recvfrom(NULL,(char*)_recv_buffer, sizeof _recv_buffer);
            }
            if (rcv_size == -1) {
               //TODO: Define receive error code
                _observer.socket_error(2);
                _listening = false;
                _running = false;
            }

            /* If message received.. */
            if(rcv_size > 0) {
                if(_binding_mode == M2MInterface::TCP ||
                   _binding_mode == M2MInterface::TCP_QUEUE){
                    //We need to "shim" out the length from the front
                    if( rcv_size > 4 ){
                        uint64_t len = (_recv_buffer[0] << 24 & 0xFF000000) + (_recv_buffer[1] << 16 & 0xFF0000);
                        len += (_recv_buffer[2] << 8 & 0xFF00) + (_recv_buffer[3] & 0xFF);
                        uint8_t* buf = (uint8_t*)malloc(len);
                        memmove(buf, _recv_buffer+4, len);
                        _observer.data_available(buf, len, _address);
                        free(buf);
                    }else{
                        _observer.socket_error(2);
                        _listening = false;
                        _running = false;
                    }
                }else{
                _observer.data_available(_recv_buffer,rcv_size,_address);
                }
            }
            memset(_recv_buffer, 0, sizeof(_recv_buffer));
        }
    }
}

int M2MConnectionHandlerPimpl::send_to_socket(const unsigned char *buf, size_t len)
{
    tr_debug("M2MConnectionHandlerPimpl::send_to_socket len - %d", len);
    int size = -1;
    if(_binding_mode == M2MInterface::TCP ||
       _binding_mode == M2MInterface::TCP_QUEUE) {
        size = ((TCPSocket*)_socket)->send(buf,len);
    } else {
        size = ((UDPSocket*)_socket)->sendto(*_socket_address,buf,len);
    }
    tr_debug("M2MConnectionHandlerPimpl::send_to_socket size - %d", size);
    return size;
}

int M2MConnectionHandlerPimpl::receive_from_socket(unsigned char *buf, size_t len,uint32_t timeout)
{
    tr_debug("M2MConnectionHandlerPimpl::receive_from_socket - blocking call");
    int recv = -1;
    if(_use_secure_connection ||
       _binding_mode == M2MInterface::TCP ||
       _binding_mode == M2MInterface::TCP_QUEUE) {
        recv = ((TCPSocket*)_socket)->recv(buf, len);
    } else {
        tr_debug("M2MConnectionHandlerPimpl::receive_from_socket timeout value %ld", timeout);
        _socket->set_timeout(timeout);
        recv = ((UDPSocket*)_socket)->recvfrom(NULL,buf, len);
        if(NSAPI_ERROR_WOULD_BLOCK == recv) {
            recv = -0x6800; //MBED_TLS_SSL_TIMEOUT error code
        }
    }
    return recv;
}

void M2MConnectionHandlerPimpl::handle_connection_error(int /*error*/)
{
    tr_debug("M2MConnectionHandlerPimpl::handle_connection_error");
    _observer.socket_error(4);
}

void M2MConnectionHandlerPimpl::set_platform_network_handler(void *handler)
{
    tr_debug("M2MConnectionHandlerPimpl::set_platform_network_handler");
    _network_interface = (NetworkStack*)handler;
}
