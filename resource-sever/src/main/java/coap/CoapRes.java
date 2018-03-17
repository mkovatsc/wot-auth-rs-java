/*******************************************************************************
 * Copyright (c) 2017, RISE SICS AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/
package coap;


import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Response;

import com.upokecenter.cbor.CBORObject;

import ace.Constants;
import ace.Message;

/**
 * A CoAP request implementing the Message interface for the ACE library.
 * 
 * @author Ludwig Seitz
 *
 */
public class CoapRes implements Message {
    
    /**
     * The parameters in the payload of this message as a Map for convenience.
     * This is null if the payload is empty or not a CBOR Map.
     */
    private Map<Short, CBORObject> parameters = null;
    
    
    /**
     * The underlying CoAP response from Californium.
     */
    private Response response;
    
    /**
     * Constructor
     * 
     * @param code  the response code
     * @param payload  the response payload, may be null
     */
    public CoapRes(ResponseCode code, CBORObject payload) {
        this.response = new Response(code);
        if (payload != null) {
            this.response.setPayload(payload.EncodeToBytes());
        }
    }

    /**
     * Constructor
     * 
     * @param code  the response code
     * @param parameters  the response parameters
     */
    public CoapRes(ResponseCode code,
            Map<Short, CBORObject> parameters) {
        this.response = new Response(code);
        this.parameters = new HashMap<>();
        this.parameters.putAll(parameters);
        CBORObject payload = Constants.getCBOR(this.parameters);
        this.response.setPayload(payload.EncodeToBytes());   
    }
    
    @Override
    public byte[] getRawPayload() {
        return this.response.getPayload();
    }

    @Override
    public String getSenderId() {
        return null;
    }

    @Override
    public Set<Short> getParameterNames() {
        if (this.parameters != null) {
            return this.parameters.keySet();
        }
        return null;
    }

    @Override
    public CBORObject getParameter(Short name) {
        if (this.parameters != null) {
            return this.parameters.get(name);
        }
        return null;
    }

    @Override
    public Map<Short, CBORObject> getParameters() {
        if (this.parameters != null) {
            Map<Short, CBORObject> map = new HashMap<>();
            map.putAll(this.parameters);
            return map;
        }
        return null;
    }

    @Override
    public Message successReply(int code, CBORObject payload) {
        return null; //We don't generate a response to a response
    }

    @Override
    public Message failReply(int failureReason, CBORObject payload) {
        return null; //We don't generate a response to a response
    }

    @Override
    public int getMessageCode() {
        return this.response.getCode().value;
    }
    
    /**
     * @return  the response code as a <code>ResponseCode</code> instance
     */
    public ResponseCode getCode() {
        return this.response.getCode();
    }

}
