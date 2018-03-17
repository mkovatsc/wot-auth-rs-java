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

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;

import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import ace.Constants;
import ace.Message;
import exception.AceException;

/**
 * A CoAP request implementing the Message interface for the ACE library.
 * 
 * @author Ludwig Seitz
 *
 */
public class CoapReq implements Message {

    /**
     * The parameters in the payload of this message as a Map for convenience,
     * if the payload is a CBOR Map.
     */
    private Map<Short, CBORObject> parameters;
    
    /**
     * The underlying Request from Californium
     */
    private Request request;
    
    
    /**
     * Create a request from an underlying Californium request.
     * Payload if any MUST be in CBOR.
     * 
     * @param req  the underlying Californium request
     * @throws AceException 
     */
    protected CoapReq(Request req) throws AceException {
        this.request = req;
        CBORObject cborPayload = null;
        if (req.getPayload() != null) {
            try {
                cborPayload = CBORObject.DecodeFromBytes(req.getPayload());
            } catch (CBORException ex) {
                throw new AceException(ex.getMessage());
            }
            if (cborPayload != null 
                    && cborPayload.getType().equals(CBORType.Map)) {
                this.parameters = Constants.getParams(cborPayload);
            }
        }
    }
    

    @Override
    public byte[] getRawPayload() {
        return this.request.getPayload();
    }

    @Override
    public String getSenderId() {
        Principal p = this.request.getSenderIdentity();
        if (p==null) {
            return null;
        }
        return p.getName();
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
        ResponseCode coapCode = null;
        switch (code) {
        case Message.CREATED :
            coapCode = ResponseCode.CREATED;
            break;
        default:
            coapCode = ResponseCode._UNKNOWN_SUCCESS_CODE;
            break;
        }
        CoapRes res = new CoapRes(coapCode, payload);
        
        return res;
    }

    @Override
    public Message failReply(int failureReason, CBORObject payload) {
        ResponseCode coapCode = null;
        switch (failureReason) {
        case Message.FAIL_UNAUTHORIZED :
            coapCode = ResponseCode.UNAUTHORIZED;
            break;
        case Message.FAIL_BAD_REQUEST :
            coapCode = ResponseCode.BAD_REQUEST;
            break;
        case Message.FAIL_FORBIDDEN :
            coapCode = ResponseCode.FORBIDDEN;
            break;
        case Message.FAIL_INTERNAL_SERVER_ERROR :
            coapCode = ResponseCode.INTERNAL_SERVER_ERROR;
            break;
        case Message.FAIL_NOT_IMPLEMENTED :
            coapCode = ResponseCode.NOT_IMPLEMENTED;
            break; 
        default :
        }
        CoapRes res = new CoapRes(coapCode, payload);
        return res;
    }
    
    /**
     * Create a CoAPRequest from a Californium <code>Request</code>.
     * 
     * @param req  the Californium Request
     * @return  the ACE CoAP request
     * @throws AceException 
     */
    public static CoapReq getInstance(Request req) throws AceException {
        return new CoapReq(req);
    }

    @Override
    public int getMessageCode() {
        return this.request.getCode().value;
    }
}
