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
package utility;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import exception.AceException;
import ace.Constants;
import ace.Message;

/**
 * A testing class implementing a dummy message. 
 * 
 * @author Ludwig Seitz
 *
 */
public class LocalMessage implements Message {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(LocalMessage.class.getName() );
    
    /**
     * The authenticated id of the sender
     */
    private String senderId;
    
    /**
     * The id of the recipient of this message (for reply messages)
     */
    private String recipientId;
    
    /**
     * The parameters contained in the payload of this message
     */
    private Map<Short, CBORObject> params;
    
    /**
     * The payload of the message when it is not a Map
     */
    private CBORObject payload;
    
    /**
     * The request or response code
     */
    private int code;
    
    /**
     * Constructor.
     * @param code 
     * @param senderId
     * @param recipientId 
     * @param parameters
     */
    public LocalMessage(int code, String senderId, 
            String recipientId, Map<Short, CBORObject> parameters) {
        this.code = code;
        this.senderId = senderId;
        this.recipientId = recipientId;
        this.params = new HashMap<>();
        this.params.putAll(parameters);
        this.payload = null;
    }

    /**
     * Constructor.
     * @param code 
     * @param senderId
     * @param recipientId 
     * @param payload
     * @throws AceException 
     */
    public LocalMessage(int code, String senderId, 
            String recipientId, CBORObject payload) {
        this.code = code;
        this.senderId = senderId;
        this.recipientId = recipientId;
        this.params = null;
        this.payload = payload;

        if (payload != null && payload.getType().equals(CBORType.Map)) {
            try {
                this.params = Constants.getParams(payload);
            } catch (AceException e) {
                LOGGER.severe(e.getMessage());
                this.params = null;
            }
        }
    }
    
    
    @Override
    public Message successReply(int code, CBORObject payload) {
        return new LocalMessage(
                code, this.recipientId, this.senderId, payload);
    }

    @Override
    public Message failReply(int failureReason, CBORObject payload) {
        return new LocalMessage(
                failureReason, this.recipientId, this.senderId, payload);
    }


    @Override
    public byte[] getRawPayload() {
       return (this.payload == null) 
               ? null : this.payload.EncodeToBytes();
    }


    @Override
    public String getSenderId() {
        return this.senderId;
    }


    @Override
    public Set<Short> getParameterNames() {
        return (this.params == null) 
                ? null : this.params.keySet();
    }


    @Override
    public CBORObject getParameter(Short name) {
        return (this.params == null) 
                ? null : this.params.get(name);
    }


    @Override
    public Map<Short, CBORObject> getParameters() {
        if (this.params == null) {
            return null;
        }
        HashMap<Short, CBORObject> ret = new HashMap<>();
       ret.putAll(this.params);
       return ret;
    }

    @Override
    public int getMessageCode() {
        return this.code;
    }
    
    @Override
    public String toString() {
        if (this.payload == null && this.params == null) {
            return "SenderId: " + this.senderId;
        }
        return "SenderId: " + this.senderId + " Parameters: "
                + ((this.params == null)? 
                        this.payload.toString() : this.params.toString());
    }
 }
