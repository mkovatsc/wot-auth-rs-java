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

import java.util.Arrays;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import exception.AceException;

/**
 * This datastructure contains the information the RS returns to a client in 
 * response to an unauthorized request (regardless of whether it was 4.01, 
 * 4.03 or 4.05).
 * 
 * @author Ludwig Seitz
 *
 */
public class AsInfo {

    /**
     * The nonce for replay protection
     */
    private byte[] nonce;
    
    /**
     * The absolute URI of the AS
     */
    private String asUri;
    
    
    /**
     * The CBOR abbreviation for "AS"
     */
    private static CBORObject AS = CBORObject.FromObject(0);
    
    /**
     * The CBOR abbreviation for "nonce"
     */
    private static CBORObject NONCE = CBORObject.FromObject(5);
    
    /**
     * Constructor with nonce.
     * 
     * @param asUri  the absolute URI of the AS
     * @param nonce  the nonce for time synchronization
     */
    public AsInfo(String asUri, byte[] nonce) {
        if (asUri == null || asUri.isEmpty()) {
            throw new IllegalArgumentException(
                    "Cannot create an DTLSProfileAsInfo object "
                    + "with null or empty asUri field");
        }
        this.asUri = asUri;
        if (nonce != null) {
            this.nonce = Arrays.copyOf(nonce, nonce.length);
        }
    }
    
    /**
     * Constructor without a nonce.
     * 
     * @param asUri  the absolute URI of the AS
     */
    public AsInfo(String asUri) {
        this(asUri, null);
    }

    /** 
     * @return  the nonce associated with this AS information or null
     * if there is none
     */
    public byte[] getNonce() {
        return this.nonce;
    }

    /**
     * @return  the absolute URI of the AS
     */
    public String getAsUri() {
        return this.asUri;
    }
    
    /**
     * @return  the CBOR encoding of this AS info
     */
    public CBORObject getCBOR() {
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(AS, this.asUri);
        if (this.nonce != null) {
            cbor.Add(NONCE, this.nonce);
        }
        return cbor;
    }
    
    /**
     * Parse the raw bytes of an AS info.
     * 
     * @param raw  the raw bytes
     * 
     * @return  the resulting DTLSProfileAsInfo object
     * @throws AceException 
     */
    public static AsInfo parse(byte[] raw) throws AceException {
       CBORObject cbor = CBORObject.DecodeFromBytes(raw);
       if (!cbor.getType().equals(CBORType.Map)) {
           throw new AceException("Malformed AS-info object");
       }
       CBORObject asC = cbor.get(AS);
       if (asC == null || !asC.getType().equals(CBORType.TextString)) {
           throw new AceException("Malformed AS-info object");
       }
       String asUri = asC.AsString();
       CBORObject nonceC = cbor.get(NONCE);
       byte[] nonce = null;
       if (nonceC != null) {
           if (!nonceC.getType().equals(CBORType.ByteString)) {
               throw new AceException("Malformed AS-info object");
           }
           nonce = nonceC.GetByteString();
       }
       return new AsInfo(asUri, nonce);
    }

}
