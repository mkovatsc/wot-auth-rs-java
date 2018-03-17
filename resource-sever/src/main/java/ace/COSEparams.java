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
package ace;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.MessageTag;

/**
 * General parameters of a COSE Message (i.e. not including message specific
 * ones like key and IV).
 * 
 * @author Ludwig Seitz
 *
 */
public class COSEparams {
    
    /**
     * Identifies the type of COSE message
     */
    private MessageTag tag;
    
    /**
     * Identifies the main algorithm
     */
    private AlgorithmID alg;
    
    /**
     * Identifies the key wrapping method
     */
    private AlgorithmID keyWrap;
    
    
    /**
     * Constructor.
     * 
     * @param tag  the message type (MAC, MAC0, Sign1, Sign, ...)
     * @param alg  the main algorithm (HMAC_SHA_256, AES_CCM_16_64_128, ...)
     * @param keyWrap  the key wrap algorithm (Direct, AES_KW_128, ...)
     */
    public COSEparams(MessageTag tag, AlgorithmID alg, AlgorithmID keyWrap) {
        this.tag = tag;
        this.alg = alg;
        this.keyWrap = keyWrap;
    }

    /**
     * @return  the message type (MAC, MAC0, Sign1, Sign, ...)
     */
    public MessageTag getTag() {
        return this.tag;
    }

    /**
     * @return   the main algorithm (HMAC_SHA_256, AES_CCM_16_64_128, ...)
     */
    public AlgorithmID getAlg() {
        return this.alg;
    }


    /**
     * @return  the key wrap algorithm (Direct, AES_KW_128, ...)
     */
    public AlgorithmID getKeyWrap() {
        return this.keyWrap;
    }
    
    @Override
    public String toString() {
        return new String(this.tag.value + ":" + this.alg.AsCBOR().AsInt32() 
                + ":" + this.keyWrap.AsCBOR().AsInt16());
    }
    
    /**
     * Parse an encoded set of COSE message parameters.
     * 
     * @param encoded  the encoded String.
     * @return  the parsed parameter object
     * @throws NumberFormatException
     * @throws CoseException
     */
    public static COSEparams parse(String encoded) 
                throws NumberFormatException, CoseException {
        String[] params = encoded.split(":");
        if (params.length != 3) {
            throw new IllegalArgumentException(
                    "Not an encoded set of COSE message parameters");
        }
        return new COSEparams(
                MessageTag.FromInt(Integer.valueOf(params[0])),
                AlgorithmID.FromCBOR(CBORObject.FromObject(
                        Integer.valueOf(params[1]))),
                AlgorithmID.FromCBOR(CBORObject.FromObject(
                        Integer.valueOf(params[2]))));
                
    }
    
    @Override
    public boolean equals(Object cose) {
        if (cose instanceof COSEparams) {
            COSEparams foo = (COSEparams)cose;
            if (this.tag.value != foo.tag.value) {
                return false;
            }
            if (this.alg.compareTo(foo.alg) != 0) {
                return false;
            }
            if (this.keyWrap.compareTo(foo.keyWrap) != 0) {
                return false;
            }
            return true;
        }
        return false;
    }

    @Override
    public int hashCode() {
        return 10000*this.tag.value + 100*this.alg.AsCBOR().AsInt32() 
                + this.keyWrap.AsCBOR().AsInt32();
    }
    
}
