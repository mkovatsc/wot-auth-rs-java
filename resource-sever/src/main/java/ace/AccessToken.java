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

import exception.AceException;

/**
 * An interface with methods that access tokens need to implement.
 *  
 * @author Ludwig Seitz
 *
 */
public interface AccessToken {

	/**
	 * Checks if the token is expired at the given time
	 * 
	 * @param now  the time for which the expiry should be checked
	 * 
	 * @return  true if the token is expired, false if it is still valid
	 * @throws AceException 
	 */
	public boolean expired(long now) throws AceException;
	
	/**
	 * Checks if the token is still valid (including expiration).
	 * Note that this method may need to perform introspection.
	 * 
	 * @param now  the time for which validity should be checked
	 * 
	 * @return  true if the token is valid, false if it is invalid
	 * @throws AceException 
	 */
	public boolean isValid(long now) throws AceException;
	
	
	/**
	 * Encodes this Access Token as a CBOR Object.
	 * 
	 * @return  the encoding of the token.
	 */
	public CBORObject encode();
	
	/**
	 * @return  the string representation of the cti by Base64 encoding it
	 * 
	 * @throws AceException  if the token has no cti
	 */
	public String getCti() throws AceException;
	
}
