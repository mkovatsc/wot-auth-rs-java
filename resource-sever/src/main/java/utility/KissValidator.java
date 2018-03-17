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
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import ace.AceException;
import utility.AudienceValidator;
import utility.ScopeValidator;

/**
 * Simple audience and scope validator for testing purposes.
 * 
 * @author Ludwig Seitz
 *
 */
public class KissValidator implements AudienceValidator, ScopeValidator {

	private Set<String> myAudiences;
	
	/**
	 * Maps the scopes to a map that maps the scope's resources to the actions 
	 * allowed on that resource
	 */
	private Map<String, Map<String, Set<String>>> myScopes;  
	
	/**
	 * Constructor.
	 * 
	 * @param myAudiences  the audiences that this validator should accept
	 * @param myScopes  the scopes that this validator should accept
	 */
	public KissValidator(Set<String> myAudiences, 
	        Map<String, Map<String, Set<String>>> myScopes) {
		this.myAudiences = new HashSet<>();
		this.myScopes = new HashMap<>();
		this.myAudiences.addAll(myAudiences);
		this.myScopes.putAll(myScopes);
	}
	
	@Override
	public boolean match(String aud) {
		return this.myAudiences.contains(aud);
	}

    @Override
    public boolean scopeMatch(String scope, String resourceId, String actionId)
            throws AceException {
        Map<String, Set<String>> resources = this.myScopes.get(scope);
        if (resources == null) {
            return false;
        }
        if (resources.containsKey(resourceId)) {
            return resources.get(resourceId).contains(actionId);
        }
        return false;
    }

    @Override
    public boolean scopeMatchResource(String scope, String resourceId)
            throws AceException {
        Map<String, Set<String>> resources = this.myScopes.get(scope);
        if (resources == null) {
            return false;
        }
        return resources.containsKey(resourceId);
    }
}
