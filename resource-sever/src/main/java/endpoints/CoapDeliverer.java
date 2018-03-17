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
package endpoints;

import java.io.Closeable;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.core.server.ServerMessageDeliverer;
import org.eclipse.californium.core.server.resources.Resource;

import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import COSE.KeyKeys;

import ace.AceException;
import ace.Constants;
import utility.KissTime;
import utility.AsInfo;
import exception.IntrospectionException;
import utility.IntrospectionHandler;
import utility.TokenRepository;

/**
 * This deliverer processes incoming and outgoing messages at the RS 
 * according to the specifications of the ACE framework 
 * (draft-ietf-ace-oauth-authz) and the DTLS profile of that framework
 * (draft-ietf-ace-dtls-authorize).
 * 
 * It's specific task is to match requests against existing access tokens
 * to see if the request is authorized.
 * 
 * @author Ludwig Seitz
 *
 */
public class CoapDeliverer implements MessageDeliverer, Closeable {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(CoapDeliverer.class.getName());
    
    /**
     * The token repository
     */
    private TokenRepository tr;
    
    /**
     * The introspection handler
     */
    private IntrospectionHandler i;
    
    /**
     * The AS information message sent back to unauthorized requesters
     */
    private AsInfo asInfo;
  
    /**
     * The ServerMessageDeliverer that processes the request
     * after access control has been done
     */
    private ServerMessageDeliverer d;
    

    /**
     * Constructor. 
     * @param root  the root of the resources that this deliverer controls
     * @param tr  the token repository.
     * @param i  the introspection handler or null if there isn't any.
     * @param asInfo  the AS information to send for client authz errors.
     */
    public CoapDeliverer(Resource root, TokenRepository tr, 
            IntrospectionHandler i, AsInfo asInfo) {
        this.d = new ServerMessageDeliverer(root);
        this.tr = tr;
        this.asInfo = asInfo;
    }
    
    @Override
    public void deliverRequest(final Exchange ex) {
        Request request = ex.getCurrentRequest();
        Response r = null;
        //authz-info is not under access control
        try {
            URI uri = new URI(request.getURI());
            //Need to check with and without trailing / in case there are query options
            if (uri.getPath().endsWith("/authz-info") || uri.getPath().endsWith("/authz-info/") ) { 
                this.d.deliverRequest(ex);
                return;
            }
        } catch (URISyntaxException e) {
            LOGGER.warning("Request-uri " + request.getURI()
                    + " is invalid: " + e.getMessage());
            r = new Response(ResponseCode.BAD_REQUEST);
            ex.sendResponse(r);
            return;
        }      
       
        if (request.getSenderIdentity() == null) {
            LOGGER.warning("Unauthenticated client tried to get access");
            r = new Response(ResponseCode.UNAUTHORIZED);
            r.setPayload(this.asInfo.getCBOR().EncodeToBytes());
            ex.sendResponse(r);
            return;
        }
        String subject = request.getSenderIdentity().getName();

        String kid = this.tr.getKid(subject);
        if (kid == null) {//Check if this was the Base64 encoded kid map
            try {
                CBORObject cbor = CBORObject.DecodeFromBytes(
                        Base64.getDecoder().decode(subject));
                if (cbor.getType().equals(CBORType.Map)) {
                   CBORObject ckid = cbor.get(KeyKeys.KeyId.AsCBOR());
                   if (ckid != null && ckid.getType().equals(
                           CBORType.ByteString)) {
                      kid = Base64.getEncoder().encodeToString(
                              ckid.GetByteString());
                   } else { //No kid in that CBOR map or it isn't a bstr
                       failUnauthz(ex);
                       return;
                   }
                } else {//Some weird CBOR that is not a map here
                   failUnauthz(ex);
                   return;
                }                
            } catch (CBORException e) {//Really no kid found for that subject
                LOGGER.finest("Error while trying to parse some "
                        + "subject identity to CBOR: " + e.getMessage());
               failUnauthz(ex);
               return;
            } catch (IllegalArgumentException e) {//Text was not Base64 encoded
                LOGGER.finest("Error: " + e.getMessage() 
                + " while trying to Base64 decode this: " + subject);
                failUnauthz(ex);
                return;
            }
           
        }
               
        String resource = request.getOptions().getUriPathString();
        String action = request.getCode().toString();  
      
        try {
            int res = this.tr.canAccess(kid, subject, resource, action, 
                    new KissTime(), this.i);
            switch (res) {
            case TokenRepository.OK :
                this.d.deliverRequest(ex);
                return;
            case TokenRepository.UNAUTHZ :
               failUnauthz(ex);
               return;
            case TokenRepository.FORBID :
                r = new Response(ResponseCode.FORBIDDEN);
                r.setPayload(this.asInfo.getCBOR().EncodeToBytes());
                ex.sendResponse(r);
                return;
            case TokenRepository.METHODNA :
                r = new Response(ResponseCode.METHOD_NOT_ALLOWED);
                r.setPayload(this.asInfo.getCBOR().EncodeToBytes());
                ex.sendResponse(r);
                return;
            default :
                LOGGER.severe("Error during scope evaluation,"
                        + " unknown result: " + res);
               ex.sendResponse(new Response(
                       ResponseCode.INTERNAL_SERVER_ERROR));
               return;
            }
        } catch (AceException e) {
            LOGGER.severe("Error in DTLSProfileInterceptor.receiveRequest(): "
                    + e.getMessage());    
        } catch (IntrospectionException e) {
            LOGGER.info("Introspection error, "
                    + "message processing aborted: " + e.getMessage());
           if (e.getMessage().isEmpty()) {
               ex.sendResponse(new Response(
                       ResponseCode.INTERNAL_SERVER_ERROR));
           }
           CBORObject map = CBORObject.NewMap();
           map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
           map.Add(Constants.ERROR_DESCRIPTION, e.getMessage());
           r = new Response(ResponseCode.BAD_REQUEST);
           r.setPayload(map.EncodeToBytes());
           ex.sendResponse(r);
        }
    }
    
    /**
     * Fail a request with 4.01 Unauthorized.
     * 
     * @param ex  the exchange
     */
    private void failUnauthz(final Exchange ex) {
        Response r = new Response(ResponseCode.UNAUTHORIZED);
        r.setPayload(this.asInfo.getCBOR().EncodeToBytes());
        ex.sendResponse(r);
    }

    @Override
    public void deliverResponse(Exchange exchange, Response response) {
        this.d.deliverResponse(exchange, response);        
    }

    @Override
    public void close() throws IOException {
        try {
            this.tr.close();
        } catch (AceException e) {
            LOGGER.severe("Error while trying to close token repository: " 
                    + e.getMessage());
        }        
    }
}
