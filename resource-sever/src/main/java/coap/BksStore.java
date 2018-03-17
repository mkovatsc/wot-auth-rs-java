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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.scandium.dtls.pskstore.PskStore;

/**
 * A PskStore implementation based on BKS.
 * 
 * This will retrieve keys from a BKS keystore.
 * 
 * @author Ludwig Seitz
 *
 */
public class BksStore implements PskStore {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(BksStore.class.getName());

    /**
     * The underlying BKS keystore
     */
    private KeyStore keystore = null;
    
    /**
     * The temporary variable to store a key password
     */
    private String keyPwd = null;
    
    /**
     * The temporary variable to store a key identity
     */
    private String keyId = null;
    
    /**
     * The in-memory map of addresses to identities
     */
    private Map<InetSocketAddress, String> addr2id = new HashMap<>();
    
    static {
        Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
    
    /**
     * Constructor.
     * 
     * @param keystoreLocation  the location of the keystore file
     * @param keystorePwd the password to the keystore
     * @param addr2idFile  the location of the file mapping addresses to identities
     * 
     * @throws IOException 
     * @throws CertificateException 
     * @throws NoSuchAlgorithmException 
     * @throws KeyStoreException 
     * @throws NoSuchProviderException 
     */
    public BksStore(String keystoreLocation, String keystorePwd, String addr2idFile) 
            throws NoSuchAlgorithmException, CertificateException, 
            IOException, KeyStoreException, NoSuchProviderException {

        InputStream keystoreStream = new FileInputStream(keystoreLocation);
        this.keystore = KeyStore.getInstance("BKS", "BC");
        this.keystore.load(keystoreStream, keystorePwd.toCharArray());
        keystoreStream.close();   
        BufferedReader in = new BufferedReader(new FileReader(addr2idFile));
        String line = "";
        while ((line = in.readLine()) != null) {
            String parts[] = line.split(":");
            this.addr2id.put(InetSocketAddress.createUnresolved(parts[0].trim(), 
                    Integer.parseInt(parts[1])), parts[2].trim());
        }
        in.close();
    }
    
    /**
     * Create the initial keystore and address2identity mapping file.
     * 
     * @param keystoreLocation  the location of the keystore file
     * @param keystorePwd the password to the keystore
     * @param addr2idFile  the location of the file mapping addresses to identities
     * 
     * @throws NoSuchProviderException 
     * @throws KeyStoreException 
     * @throws IOException 
     * @throws FileNotFoundException 
     * @throws CertificateException 
     * @throws NoSuchAlgorithmException 
     */
    public static void init(String keystoreLocation, String keystorePwd,
            String addr2idFile) throws KeyStoreException, 
            NoSuchProviderException, NoSuchAlgorithmException, 
            CertificateException, FileNotFoundException, IOException {
        KeyStore keyStore = KeyStore.getInstance("BKS", "BC");
        keyStore.load(null, keystorePwd.toCharArray());
        FileOutputStream fo = new FileOutputStream(keystoreLocation);
        keyStore.store(fo, keystorePwd.toCharArray());
        fo.close();   
        File file = new File(addr2idFile);
        file.createNewFile();        
    }
    
    
    /**
     * Set a key password for a certain key identity.
     * This method needs to be called before any calls to getKey() and
     * getIdentity().
     * 
     * @param identity  
     * @param keyPwd
     */
    public void setKeyPass(String identity, String keyPwd) {
        this.keyPwd = keyPwd;
        this.keyId = identity;
    }

    @Override
    public byte[] getKey(String identity) {
        if (this.keyPwd == null || this.keyId == null) {
            return null;
        }
        try {
            if (!this.keystore.containsAlias(identity)) {
                return null;
            }
        } catch (KeyStoreException e) {
            LOGGER.severe("KeyStoreException: " + e.getMessage());
            return null;
        }

        Key key;
        try {
            key = this.keystore.getKey(identity, this.keyPwd.toCharArray());
        } catch (UnrecoverableKeyException | KeyStoreException
                | NoSuchAlgorithmException e) {
            LOGGER.severe(e.getClass().getName() + ": " + e.getMessage());
            return null;
        }
        return key.getEncoded();
    }

    @Override
    public String getIdentity(InetSocketAddress inetAddress) {
        return this.addr2id.get(inetAddress);
                
    }
    
    /**
     * Add a new symmetric key to the keystore or overwrite the existing
     * one associated to this identity.
     * 
     * @param key  the bytes of java.security.Key.getEncoded()
     * @param identity  the key identity
     * @param password  the password to protect this key entry
     * @throws KeyStoreException 
     */
    public void addKey(byte[] key, String identity, String password) throws KeyStoreException {
        if (identity == null || key == null) {
            throw new KeyStoreException("Key and identity must not be null");
        }
        if (this.keystore != null) {
            Key k = new SecretKeySpec(key, "");
            this.keystore.setKeyEntry(identity, k, password.toCharArray(), null);
        }
    }
    
    /**
     * Checks if a key for a certain identity is present.
     * 
     * @param identity  the key identity
     * 
     * @return  true if the identity is in the keystore, false otherwise
     * 
     * @throws KeyStoreException 
     */
    public boolean hasKey(String identity) throws KeyStoreException {
        if (identity != null) {
            if (this.keystore != null) {
                return this.keystore.isKeyEntry(identity);
            }
            throw new KeyStoreException("No keystore loaded");
        }
        throw new KeyStoreException("Key identity can not be null");
    }
    
    /**
     * Remove a symmetric key from the keystore, will do nothing if the
     * key doesn't exist.
     * 
     * @param identity  the key identity
     * @throws KeyStoreException 
     */
    public void removeKey(String identity) throws KeyStoreException {
        if (identity != null) {
            if (this.keystore != null) {
                if (this.keystore.isKeyEntry(identity)) {
                    this.keystore.deleteEntry(identity);
                }
                return;
            }
            throw new KeyStoreException("No keystore loaded");
        }
        throw new KeyStoreException("Key identity can not be null");
    }
    
    

}
