package utility;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.logging.Level;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.ScandiumLogger;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.pskstore.InMemoryPskStore;

import COSE.CoseException;
import coap.BksStore;
import exception.AceException;

public class ACESecurityLayer {

//	static {
//		ScandiumLogger.initialize();
//		ScandiumLogger.setLevel(Level.ALL);
//	}
	
	static byte[] key256 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,28, 29, 30, 31, 32};
    static String aKey = "piJYICg7PY0o/6Wf5ctUBBKnUPqN+jT22mm82mhADWecE0foI1ghAKQ7qn7SL/Jpm6YspJmTWbFG8GWpXE5GAXzSXrialK0pAyYBAiFYIBLW6MTSj4MRClfSUzc8rVLwG8RH5Ak1QfZDs4XhecEQIAE=";
    static String keystoreLocation = "keystore.bks";
    static String keystorePwd = "password";
    
	public static final int DTLS_PORT = CoAP.DEFAULT_COAP_SECURE_PORT;
	private DTLSConnector dtlsConnector;
	public InMemoryPskStore pskStore;
	
	public ACESecurityLayer(byte[] pskey, String identity, int port) throws AceException, CoseException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException{

//		DtlsConnectorConfig.Builder config = new DtlsConnectorConfig.Builder(new InetSocketAddress(DTLS_PORT));
		DtlsConnectorConfig.Builder config = new DtlsConnectorConfig.Builder(new InetSocketAddress(port));

//		BksStore.init(keystoreLocation, keystorePwd,"addr2id.cfg");
//		BksStore keyStore = new BksStore(keystoreLocation, keystorePwd,"addr2id.cfg");
//		keyStore.addKey(pskey, identity, keystorePwd);
		InMemoryPskStore pskStore = new InMemoryPskStore();
		pskStore.setKey(identity, pskey);
		config.setPskStore(pskStore);
		dtlsConnector = new DTLSConnector(config.build());
	}
	public ACESecurityLayer() throws AceException, CoseException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException{

//		DtlsConnectorConfig.Builder config = new DtlsConnectorConfig.Builder(new InetSocketAddress(DTLS_PORT));
		DtlsConnectorConfig.Builder config = new DtlsConnectorConfig.Builder(new InetSocketAddress(5686));

//		BksStore.init(keystoreLocation, keystorePwd,"addr2id.cfg");
//		BksStore keyStore = new BksStore(keystoreLocation, keystorePwd,"addr2id.cfg");
//		keyStore.addKey(pskey, identity, keystorePwd);
		this.pskStore = new InMemoryPskStore();
		config.setPskStore(pskStore);
		dtlsConnector = new DTLSConnector(config.build());
	}
	
	public Connector getSecurityLayer() {
		return this.dtlsConnector;
	}
	
	public InMemoryPskStore getPskStore() {
		return this.pskStore;
	}
}
