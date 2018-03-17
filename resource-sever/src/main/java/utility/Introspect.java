package utility;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.logging.Level;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.ScandiumLogger;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;

import com.upokecenter.cbor.CBORObject;

import COSE.CoseException;
import ace.Constants;
import ace.Message;
import exception.AceException;

public class Introspect {
	
	static {
		ScandiumLogger.initialize();
		ScandiumLogger.setLevel(Level.FINE);
	}
	
	private static final String SERVER_URI_INTROSPECT_AS = "coaps://localhost:5684/introspect";
//	private static final String SERVER_URI_INTROSPECT_AS = "coaps://192.168.1.15:5684/introspect";

	private static final String PSKEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
//	private static final String PSKEY = "azertyuiopmlkjhgfdsqwxcvbnazerty";	
//	private static final String IDENTITY = "RS1";
	private static final String IDENTITY = "rs1";

	private DTLSConnector dtlsConnector;
	
	public Introspect() throws CoseException {
        
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(new InetSocketAddress(0));
        builder.setPskStore(new StaticPskStore(IDENTITY, PSKEY.getBytes()));
        
        dtlsConnector = new DTLSConnector(builder.build());
	}
	
	public Map<Short, CBORObject> introspectToken(Message msg) throws AceException, InterruptedException, IOException {
		
		CoapResponse response = null;
		try {
			System.out.println(msg.getRawPayload());
			//URI uri = new URI(SERVER_URI_RS);
			URI uri = new URI(SERVER_URI_INTROSPECT_AS);
			CoapClient client = new CoapClient(uri);
			client.setEndpoint(new CoapEndpoint(dtlsConnector, NetworkConfig.getStandard()));
			dtlsConnector.start();
			
			response = client.post(msg.getRawPayload(), MediaTypeRegistry.APPLICATION_CBOR);
			//response = client.get();
		} catch (URISyntaxException e) {
			System.err.println("Invalid URI: " + e.getMessage());
			System.exit(-1);
		}
		
		if (response != null) {

			System.out.println(response.getCode());
			System.out.println(response.getOptions());
			System.out.println(response.getResponseText());

			System.out.println("\nADVANCED\n");
			System.out.println(Utils.prettyPrint(response));

		} else {
			System.out.println("No response received.");
		}
		
		CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
        Map<Short, CBORObject> map = Constants.getParams(res);
        return map;
		
	}
}
