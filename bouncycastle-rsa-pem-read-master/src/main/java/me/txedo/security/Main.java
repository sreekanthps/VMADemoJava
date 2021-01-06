package me.txedo.security;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.UUID;

import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.*;
import com.nimbusds.jwt.*;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.lang.JoseException;

public class Main {

	protected final static Logger LOGGER = Logger.getLogger(Main.class);
	
	public final static String RESOURCES_DIR = "/Users/swesree/Desktop/KH802/CERTS/";

	public static void main(String[] args) throws FileNotFoundException,
			IOException, NoSuchAlgorithmException, NoSuchProviderException, ParseException, JOSEException, JoseException {
		Security.addProvider(new BouncyCastleProvider());
		LOGGER.info("BouncyCastle provider added.");

		KeyFactory factory = KeyFactory.getInstance("RSA", "BC");

		try {
			PrivateKey priv = generatePrivateKey(factory, RESOURCES_DIR + "vmaprivate.pem");
			
			LOGGER.info(String.format("Instantiated private key: %s", priv));
			
			PublicKey pub = generatePublicKey(factory, RESOURCES_DIR + "vmapublic.pem");
			LOGGER.info(String.format("Instantiated public key: %s", pub));
			numbusJWe(pub,priv);
			
			String jweString = jose4JEcnryption(pub);
			jose4JDeryption(priv,jweString);
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
	}

	private static PrivateKey generatePrivateKey(KeyFactory factory, String filename)
			throws InvalidKeySpecException, FileNotFoundException, IOException {
		PemFile pemFile = new PemFile(filename);
		byte[] content = pemFile.getPemObject().getContent();
		PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
		return factory.generatePrivate(privKeySpec);
	}
	
	private static PublicKey generatePublicKey(KeyFactory factory, String filename)
			throws InvalidKeySpecException, FileNotFoundException, IOException {
		PemFile pemFile = new PemFile(filename);
		byte[] content = pemFile.getPemObject().getContent();
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
		return factory.generatePublic(pubKeySpec);
	}
	
	private static void numbusJWe(PublicKey publicKey, PrivateKey privKey) throws ParseException, JOSEException {
		Date now = new Date();
		
		JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
					.issuer("https://openid.net")
					.subject("alice")
					.audience(Arrays.asList("https://app-one.com", "https://app-two.com"))
					.expirationTime(new Date(now.getTime() + 1000*60*10)) // expires in 10 minutes
					.notBeforeTime(now)
					.issueTime(now)
					.jwtID(UUID.randomUUID().toString())
					.build();
			System.out.println(jwtClaims.toJSONObject());
			// Request JWT encrypted with RSA-OAEP-256 and 128-bit AES/GCM
			JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);
				// Create the encrypted JWT object
			EncryptedJWT jwt = new EncryptedJWT(header, jwtClaims);
			// Create an encrypter with the specified public RSA key
			RSAEncrypter encrypter = new RSAEncrypter((RSAPublicKey) publicKey);
			// Do the actual encryption
			jwt.encrypt(encrypter);
			// Serialise to JWT compact form
			String jwtString = jwt.serialize();
			System.out.println("jwtString : "+jwtString);
				
		//
		//
			// Parse back
			//String jwtStringNew = "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.hJ905rCCsW0u07cCleTh_eYKAyDP7ZHNnRA50qDWXo7seygePzIkr37ZCeaW2hmZ-c6v_c7Yp3Y0kzE5OE0h93J09XAtYfwZk3zZVKXH8hd6fWjeY7ZgB8I4CpQaa9BX-Zp9bBznXHh5WqpckkMAXZVT-wiLNVqQDpyg8Jifi5tuw4SjT4irRrFYF5LfSDLU4EigKKC3Rn1IOlwEKhHuvqLFuCbqgXVh_Ps75P9_wXr3XoKSwEDf5zbOh42cPlenKfG0TQpeEhKamEbmpuRnOZYRHmOQ0d6KTI7t8xxRQ0g3nF0AJGQKwnbZDgZPli8v3dI8XZY9rca03rG8aQpCag.JFWISQTeuw2euVfT.5ekMlQk5tkPFLdUnZIh-GMfFGS36UPKAd_obtu-YCy_vv_iuNPVbxZyzjJFRnK2-G8Cf3UuKvpNusyjpd_AfIvoxg7fqCr95CZ8IulBGo1SddvcXx-kCsCNPawK97pN7qclHc6oqrIpK4CjUR0msJtgNbdTrFI0VOw1dLXoz_jFJ13xO1LQiXkxdJltD6qpEfE3x1UyNFpDHudplur7v6cd9WOXNFlQ6zQYfn-9ZHOMGoGFcQAB9u9crCkoyIX4vifNrJA.zD8126ElxZvp-RODUr5qSg";
			String jwtStringNew =  "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.u26p54cKA51XrUE2BBW2v6qDVq4ISK1zYmDIXFfy2yVTJdyhTQZ2d38umqe0BbUeDN7U9PANbXyp0Sg1Z6-Zr_XQCoo8XjRrMR2du3Wbi0VWhA0Xaz42kSuoEYG7mWMkz0T7uX94ssjR3CLumjFC45Z9tu4HvZ7UQG-O2-TXv4Gn3PZYi5-eLF5gLwTd8kVnL0IAXiQwP51iRRL5FvuXPOw-SRtgnS1ir-dWlO4DPIZoPeL7-ghNjzRMziU0n4zlmjWH2Q6bE1kW1UbS5MG_2sxSFNWwHUocVpelc-_AOZ3yBya3SYnGQ8FNiwkMqW1Q5dlwnREsICUzo4Mq_FEKWA.yHD-HK2bjB50mi975q1KCQ.dO6u6ZEXFrFpv11XYhyp4LltGiKDwsqirDP8czsOAJutIVg.eVgDmusIToKb9p5-eqYL8A";
			EncryptedJWT jwt1= EncryptedJWT.parse(jwtStringNew);
		
			// Create a decrypter with the specified private RSA key
			RSADecrypter decrypter = new RSADecrypter(privKey);
		
			// Decrypt
			jwt1.decrypt(decrypter);
		
				
			System.out.println(jwt1.getHeader());
			System.out.println("numbusJWe::: "+jwt1.getPayload());
// TODO Auto-generated method stub
	}
	
	private static String  jose4JEcnryption(PublicKey key) throws JoseException {
		JsonWebEncryption jwe = new JsonWebEncryption();
		 jwe.setPayload("Hello World!");
		 jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
		 jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
		 jwe.setKey(key);
		 String serializedJwe = jwe.getCompactSerialization();
		 System.out.println("Serialized Encrypted JWE: " + serializedJwe);
		 return serializedJwe;
	}
	
	private static void  jose4JDeryption(PrivateKey key, String jweToken) throws JoseException {
		String jwtStringNew1 = "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.u26p54cKA51XrUE2BBW2v6qDVq4ISK1zYmDIXFfy2yVTJdyhTQZ2d38umqe0BbUeDN7U9PANbXyp0Sg1Z6-Zr_XQCoo8XjRrMR2du3Wbi0VWhA0Xaz42kSuoEYG7mWMkz0T7uX94ssjR3CLumjFC45Z9tu4HvZ7UQG-O2-TXv4Gn3PZYi5-eLF5gLwTd8kVnL0IAXiQwP51iRRL5FvuXPOw-SRtgnS1ir-dWlO4DPIZoPeL7-ghNjzRMziU0n4zlmjWH2Q6bE1kW1UbS5MG_2sxSFNWwHUocVpelc-_AOZ3yBya3SYnGQ8FNiwkMqW1Q5dlwnREsICUzo4Mq_FEKWA.yHD-HK2bjB50mi975q1KCQ.dO6u6ZEXFrFpv11XYhyp4LltGiKDwsqirDP8czsOAJutIVg.eVgDmusIToKb9p5-eqYL8A";
		JsonWebEncryption jwe = new JsonWebEncryption();
		jwe.setAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.PERMIT, 
		        KeyManagementAlgorithmIdentifiers.RSA_OAEP_256));
		 jwe.setContentEncryptionAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.PERMIT, 
		        ContentEncryptionAlgorithmIdentifiers.AES_256_GCM));
		 jwe.setKey(key);
		 jwe.setCompactSerialization(jwtStringNew1);
		 System.out.println("JOSE4J ::: getHeaders :::: " + jwe.getHeaders());
		 System.out.println("JOSE4J ::: getContentEncryptionAlgorithm :::: " + jwe.getContentEncryptionAlgorithm());
		 System.out.println("JOSE4J ::: getEncryptedKey :::: " + jwe.getEncryptedKey());
		 System.out.println("JOSE4J ::: getIv :::: " + jwe.getIv());
		 System.out.println("JOSE4J ::: Payload :::: " + jwe.getPayload());
	}

}
