package org.kontalk.konbot;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.junit.Test;
import org.kontalk.konbot.client.EndpointServer;
import org.kontalk.konbot.client.KontalkConnection;
import org.kontalk.konbot.crypto.PGP;
import org.kontalk.konbot.crypto.PersonalKey;
import org.kontalk.konbot.crypto.X509Bridge;

import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import static org.junit.Assert.*;


public class P12CertificateTest {

    @Test
    public void testConnectPGP() throws Exception {
        PGP.registerProvider();
        String privateFile = "/home/daniele/Download/kontalk/private.pgp";
        String publicFile = "/home/daniele/Download/kontalk/public.pgp";
        //String privateFile = "/home/daniele/Download/kontalk/tim/kontalk-private.asc";
        //String publicFile = "/home/daniele/Download/kontalk/tim/kontalk-public.asc";

        // load the keyring
        PGP.PGPKeyPairRing ring;
        ByteArrayOutputStream privateKeyData = new ByteArrayOutputStream();
        IOUtils.copy(new FileInputStream(privateFile), privateKeyData);
        ByteArrayOutputStream publicKeyData = new ByteArrayOutputStream();
        IOUtils.copy(new FileInputStream(publicFile), publicKeyData);
        try {
            ring = PGP.PGPKeyPairRing.loadArmored(privateKeyData.toByteArray(), publicKeyData.toByteArray());
        }
        catch (IOException e) {
            // try not armored
            ring = PGP.PGPKeyPairRing.load(privateKeyData.toByteArray(), publicKeyData.toByteArray());
        }

        // bridge certificate for connection
        X509Certificate bridgeCert = X509Bridge.createCertificate(ring.publicKey, ring.secretKey.getSecretKey(), "");

        // and now the real final key
        PersonalKey key = PersonalKey.load(ring.secretKey, ring.publicKey, "", bridgeCert);


        KontalkConnection conn = new KontalkConnection("test",
                new EndpointServer("prime.kontalk.net|zeta.kontalk.net:7222"),
                false, key.getBridgePrivateKey(), key.getBridgeCertificate(), true, null);
        conn.connect();
    }

    @Test
    public void testConnect() throws Exception {
        KeyStore p12 = KeyStore.getInstance("pkcs12");
        p12.load(new FileInputStream("/home/daniele/Download/kontalk/CERT.p12"), "kontalk".toCharArray());

        PrivateKey privateKey = null;
        X509Certificate certificate = null;

        Enumeration e = p12.aliases();
        while (e.hasMoreElements()) {
            String alias = (String) e.nextElement();
            System.out.println(alias);
            if (p12.isKeyEntry(alias)) {
                certificate = (X509Certificate) p12.getCertificate(alias);
                privateKey = (PrivateKey) p12.getKey(alias, "kontalk".toCharArray());
            }
        }

        assertNotNull(privateKey);
        assertNotNull(certificate);

        KontalkConnection conn = new KontalkConnection("test",
                new EndpointServer("prime.kontalk.net|zeta.kontalk.net:7222"),
                false, privateKey, certificate, true, null);
        conn.connect();
    }

    @Test
    public void testConnectPem() throws Exception {
        PEMParser parser = new PEMParser(new FileReader("/home/daniele/Download/kontalk/selfsigned.cer"));
        X509CertificateHolder x509CertificateHolder = (X509CertificateHolder) parser.readObject();
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate( x509CertificateHolder );

        parser = new PEMParser(new FileReader("/home/daniele/Download/kontalk/private.key"));

        PrivateKey privateKey;
        Object pkeyInfo = null;
        try {
            pkeyInfo = parser.readObject();
            PrivateKeyInfo info = (PrivateKeyInfo) pkeyInfo;
            privateKey = new JcaPEMKeyConverter().getPrivateKey(info);
        }
        catch (ClassCastException e) {
            PEMKeyPair pair = (PEMKeyPair) pkeyInfo;
            privateKey = new JcaPEMKeyConverter().getPrivateKey(pair.getPrivateKeyInfo());
        }

        assertNotNull(privateKey);
        assertNotNull(certificate);

        KontalkConnection conn = new KontalkConnection("test",
                new EndpointServer("prime.kontalk.net|zeta.kontalk.net:7222"),
                false, privateKey, certificate, true, null);
        conn.connect();
    }

}
