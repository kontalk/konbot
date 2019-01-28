/*
 * Konbot
 * Copyright (C) 2018 Kontalk Devteam <devteam@kontalk.org>

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.kontalk.konbot.crypto;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.kontalk.konbot.crypto.PGP.PGPDecryptedKeyPairRing;
import org.kontalk.konbot.crypto.PGP.PGPKeyPairRing;

import java.io.*;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Iterator;


/** Personal asymmetric encryption key. */
public class PersonalKey {
    private static final KeyFingerPrintCalculator sFingerprintCalculator =
        PGP.sFingerprintCalculator;

    public static final int MIN_PASSPHRASE_LENGTH = 4;

    /** Decrypted key pair (for direct usage). */
    private final PGPDecryptedKeyPairRing mPair;
    /** X.509 bridge certificate. */
    private final X509Certificate mBridgeCert;

    private PersonalKey(PGPDecryptedKeyPairRing keyPair, X509Certificate bridgeCert) {
        mPair = keyPair;
        mBridgeCert = bridgeCert;
    }

    private PersonalKey(PGPKeyPair authKp, PGPKeyPair signKp, PGPKeyPair encryptKp, X509Certificate bridgeCert) {
        this(new PGPDecryptedKeyPairRing(authKp, signKp, encryptKp), bridgeCert);
    }

    public PGPKeyPair getEncryptKeyPair() {
        return mPair.encryptKey;
    }

    public PGPKeyPair getSignKeyPair() {
        return mPair.signKey;
    }

    public PGPKeyPair getAuthKeyPair() {
        return mPair.authKey;
    }

    public X509Certificate getBridgeCertificate() {
        return mBridgeCert;
    }

    public PrivateKey getBridgePrivateKey() throws PGPException {
        return PGP.convertPrivateKey(mPair.authKey.getPrivateKey());
    }

    public PGPPublicKeyRing getPublicKeyRing() throws IOException {
        return new PGPPublicKeyRing(getEncodedPublicKeyRing(), sFingerprintCalculator);
    }

    public byte[] getEncodedPublicKeyRing() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        mPair.authKey.getPublicKey().encode(out);
        mPair.signKey.getPublicKey().encode(out);
        mPair.encryptKey.getPublicKey().encode(out);
        return out.toByteArray();
    }

    /** Returns the first user ID on the key that matches the given network. */
    public String getUserId(String network) {
        return PGP.getUserId(mPair.authKey.getPublicKey(), network);
    }

    public String getFingerprint() {
        return PGP.getFingerprint(mPair.authKey.getPublicKey());
    }

    public PGPKeyPairRing storeNetwork(String userId, String network, String name, String passphrase) throws PGPException, IOException {
        return store(name, userId + '@' + network, null, passphrase);
    }

    public PGPKeyPairRing store(String name, String email, String comment, String passphrase) throws PGPException, IOException {
        // name[ (comment)] <[email]>
        StringBuilder userid = new StringBuilder(name);

        if (comment != null) userid
            .append(" (")
            .append(comment)
            .append(')');

        userid.append(" <");
        if (email != null)
            userid.append(email);
        userid.append('>');

        return PGP.store(mPair, userid.toString(), passphrase);
    }

    /**
     * Updates the public key.
     * @return the public keyring.
     */
    public PGPPublicKeyRing update(byte[] keyData) throws IOException {
        PGPPublicKeyRing ring = new PGPPublicKeyRing(keyData, sFingerprintCalculator);
        // FIXME should loop through the ring and check for master/subkey
        mPair.authKey = new PGPKeyPair(ring.getPublicKey(), mPair.authKey.getPrivateKey());
        return ring;
    }

    public PersonalKey copy(X509Certificate bridgeCert) {
        return new PersonalKey(mPair, bridgeCert);
    }

    /** Checks that the given personal key data is correct. */
    public static PGPKeyPairRing test(InputStream privateKeyData, InputStream publicKeyData, String passphrase, InputStream bridgeCertData)
            throws PGPException, IOException, CertificateException, NoSuchProviderException {

        PGPSecretKeyRing secRing = new PGPSecretKeyRing(privateKeyData, sFingerprintCalculator);
        PGPPublicKeyRing pubRing = new PGPPublicKeyRing(publicKeyData, sFingerprintCalculator);

        // X.509 bridge certificate
        X509Certificate bridgeCert = (bridgeCertData != null) ?
            X509Bridge.load(bridgeCertData) : null;

        return test(secRing, pubRing, passphrase, bridgeCert);
    }

    /** Checks that the given personal key data is correct. */
    public static PGPKeyPairRing test(byte[] privateKeyData, byte[] publicKeyData, String passphrase, byte[] bridgeCertData)
            throws PGPException, IOException, CertificateException, NoSuchProviderException {

        PGPSecretKeyRing secRing = new PGPSecretKeyRing(privateKeyData, sFingerprintCalculator);
        PGPPublicKeyRing pubRing = new PGPPublicKeyRing(publicKeyData, sFingerprintCalculator);

        // X.509 bridge certificate
        X509Certificate bridgeCert = (bridgeCertData != null) ?
            X509Bridge.load(bridgeCertData) : null;

        return test(secRing, pubRing, passphrase, bridgeCert);
    }

    private static PGPKeyPairRing test(PGPSecretKeyRing secRing, PGPPublicKeyRing pubRing, String passphrase, X509Certificate bridgeCert)
            throws PGPException, IOException, CertificateException, NoSuchProviderException {

        // for now we just do a test load
        load(secRing, pubRing, passphrase, bridgeCert);

        return new PGPKeyPairRing(pubRing, secRing);
    }

    /** Creates a {@link PersonalKey} from private and public key input streams. */
    public static PersonalKey load(InputStream privateKeyData, InputStream publicKeyData, String passphrase, InputStream bridgeCertData)
            throws PGPException, IOException, CertificateException, NoSuchProviderException {

        PGPSecretKeyRing secRing = new PGPSecretKeyRing(privateKeyData, sFingerprintCalculator);
        PGPPublicKeyRing pubRing = new PGPPublicKeyRing(publicKeyData, sFingerprintCalculator);

        // X.509 bridge certificate
        X509Certificate bridgeCert = (bridgeCertData != null) ?
            X509Bridge.load(bridgeCertData) : null;

        return load(secRing, pubRing, passphrase, bridgeCert);
    }

    /** Creates a {@link PersonalKey} from private and public key byte buffers. */
    public static PersonalKey load(byte[] privateKeyData, byte[] publicKeyData, String passphrase, byte[] bridgeCertData)
            throws PGPException, IOException, CertificateException, NoSuchProviderException {

        PGPSecretKeyRing secRing = new PGPSecretKeyRing(privateKeyData, sFingerprintCalculator);
        PGPPublicKeyRing pubRing = new PGPPublicKeyRing(publicKeyData, sFingerprintCalculator);

        // X.509 bridge certificate
        X509Certificate bridgeCert = (bridgeCertData != null) ?
            X509Bridge.load(bridgeCertData) : null;

        return load(secRing, pubRing, passphrase, bridgeCert);
    }

    /** Creates a {@link PersonalKey} from private and public key byte buffers. */
    public static PersonalKey load(byte[] privateKeyData, byte[] publicKeyData, String passphrase, X509Certificate bridgeCert)
        throws PGPException, IOException, CertificateException, NoSuchProviderException {

        PGPSecretKeyRing secRing = new PGPSecretKeyRing(privateKeyData, sFingerprintCalculator);
        PGPPublicKeyRing pubRing = new PGPPublicKeyRing(publicKeyData, sFingerprintCalculator);

        return load(secRing, pubRing, passphrase, bridgeCert);
    }

    @SuppressWarnings("unchecked")
    public static PersonalKey load(PGPSecretKeyRing secRing, PGPPublicKeyRing pubRing, String passphrase, X509Certificate bridgeCert)
            throws PGPException, IOException, CertificateException, NoSuchProviderException {

        PGPDigestCalculatorProvider sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build();
        PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder(sha1Calc)
            .setProvider(PGP.PROVIDER)
            .build(passphrase.toCharArray());

        PGPKeyPair authKp, signKp, encryptKp;

        PGPPublicKey  authPub = null;
        PGPPrivateKey authPriv = null;
        PGPPublicKey  signPub = null;
        PGPPrivateKey signPriv = null;
        PGPPublicKey   encPub = null;
        PGPPrivateKey  encPriv = null;

        // public keys
        Iterator<PGPPublicKey> pkeys = pubRing.getPublicKeys();
        while (pkeys.hasNext()) {
            PGPPublicKey key = pkeys.next();
            int keyFlags = PGP.getKeyFlags(key);

            if (key.isMasterKey()) {
                // legacy support
                // if key flags has CAN_AUTHENTICATE, use the new key format
                if ((keyFlags & PGPKeyFlags.CAN_AUTHENTICATE) == PGPKeyFlags.CAN_AUTHENTICATE) {
                    authPub = key;
                }
                else {
                    // no authentication key flags, presuming old key format
                    // use the master key for both authentication and signing
                    authPub = signPub = key;
                }
            }
            else {
                // legacy support
                // if key flags has CAN_SIGN, use the new key format
                if ((keyFlags & PGPKeyFlags.CAN_SIGN) == PGPKeyFlags.CAN_SIGN) {
                    signPub = key;
                }
                else {
                    // no encryption key flags, presuming old key format
                    // use the subkey for encryption
                    encPub = key;
                }
            }
        }

        // secret keys
        Iterator<PGPSecretKey> skeys = secRing.getSecretKeys();
        while (skeys.hasNext()) {
            PGPSecretKey key = skeys.next();
            int keyFlags = PGP.getKeyFlags(key.getPublicKey());

            if (key.isMasterKey()) {
                // legacy support
                // if key flags has CAN_AUTHENTICATE, use the new key format
                if ((keyFlags & PGPKeyFlags.CAN_AUTHENTICATE) == PGPKeyFlags.CAN_AUTHENTICATE) {
                    authPriv = key.extractPrivateKey(decryptor);
                }
                else {
                    // no authentication key flags, presuming old key format
                    // use the master key for both authentication and signing
                    authPriv = signPriv = key.extractPrivateKey(decryptor);
                }
            }
            else {
                // legacy support
                // if key flags has CAN_SIGN, use the new key format
                if ((keyFlags & PGPKeyFlags.CAN_SIGN) == PGPKeyFlags.CAN_SIGN) {
                    signPriv = key.extractPrivateKey(decryptor);
                }
                else {
                    // no encryption key flags, presuming old key format
                    // use the subkey for encryption
                    encPriv = key.extractPrivateKey(decryptor);
                }
            }
        }

        if (encPriv != null && encPub != null && authPriv != null && authPub != null) {
            authKp = new PGPKeyPair(authPub, authPriv);
            //signKp = new PGPKeyPair(signPub, signPriv);
            encryptKp = new PGPKeyPair(encPub, encPriv);
            return new PersonalKey(authKp, null, encryptKp, bridgeCert);
        }

        throw new PGPException("invalid key data");
    }

    public static PersonalKey create(Date timestamp) throws IOException {
        try {
            PGPDecryptedKeyPairRing kp = PGP.create(timestamp);
            return new PersonalKey(kp, null);
        }
        catch (Exception e) {
            throw new IOException("unable to generate keypair", e);
        }
    }

    /**
     * Revokes the whole key pair using the master (signing) key.
     * @param store true to store the key in this object
     * @return the revoked master public key
     */
    public PGPPublicKey revoke(boolean store)
            throws PGPException, IOException, SignatureException {

        PGPPublicKey revoked = PGP.revokeKey(mPair.authKey);

        if (store)
            mPair.authKey = new PGPKeyPair(revoked, mPair.authKey.getPrivateKey());

        return revoked;
    }

}
