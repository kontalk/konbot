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

import org.bouncycastle.openpgp.PGPException;

import java.io.IOException;


/**
 * Kontalk keyring singleton.
 * @author Daniele Ricci
 */
public class KontalkKeyring {
    private static KontalkKeyring INSTANCE;

    private final PersonalKey personalKey;

    private final String secretKeyFingerprint;

    /** Use {@link #getInstance()} instead. */
    private KontalkKeyring(PersonalKey key, byte[] privateKeyData, byte[] publicKeyData) throws IOException, PGPException {
        personalKey = key;

        // import into GnuPG
        GnuPGInterface.getInstance().importKey(publicKeyData);
        GnuPGInterface.getInstance().importKey(privateKeyData);

        // calculate secret key fingerprint for signing
        secretKeyFingerprint = personalKey.getFingerprint();
    }

    public byte[] signData(byte[] data) throws IOException, PGPException {
        return GnuPGInterface.getInstance().signData(data, secretKeyFingerprint);
    }

    public static void init(PersonalKey key, byte[] privateKeyData, byte[] publicKeyData) throws IOException, PGPException {
        INSTANCE = new KontalkKeyring(key, privateKeyData, publicKeyData);
    }

    public synchronized static KontalkKeyring getInstance() {
        if (INSTANCE == null)
            throw new IllegalArgumentException("Call init() first");
        return INSTANCE;
    }

}
