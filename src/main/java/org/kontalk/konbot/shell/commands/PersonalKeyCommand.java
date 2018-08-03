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

package org.kontalk.konbot.shell.commands;

import org.bouncycastle.openpgp.PGPException;
import org.kontalk.konbot.crypto.*;
import org.kontalk.konbot.shell.HelpableCommand;
import org.kontalk.konbot.shell.ShellSession;
import org.kontalk.konbot.util.StreamUtils;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.zip.ZipInputStream;


@SuppressWarnings("unused")
public class PersonalKeyCommand extends AbstractCommand implements HelpableCommand {

    @Override
    public String name() {
        return "personalkey";
    }

    @Override
    public String description() {
        return "Set personal key data";
    }

    @Override
    public void run(String[] args, ShellSession session) {
        if (args.length < 3) {
            help();
            return;
        }

        String keypackFile = args[1];
        String passphrase = args[2];

        ZipInputStream in = null;
        PersonalKeyImporter importer = null;
        try {
            in = new ZipInputStream(new FileInputStream(keypackFile));
            importer = new PersonalKeyImporter(in, passphrase);
            importer.load();

            PersonalKey key = importer.createPersonalKey();
            if (key == null)
                throw new PGPException("Unable to load personal key");

            byte[] privateKeyData = importer.getPrivateKeyData();
            byte[] publicKeyData = importer.getPublicKeyData();

            // load the keyring
            PGP.PGPKeyPairRing ring;
            try {
                ring = PGP.PGPKeyPairRing.loadArmored(privateKeyData, publicKeyData);
            }
            catch (IOException e) {
                // try not armored
                ring = PGP.PGPKeyPairRing.load(privateKeyData, publicKeyData);
            }

            // bridge certificate for connection
            X509Certificate bridgeCert = X509Bridge.createCertificate(ring.publicKey, ring.secretKey.getSecretKey(), passphrase);

            // and now the real final key
            key = PersonalKey.load(ring.secretKey, ring.publicKey, passphrase, bridgeCert);
            session.put("auth.personalkey.data.private", privateKeyData);
            session.put("auth.personalkey.data.public", publicKeyData);
            session.put("auth.personalkey", key);

            // initialize keyring
            KontalkKeyring.init(key, privateKeyData, publicKeyData);
        }
        catch (Exception e) {
            println("Error importing personal key: " + e);
            e.printStackTrace(out);
        }
        finally {
            StreamUtils.close(importer);
            StreamUtils.close(in);
        }
    }

    public static PersonalKey personalKey(ShellSession session) {
        return (PersonalKey) session.get("auth.personalkey");
    }

    public static byte[] privateKeyData(ShellSession session) {
        return (byte[]) session.get("auth.personalkey.data.private");
    }

    public static byte[] publicKeyData(ShellSession session) {
        return (byte[]) session.get("auth.personalkey.data.public");
    }

    @Override
    public void help() {
        println("Usage: "+name()+" <kontalk_keys.zip> <passphrase>");
    }
}
