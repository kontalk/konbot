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
import org.jivesoftware.smack.packet.Presence;
import org.jxmpp.stringprep.XmppStringprepException;
import org.kontalk.konbot.client.EndpointServer;
import org.kontalk.konbot.client.KontalkConnection;
import org.kontalk.konbot.crypto.PersonalKey;
import org.kontalk.konbot.shell.HelpableCommand;
import org.kontalk.konbot.shell.ShellSession;


@SuppressWarnings("unused")
public class ConnectCommand extends AbstractCommand implements HelpableCommand {

    private static final String DEFAULT_RESOURCE = "konbot";

    @Override
    public String name() {
        return "connect";
    }

    @Override
    public String description() {
        return "Connect to server";
    }

    @Override
    public void run(String[] args, ShellSession session) {
        KontalkConnection conn = connection(session);
        if (conn != null && conn.isConnected()) {
            println("Already connected.");
        }
        else {
            if (conn == null) {
                try {
                    conn = createConnection(session);
                }
                catch (Exception e) {
                    println("Unable to create connection: " + e);
                    e.printStackTrace(out);
                }
            }

            if (conn != null) {
                try {
                    conn.connect();
                    conn.login();
                    conn.sendStanza(presence());
                }
                catch (Exception e) {
                    println("Unable to connect: " + e);
                    e.printStackTrace(out);
                }
            }
        }
    }

    private KontalkConnection createConnection(ShellSession session) throws PGPException, XmppStringprepException {
        PersonalKey key = (PersonalKey) session.get("auth.personalkey");
        String xmppDomain = (String) session.get("server.xmppdomain");

        if (key == null || xmppDomain == null)
            throw new IllegalArgumentException("Session is not ready");

        String host = (String) session.get("server.host");
        int port = session.getInt("server.port", EndpointServer.DEFAULT_PORT);
        EndpointServer server = new EndpointServer(xmppDomain, host, port);

        KontalkConnection conn = new KontalkConnection(DEFAULT_RESOURCE, server, false,
                key.getBridgePrivateKey(), key.getBridgeCertificate(), true, null);
        session.put("connection", conn);
        return conn;
    }

    private Presence presence() {
        Presence p = new Presence(Presence.Type.available);
        p.setMode(Presence.Mode.available);
        p.setPriority(0);
        return p;
    }

    public static KontalkConnection connection(ShellSession session) {
        return (KontalkConnection) session.get("connection");
    }

    @Override
    public void help() {
        println("Usage: "+name());
    }
}
