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

import com.google.gson.Gson;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.roster.Roster;
import org.jivesoftware.smack.roster.RosterEntry;
import org.jivesoftware.smackx.address.packet.MultipleAddresses;
import org.jxmpp.jid.impl.JidCreate;
import org.jxmpp.jid.parts.Localpart;
import org.kontalk.konbot.client.XMPPTCPConnection;
import org.kontalk.konbot.shell.HelpableCommand;
import org.kontalk.konbot.shell.ShellSession;
import org.kontalk.konbot.util.JsonTransformer;
import org.kontalk.konbot.util.MessageUtils;
import spark.Request;
import spark.Response;
import spark.Route;

import java.util.List;
import java.util.logging.Logger;

import static spark.Spark.*;


@SuppressWarnings("unused")
public class HttpServerCommand extends AbstractCommand implements HelpableCommand {
    private static final Logger log = Logger.getLogger(HttpServerCommand.class.getName());
    private static final Gson gson = new Gson();

    @Override
    public String name() {
        return "httpserver";
    }

    @Override
    public String description() {
        return "Start a HTTP server";
    }

    @Override
    public void run(String[] args, ShellSession session) {
        if (args.length > 1) {
            if (args[1].equals("stop")) {
                println("Stopping HTTP server");
                stop();
                return;
            }
            else {
                try {
                    port(Integer.parseInt(args[1]));
                    ipAddress("127.0.0.1");
                }
                catch (NumberFormatException e) {
                    throw new IllegalArgumentException("Invalid port: " + args[1]);
                }
            }
        }

        println("Starting HTTP server");

        post("/message/broadcast/roster", new Route() {
            @Override
            public Object handle(Request req, Response res) throws Exception {
                MessageRequest msgreq = gson.fromJson(req.body(), MessageRequest.class);
                return HttpServerCommand.this.rosterBroadcast(session, msgreq);
            }
        }, new JsonTransformer());

        awaitInitialization();
    }

    private MessageResponse rosterBroadcast(ShellSession session, MessageRequest req) {
        MessageResponse res = new MessageResponse();

        XMPPTCPConnection conn = ConnectCommand.connection(session);
        if (conn == null || !conn.isAuthenticated())
            throw new IllegalArgumentException("Not connected");

        Roster roster = Roster.getInstanceFor(conn);
        MultipleAddresses multicast = new MultipleAddresses();
        for (RosterEntry e : roster.getEntries()) {
            multicast.addAddress(MultipleAddresses.Type.to, e.getJid(), null, null, false, null);
        }

        if (multicast.getAddressesOfType(MultipleAddresses.Type.to).size() > 0) {
            Message message = new Message(JidCreate.bareFrom(Localpart.fromOrThrowUnchecked("multicast"),
                    conn.getXMPPServiceDomain()), Message.Type.chat);
            String id = MessageUtils.messageId();
            message.setStanzaId(id);
            message.addExtension(multicast);
            message.setBody(req.getBody());
            try {
                message = MessageUtils.signMessage(message);
                conn.sendStanza(message);
                res.setId(id);
            }
            catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        return res;
    }

    private static final class MessageRequest {
        private List<String> to;
        private String body;

        public List<String> getTo() {
            return to;
        }

        public void setTo(List<String> to) {
            this.to = to;
        }

        public String getBody() {
            return body;
        }

        public void setBody(String body) {
            this.body = body;
        }
    }

    private static final class MessageResponse {
        private String id;

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }
    }

    @Override
    public void help() {
        println("Usage: "+name()+" [<port>]");
    }
}
