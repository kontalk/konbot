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

import org.kontalk.konbot.shell.HelpableCommand;
import org.kontalk.konbot.shell.ShellSession;


@SuppressWarnings("unused")
public class ServerCommand extends AbstractCommand implements HelpableCommand {

    @Override
    public String name() {
        return "server";
    }

    @Override
    public String description() {
        return "Set server connection parameters";
    }

    @Override
    public void run(String[] args, ShellSession session) {
        if (args.length < 2) {
            help();
            return;
        }

        String xmppDomain = args[1];
        String host = null;
        int port = 0;
        if (args.length > 2) {
            host = args[2];
        }
        if (args.length > 3) {
            port = Integer.parseInt(args[3]);
        }

        session.put("server.xmppdomain", xmppDomain);
        session.put("server.host", host);
        session.put("server.port", port);
    }

    @Override
    public void help() {
        println("Usage: "+name()+" <xmpp_domain> [<host>] [<port>]");
    }
}
