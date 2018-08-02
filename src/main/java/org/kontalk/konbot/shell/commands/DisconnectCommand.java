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

import org.kontalk.konbot.client.XMPPTCPConnection;
import org.kontalk.konbot.shell.HelpableCommand;
import org.kontalk.konbot.shell.ShellSession;


@SuppressWarnings("unused")
public class DisconnectCommand extends AbstractCommand implements HelpableCommand {

    @Override
    public String name() {
        return "disconnect";
    }

    @Override
    public String description() {
        return "Disconnect from server";
    }

    @Override
    public void run(String[] args, ShellSession session) {
        XMPPTCPConnection conn = ConnectCommand.connection(session);
        if (conn == null || !conn.isConnected()) {
            println("Not connected.");
        }
        else {
            println("Disconnecting.");
            conn.disconnect();
        }
    }

    @Override
    public void help() {
        println("Usage: "+name());
    }
}
