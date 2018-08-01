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

import java.util.Map;


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
    public void run(String[] args, Map<String, Object> session) {
        if (args.length < 3) {
            help();
            return;
        }

        String keypackFile = args[1];
        String passphrase = args[2];

        // TODO open keypack immediately and put parsed stuff in session
        println("Not implemented.");
    }

    @Override
    public void help() {
        println("Usage: "+name()+" <kontalk_keys.zip> <passphrase>");
    }
}
