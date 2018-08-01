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

import org.kontalk.konbot.shell.ParentShell;
import org.kontalk.konbot.shell.ShellCommand;

import java.io.PrintWriter;


public abstract class AbstractCommand implements ShellCommand {

    protected PrintWriter out;

    protected ParentShell shell;

    @Override
    public void setOutput(PrintWriter writer) {
        this.out = writer;
    }

    @Override
    public void setParentShell(ParentShell shell) {
        this.shell = shell;
    }

    protected void printf(String fmt, Object... args) {
        print(String.format(fmt, args));
    }

    protected void printlnf(String fmt, Object... args) {
        println(String.format(fmt, args));
    }

    protected void print(Object msg) {
        out.println(msg);
    }

    protected void println() {
        out.println();
    }

    protected void println(Object msg) {
        out.println(msg);
    }

}
