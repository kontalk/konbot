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

package org.kontalk.konbot;

import org.kontalk.konbot.client.SmackInitializer;
import org.kontalk.konbot.crypto.PGP;
import org.kontalk.konbot.shell.BotShell;
import org.kontalk.konbot.util.StreamUtils;

import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;


public class Konbot {

    private final String[] args;

    public Konbot(String[] args) {
        this.args = args;
        SmackInitializer.initialize();
        PGP.registerProvider();
        initLog();
    }

    private void initLog() {
        InputStream in = null;
        try {
            in = getClass().getResourceAsStream("/logging.properties");
            LogManager.getLogManager().readConfiguration(in);
        }
        catch (IOException e) {
            Logger.getAnonymousLogger().log(Level.SEVERE, "Unable to load logging configuration", e);
        }
        finally {
            StreamUtils.close(in);
        }
    }

    public void run() {
        try {
            BotShell sh = new BotShell();
            sh.init();

            if (args != null && args.length > 0) {
                sh.run(args);
            }
            else {
                sh.start();
            }
        }
        catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    public static void main(String[] args) {
        new Konbot(args).run();
    }

}
