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

package org.kontalk.konbot.shell;

import org.jline.reader.*;
import org.jline.reader.impl.DefaultParser;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
import org.kontalk.konbot.shell.commands.AbstractCommand;
import org.kontalk.konbot.shell.commands.PersonalKeyCommand;
import org.kontalk.konbot.shell.commands.ServerCommand;

import java.io.IOException;
import java.util.Map;
import java.util.TreeMap;


public class BotShell {

    private static final String PROMPT = "konbot > ";

    private final Terminal terminal;
    private final LineReader reader;

    private Map<String, ShellCommand> commands = new TreeMap<>();
    private Map<String, Object> session = new TreeMap<>();

    private volatile boolean running;

    public BotShell() throws IOException {
        terminal = TerminalBuilder.terminal();
        reader = LineReaderBuilder.builder()
                .terminal(terminal)
                .parser(new DefaultParser())
                .build();
    }

    public void init() {
        // TODO use reflection
        addCommand(new HelpCommand());
        addCommand(new ExitCommand());
        addCommand(new ServerCommand());
        addCommand(new PersonalKeyCommand());
    }

    private void addCommand(ShellCommand cmd) {
        cmd.setOutput(terminal.writer());
        commands.put(cmd.name(), cmd);
    }

    public void start() {
        running = true;
        while (running) {
            try {
                reader.readLine(PROMPT);
                ParsedLine line = reader.getParsedLine();
                String[] args = line.words().toArray(new String[0]);
                if (args.length == 0 || args[0].length() == 0)
                    continue;

                ShellCommand cmd = commands.get(args[0]);
                if (cmd == null)
                    throw new CommandNotFoundException(args[0]);

                cmd.run(args, session);
            }
            catch (CommandNotFoundException e) {
                terminal.writer().println("Command not found: " + e.getMessage());
            }
            catch (UserInterruptException e) {
                terminal.writer().println("Interrupt");
            }
            catch (EndOfFileException e) {
                terminal.writer().println("End-of-file");
            }
            catch (Exception e) {
                terminal.writer().println("Command error: " + e);
            }
        }
    }

    public void stop() {
        running = false;
    }

    /** Help command. */
    private class HelpCommand extends AbstractCommand implements HelpableCommand {
        HelpCommand() {
        }

        @Override
        public String name() {
            return "help";
        }

        @Override
        public String description() {
            return "Provide help for commands.";
        }

        @Override
        public void run(String[] args, Map<String, Object> session) {
            if (args.length < 2) {
                list();
                return;
            }

            String name = args[1];

            try {
                HelpableCommand cmd = (HelpableCommand) commands.get(name);
                if (cmd == null)
                    throw new CommandNotFoundException(name);
                cmd.help();
            }
            catch (ClassCastException e) {
                println("Command does not provide help: " + name);
            } catch (CommandNotFoundException e) {
                println("Command not found: " + e.getMessage());
            }
        }

        private void list() {
            for (String name : commands.keySet()) {
                printlnf("%-20s%s", name, commands.get(name).description());
            }
        }

        @Override
        public void help() {
            println("Usage: "+name()+" <command>");
        }
    }

    /** Exit command. */
    private class ExitCommand extends AbstractCommand implements HelpableCommand {
        ExitCommand() {
        }

        @Override
        public String name() {
            return "exit";
        }

        @Override
        public String description() {
            return "Exit the program.";
        }

        @Override
        public void run(String[] args, Map<String, Object> session) {
            stop();
        }

        @Override
        public void help() {
            println("Usage: "+name());
        }
    }

    private static final class CommandNotFoundException extends Exception {
        CommandNotFoundException(String name) {
            super(name);
        }
    }

}
