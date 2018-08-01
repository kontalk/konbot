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

import org.clapper.util.classutil.*;
import org.jline.reader.*;
import org.jline.reader.impl.DefaultParser;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
import org.kontalk.konbot.shell.commands.AbstractCommand;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.TreeMap;


public class BotShell implements ParentShell {

    private static final String PROMPT = "konbot > ";

    private final Terminal terminal;
    private final LineReader reader;

    private Map<String, ShellCommand> commands = new TreeMap<>();
    private ShellSession session = new ShellSession();

    private volatile boolean running;

    public BotShell() throws IOException {
        terminal = TerminalBuilder.terminal();
        reader = LineReaderBuilder.builder()
                .terminal(terminal)
                .parser(new DefaultParser())
                .build();
    }

    public void init() throws ClassUtilException {
        // built-in commands
        addCommand(new HelpCommand());
        addCommand(new ExitCommand());

        Collection<ClassInfo> commands = new ArrayList<>();
        ClassFilter filter = new AndClassFilter(
                new SubclassClassFilter(ShellCommand.class),
                new NotClassFilter(new AbstractClassFilter())
        );
        ClassFinder finder = new ClassFinder();
        finder.addClassPath();

        if (finder.findClasses(commands, filter) > 0) {
            for (ClassInfo info : commands) {
                String clsName = info.getClassName();
                if (!clsName.startsWith(getClass().getName() + "$"))
                    addCommand((ShellCommand) ClassUtil.instantiateClass(info.getClassName()));
            }
        }
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

                runCommand(args);
            }
            catch (CommandNotFoundException e) {
                terminal.writer().println("Command not found: " + e.getMessage());
            }
            catch (UserInterruptException e) {
                terminal.writer().println("Interrupt");
                stop();
            }
            catch (EndOfFileException e) {
                terminal.writer().println("End-of-file");
                stop();
            }
            catch (Exception e) {
                terminal.writer().println("Command error: " + e);
            }
        }
    }

    public void stop() {
        end();
        running = false;
    }

    private void end() {
        terminal.flush();
    }

    public void run(String[] args) {
        try {
            runCommand(args);
        }
        catch (CommandNotFoundException e) {
            terminal.writer().println("Command not found: " + e.getMessage());
        }
        catch (UserInterruptException e) {
            terminal.writer().println("Interrupt");
            stop();
        }
        catch (EndOfFileException e) {
            terminal.writer().println("End-of-file");
            stop();
        }
        catch (Exception e) {
            terminal.writer().println("Command error: " + e);
        }
        finally {
            end();
        }
    }

    @Override
    public void runCommand(String[] args) throws CommandNotFoundException {
        ShellCommand cmd = commands.get(args[0]);
        if (cmd == null)
            throw new CommandNotFoundException(args[0]);

        cmd.run(args, session);
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
            return "Provide help for commands";
        }

        @Override
        public void run(String[] args, ShellSession session) {
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
            return "Exit the program";
        }

        @Override
        public void run(String[] args, ShellSession session) {
            stop();
        }

        @Override
        public void help() {
            println("Usage: "+name());
        }
    }

}
