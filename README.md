Konbot
======

An extensible bot for Kontalk written in Java.

## Overview
Konbot is a Java application that provides a command shell to interact with a Kontalk server.  
It can use a personal keypack (kontalk-keys.zip) exported from a Kontalk registered app to log in to Kontalk.

## Interactive shell
If executed standalone, Konbot provides an interactive shell with a few commands.

> TODO how to run main class

## Add your own commands
You can implement your own commands by extending the `AbstractCommand` class. You can look at any of the built-in
commands for examples.

Konbot automatically loads all command classes at startup, so it will automatically detect any custom commands. Just
include the jar with your custom commands in the classpath and run the interactive shell!

## Extensible bot
When you include Konbot as a library, you can run the command interpreter directly with existing or new commands.
Take a look at [Databot](https://github.com/kontalk/databot), a simple bot that replies to users with random data.
