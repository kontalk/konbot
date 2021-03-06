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

package org.kontalk.konbot.client;

import org.jivesoftware.smack.ReconnectionManager;
import org.jivesoftware.smack.ReconnectionManager.ReconnectionPolicy;
import org.jivesoftware.smack.SmackConfiguration;
import org.jivesoftware.smack.debugger.ConsoleDebugger;
import org.jivesoftware.smack.roster.Roster;
import org.jivesoftware.smackx.iqversion.VersionManager;
import org.jivesoftware.smackx.receipts.DeliveryReceiptManager;


/**
 * Initializes the Smack subsystem.
 * @author Daniele Ricci
 */
public class SmackInitializer {

    private static boolean sInitialized;

    public static void initialize() {
        if (!sInitialized) {
            // do not append Smack version
            VersionManager.setAutoAppendSmackVersion(false);
            // TODO take these from somewhere
            VersionManager.setDefaultVersion("Konbot", "1");

            // TODO this is not the place
            Roster.setDefaultSubscriptionMode(Roster.SubscriptionMode.accept_all);

            // TODO this is not the place
            DeliveryReceiptManager.setDefaultAutoReceiptMode(DeliveryReceiptManager.AutoReceiptMode.always);

            // console debugger
            SmackConfiguration.setDefaultSmackDebuggerFactory(ConsoleDebugger.Factory.INSTANCE);

            // reconnection policy
            ReconnectionManager.setEnabledPerDefault(true);
            ReconnectionManager.setDefaultReconnectionPolicy(ReconnectionPolicy.RANDOM_INCREASING_DELAY);

            sInitialized = true;
        }
    }

}
