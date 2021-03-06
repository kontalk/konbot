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

package org.kontalk.konbot.util;

import org.bouncycastle.openpgp.PGPException;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.util.StringUtils;
import org.kontalk.konbot.client.OpenPGPSignedMessage;
import org.kontalk.konbot.crypto.KontalkKeyring;

import java.io.IOException;


public final class MessageUtils {

    private MessageUtils() {}

    public static String messageId() {
        return StringUtils.randomString(30);
    }

    public static Message signMessage(Message message) throws IOException, PGPException {
        byte[] signedBody = KontalkKeyring.getInstance().signData(message.getBody().getBytes());
        message.addExtension(new OpenPGPSignedMessage(signedBody));
        return message;
    }

}
