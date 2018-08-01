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

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;


public final class StreamUtils {
    private StreamUtils() {}

    public static ByteArrayInOutStream readFully(InputStream in, long maxSize) throws IOException {
        byte[] buf = new byte[1024];
        ByteArrayInOutStream out = new ByteArrayInOutStream();
        int l;
        while ((l = in.read(buf, 0, 1024)) > 0 && out.size() < maxSize)
            out.write(buf, 0, l);
        return out;
    }

    public static void close(Closeable stream) {
        if (stream != null) {
            try {
                stream.close();
            }
            catch (IOException ignored) {
            }
        }
    }

}
