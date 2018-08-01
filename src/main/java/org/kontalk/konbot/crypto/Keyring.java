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

package org.kontalk.konbot.crypto;

import org.jivesoftware.smack.util.StringUtils;

import java.util.HashMap;
import java.util.Map;


/**
 * Keyring management.
 * @author Daniele Ricci
 */
public class Keyring {

    public static final int TRUST_UNKNOWN = 0;
    public static final int TRUST_IGNORED = 1;
    public static final int TRUST_VERIFIED = 2;

    private Keyring() {
    }

    /** Converts a raw-string trusted fingerprint map to a {@link TrustedFingerprint} map. */
    public static Map<String, TrustedFingerprint> fromTrustedFingerprintMap(Map<String, String> props) {
        Map<String, Keyring.TrustedFingerprint> keys = new HashMap<>(props.size());
        for (Map.Entry e : props.entrySet()) {
            TrustedFingerprint fingerprint = TrustedFingerprint
                    .fromString((String) e.getValue());
            if (fingerprint != null) {
                keys.put((String) e.getKey(), fingerprint);
            }
        }
        return keys;
    }

    public static final class TrustedFingerprint {
        public final String fingerprint;
        public final int trustLevel;

        TrustedFingerprint(String fingerprint, int trustLevel) {
            this.fingerprint = fingerprint;
            this.trustLevel = trustLevel;
        }

        @Override
        public String toString() {
            return fingerprint + "|" + trustLevel;
        }

        public static TrustedFingerprint fromString(String value) {
            if (!StringUtils.isNullOrEmpty(value)) {
                String[] parsed = value.split("\\|");
                String fingerprint = parsed[0];
                int trustLevel = TRUST_UNKNOWN;
                if (parsed.length > 1) {
                    String _trustLevel = parsed[1];
                    try {
                        trustLevel = Integer.parseInt(_trustLevel);
                    }
                    catch (NumberFormatException ignored) {
                    }
                }

                return new TrustedFingerprint(fingerprint, trustLevel);
            }
            return null;
        }
    }

}
