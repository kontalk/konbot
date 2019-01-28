package org.kontalk.konbot;

import org.junit.Test;
import org.jxmpp.jid.Jid;
import org.jxmpp.jid.impl.JidCreate;

public class GroupJidTest {

    @Test
    public void testGroupJidParse() {
        Jid jid = JidCreate.fromOrThrowUnchecked("hjdsfglkjhdfsklj@daniele@casaricci.it");
        System.out.println(jid);
        System.out.println(jid.getLocalpartOrNull().toString());
        System.out.println(jid.getLocalpartOrNull().asUnescapedString());
        System.out.println(jid.getDomain());
    }

}
