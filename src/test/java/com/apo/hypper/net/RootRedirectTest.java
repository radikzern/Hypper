package com.apo.hypper.net;

import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNull;

public class RootRedirectTest {
    private static final String NF_LIVE =
            "ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.5 dst=93.184.216.34 sport=40001 dport=443 "
                    + "src=127.0.0.1 dst=10.0.0.5 sport=37000 dport=40001 [ASSURED] mark=0 use=2";
    private static final String NF_OLD =
            "ipv4     2 tcp      6 100 TIME_WAIT src=10.0.0.5 dst=1.1.1.1 sport=40001 dport=80 "
                    + "src=127.0.0.1 dst=10.0.0.5 sport=37000 dport=40001 [ASSURED] mark=0 use=2";
    private static final String NF_OTHER =
            "ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.5 dst=8.8.8.8 sport=40002 dport=853 "
                    + "src=8.8.8.8 dst=10.0.0.5 sport=853 dport=40002 [ASSURED] mark=0 use=2";
    private static final String IP_CONNTRACK =
            "tcp      6 431999 ESTABLISHED src=10.0.0.5 dst=149.154.175.50 sport=40003 dport=5222 "
                    + "src=127.0.0.1 dst=10.0.0.5 sport=37000 dport=40003 [ASSURED] use=1";

    @Test
    public void findsRedirectedConnection() {
        assertArrayEquals(new String[]{"93.184.216.34", "443"},
                RootRedirect.findOriginal(Arrays.asList(NF_OTHER, NF_OLD, NF_LIVE), 40001, 37000));
    }

    @Test
    public void parsesOldIpConntrackFormat() {
        assertArrayEquals(new String[]{"149.154.175.50", "5222"},
                RootRedirect.findOriginal(Arrays.asList(IP_CONNTRACK), 40003, 37000));
    }

    @Test
    public void ignoresConnectionsNotRedirectedToUs() {
        assertNull(RootRedirect.findOriginal(Arrays.asList(NF_OTHER), 40002, 37000));
        assertNull(RootRedirect.findOriginal(Arrays.asList(NF_LIVE), 40001, 9999));
    }
}
