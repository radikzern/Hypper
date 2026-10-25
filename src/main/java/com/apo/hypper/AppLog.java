package com.apo.hypper;

import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.Date;
import java.util.Locale;

/** Журнал в памяти для экрана «Журнал» + logcat. */
public final class AppLog {
    private static final int MAX = 300;
    private static final ArrayDeque<String> LINES = new ArrayDeque<String>();
    private static final SimpleDateFormat FMT = new SimpleDateFormat("HH:mm:ss", Locale.US);
    public static volatile boolean verbose = false;

    private AppLog() {
    }

    public static void i(String msg) {
        add("I", msg);
    }

    public static void e(String msg) {
        add("E", msg);
    }

    public static void d(String msg) {
        if (verbose) add("D", msg);
    }

    private static void add(String level, String msg) {
        try {
            android.util.Log.println("E".equals(level) ? android.util.Log.ERROR : android.util.Log.INFO, "hypper", msg);
        } catch (RuntimeException ignored) {
            // юнит-тесты без android.jar
        }
        synchronized (LINES) {
            String time;
            synchronized (FMT) {
                time = FMT.format(new Date());
            }
            LINES.addLast(time + " " + level + " " + msg);
            while (LINES.size() > MAX) LINES.removeFirst();
        }
    }

    public static String dump() {
        StringBuilder sb = new StringBuilder();
        synchronized (LINES) {
            for (String l : LINES) sb.append(l).append('\n');
        }
        return sb.toString();
    }

    public static void clear() {
        synchronized (LINES) {
            LINES.clear();
        }
    }
}
