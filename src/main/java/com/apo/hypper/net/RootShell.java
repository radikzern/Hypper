package com.apo.hypper.net;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

/** Постоянная оболочка su: команды выполняются по очереди, вывод читается до маркера. */
final class RootShell {
    private final Process process;
    private final OutputStream stdin;
    private final BufferedReader stdout;
    private int seq;

    static final class Result {
        final int code;
        final List<String> lines;

        Result(int code, List<String> lines) {
            this.code = code;
            this.lines = lines;
        }

        String output() {
            StringBuilder sb = new StringBuilder();
            for (String l : lines) sb.append(sb.length() == 0 ? "" : "\n").append(l);
            return sb.toString();
        }
    }

    RootShell() throws IOException {
        try {
            process = Runtime.getRuntime().exec("su");
        } catch (IOException e) {
            throw new IOException("нет root (su не найден)");
        }
        stdin = process.getOutputStream();
        stdout = new BufferedReader(new InputStreamReader(process.getInputStream(), VlessClient.UTF8));
        Result r = run("id");
        if (r.code != 0 || r.output().indexOf("uid=0") < 0) {
            close();
            throw new IOException("нет root (доступ не выдан)");
        }
    }

    /** Выполняет команду; stderr сливается в вывод. */
    synchronized Result run(String cmd) throws IOException {
        String marker = "__hypper_end_" + (++seq) + "__";
        stdin.write(("(" + cmd + ") 2>&1; echo \"" + marker + " $?\"\n").getBytes(VlessClient.UTF8));
        stdin.flush();
        List<String> lines = new ArrayList<String>();
        String line;
        while ((line = stdout.readLine()) != null) {
            int m = line.indexOf(marker);
            if (m >= 0) {
                if (m > 0) lines.add(line.substring(0, m));
                int code;
                try {
                    code = Integer.parseInt(line.substring(m + marker.length()).trim());
                } catch (NumberFormatException e) {
                    code = -1;
                }
                return new Result(code, lines);
            }
            lines.add(line);
        }
        throw new IOException("root-оболочка закрылась");
    }

    void close() {
        try {
            stdin.write("exit\n".getBytes(VlessClient.UTF8));
            stdin.flush();
        } catch (IOException ignored) {
        }
        process.destroy();
    }
}
