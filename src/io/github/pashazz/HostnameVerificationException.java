package io.github.pashazz;


import javax.net.ssl.SSLSession;

public class HostnameVerificationException extends RuntimeException
{
    public HostnameVerificationException(String host, SSLSession session)
    {
        this.session = session;
        this.host = host;
    }
    private SSLSession session;
    private String host;

    public SSLSession getSession() {
        return session;
    }

    public String getHost() {
        return host;
    }
}