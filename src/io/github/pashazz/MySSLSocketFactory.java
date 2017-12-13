package io.github.pashazz;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;


public class MySSLSocketFactory extends SSLSocketFactory {
    private final SSLSocketFactory delegate;
    private HandshakeCompletedListener handshakeListener;
    private Connector connector;

    public MySSLSocketFactory(
            SSLSocketFactory delegate, HandshakeCompletedListener handshakeListener, Connector connector) {
        this.delegate = delegate;
        this.handshakeListener = handshakeListener;
        this.connector = connector;
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose)
            throws IOException {
        SSLSocket socket = (SSLSocket) this.delegate.createSocket(s, host, port, autoClose);

        if (this.handshakeListener != null) {
            socket.addHandshakeCompletedListener(this.handshakeListener);
            connector.socket = socket;

        }

        return socket;
    }

    @Override
    public Socket createSocket(Socket s, InputStream consumed, boolean autoClose)
            throws IOException
    {
        SSLSocket socket = (SSLSocket) this.delegate.createSocket(s, consumed, autoClose);
         if (this.handshakeListener != null) {
            socket.addHandshakeCompletedListener(this.handshakeListener);
        }

        return socket;

    }

    @Override
    public Socket createSocket(InetAddress addr1, int port1, InetAddress addr2, int port2) throws IOException
    {
        SSLSocket socket = (SSLSocket) this.delegate.createSocket(addr1, port1, addr2, port2);

        if (this.handshakeListener != null) {
            socket.addHandshakeCompletedListener(this.handshakeListener);
        }

        return socket;

    }


    @Override
    public String[] getDefaultCipherSuites() {

        return this.delegate.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return this.delegate.getSupportedCipherSuites();
    }

    @Override
    public  Socket createSocket(InetAddress addr, int port) throws IOException
    {
         SSLSocket socket = (SSLSocket) this.delegate.createSocket(addr, port);

        if (this.handshakeListener != null) {
            socket.addHandshakeCompletedListener(this.handshakeListener);
        }

        return socket;
    }

    @Override
    public Socket createSocket(String var1, int var2, InetAddress var3, int var4) throws IOException
    {
        SSLSocket socket = (SSLSocket) this.delegate.createSocket(var1, var2, var3, var4);

        if (this.handshakeListener != null) {
            socket.addHandshakeCompletedListener(this.handshakeListener);
        }

        return socket;
    }

    @Override
      public Socket createSocket(String var1, int var2) throws IOException
    {
        SSLSocket socket = (SSLSocket) this.delegate.createSocket(var1, var2);

        if (this.handshakeListener != null) {
            socket.addHandshakeCompletedListener(this.handshakeListener);
        }

        return socket;
    }

}