package io.github.pashazz;

import sun.security.provider.certpath.SunCertPathBuilderException;
import sun.security.validator.ValidatorException;


import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStore;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.*;
import javax.security.cert.X509Certificate;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;

public class Connector {
    public Connector(String url_string) throws RuntimeException {
        try {
            url = new URL(url_string);
        } catch (MalformedURLException e) {
            System.out.printf("Malformed url: %s\nUnable to create io.github.pashazz.Connector object", url_string);
            e.printStackTrace();
        }
        if (!url.getProtocol().equals("https")) {
            throw new RuntimeException("Non-HTTPS protocol: " + url.getProtocol());
        }
       // Security.setProperty("");
    }

    private URL url;


    public URL getUrl() {
        return url;
    }
    SSLSocket socket;
    SSLSession session;

    private  void printCertificate(X509Certificate cert)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("Subject DN: ");
        sb.append(cert.getSubjectDN());
        sb.append("\nIssuer: ");
        sb.append(cert.getIssuerDN());
        sb.append("\nAlgorithm: ");
        sb.append(cert.getSigAlgName());
        sb.append("\nSerial Number: ");
        sb.append(cert.getSerialNumber());
        sb.append("\nBegins On: ");
        sb.append(cert.getNotBefore());
        sb.append("\nExpires On: ");
        sb.append(cert.getNotAfter());
        sb.append("\n");
        System.out.println(sb);

    }

    private void printCertificate(java.security.cert.X509Certificate cert)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("Subject DN: ");
        sb.append(cert.getSubjectDN());
        sb.append("\nIssuer: ");
        sb.append(cert.getIssuerDN());
        sb.append("\nAlgorithm:");
        sb.append(cert.getSigAlgName());
        sb.append("\nSerial Number: ");
        sb.append(cert.getSerialNumber());
        sb.append("\nBegins On: ");
        sb.append(cert.getNotBefore());
        sb.append("\nExpires On: ");
        sb.append(cert.getNotAfter());
        sb.append("\n");
        System.out.println(sb);
    }
    private void printCertificateChain() {
        X509Certificate[] certs;
        try {
           session.getId();
           certs = session.getPeerCertificateChain();
        }
        catch (SSLPeerUnverifiedException e)
        {
            e.printStackTrace();
            return;
        }
        System.out.println("Full Certificate Chain");
        for (X509Certificate cert: certs)
        {
            printCertificate(cert);
        }
    }


    public void connect() throws Throwable{
        StringBuilder sb = new StringBuilder();
        HttpsURLConnection conn;

        String storeFileName = System.getProperty("javax.net.ssl.trustStore");

        if (storeFileName == null)
        {
            storeFileName = "";
        }
        File storeFile = new File(storeFileName);
        String storeFiles[] = new String[]
                {
                        System.getProperty("java.home") + "/lib/security/jssecacerts",
                        System.getProperty("java.home") + "/lib/security/cacerts"
                };


        for(int i = 0; i < storeFiles.length; ++i) {
            storeFileName = storeFiles[i];
            storeFile = new File(storeFileName);
            if (storeFile.exists())
                break;
        }


        System.out.printf("Found trust store: %s\n", storeFileName);
        String password = System.getProperty("javax.net.ssl.trustStorePassword");
        if (password == null)
            password = "changeit";

        /* Will only work in java 1.8u152*/
        String disabledAlgorithms = System.getProperty("jdk.certpath.disabledAlgorithms");
        if (disabledAlgorithms == null)
            disabledAlgorithms = "SHA1 jdkCA & usage TLSServer";
        else
            disabledAlgorithms += ", SHA1 jdkCA & usage TLSServer";

        System.setProperty("jdk.certpath.disabledAlgorithms", disabledAlgorithms);


        FileInputStream fis = new FileInputStream(storeFile);

        //Enable revokation checks
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        KeyManagerFactory kmf =  KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(fis, password.toCharArray());

// initialize certification path checking for the offered certificates and revocation checks against CLRs
        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX");
        PKIXRevocationChecker rc = (PKIXRevocationChecker)cpb.getRevocationChecker();
        rc.setOptions(EnumSet.of(
                PKIXRevocationChecker.Option.PREFER_CRLS, // prefer CLR over OCSP
                PKIXRevocationChecker.Option.ONLY_END_ENTITY//,
                //PKIXRevocationChecker.Option.NO_FALLBACK // don't fall back to OCSP checking
        ));

        PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(ks, new X509CertSelector());
        pkixParams.addCertPathChecker(rc);

        tmf.init( new CertPathTrustManagerParameters(pkixParams) );

        kmf.init(ks, password.toCharArray());


        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        try {
            conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(new MySSLSocketFactory(ctx.getSocketFactory(),
                    handshakeCompletedEvent -> sb.append("Handshake completed successfully\n"),
                    this));

            conn.setHostnameVerifier((string, ssls) -> {
                if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(string, ssls)) {
                    throw new HostnameVerificationException(string, ssls);
                } else {
                    sb.append("Hostname verification completed successfully\n");
                    return true;
                }
            });

        } catch (IOException e) {
            e.printStackTrace();
            return;
        }
        try {
            conn.connect();
        } catch (HostnameVerificationException e) {
            SSLSession s = e.getSession();
            session = s;
            X509Certificate cert = s.getPeerCertificateChain()[0];
            Principal principal = cert.getSubjectDN();

            System.out.printf("Hostname verification failed: SSL certificate subject name '%s' does not match target name '%s'\n",
                    principal.getName().split(",")[0], e.getHost());
            return;
    }  catch (SSLHandshakeException _e) {
            try {
                throw _e.getCause();
            } catch (ValidatorException _ve) {
                try {
                    throw _ve.getCause();
                } catch (CertPathValidatorException ve) {
                    List<? extends  java.security.cert.Certificate> certs = ve.getCertPath().getCertificates();
                    String reasonString = ve.getReason().toString();
                    if (reasonString.equals("EXPIRED")) {
                        System.out.println("Certificate expired");
                        for (Certificate _cert : certs) {
                            java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) _cert;
                            printCertificate(cert);
                            Date expirationDate = cert.getNotAfter();
                            Date date = new Date();
                            if (expirationDate.before(date)) {
                                //TODO: Print certificate
                                StringBuilder builder = new StringBuilder();
                                builder.append("Expiration date is earlier than current date\n");
                                builder.append("Expiration date: ");
                                builder.append(expirationDate);
                                builder.append("\nCurrent date: ");
                                builder.append(date);
                                builder.append('\n');
                                System.out.println(builder.toString());
                            }
                        }

                    }
                    else if (reasonString.equals("REVOKED"))
                    {
                        System.out.println(ve.getLocalizedMessage());
                        for (Certificate _cert : certs) {
                            java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) _cert;
                            if (cert.getIssuerX500Principal() ==
                                    ((CertificateRevokedException)ve.getCause()).getAuthorityName())
                                System.out.println(ve.getLocalizedMessage());
                            printCertificate(cert);

                        }
                    }
                    else
                    {
                        System.out.println("CertPathValidator: " + reasonString);
                    }
                } catch (SunCertPathBuilderException e) { //Might be untrusted root or self-signed
                    //Now accept connection w/o actually checking the certificate
                    TrustManager[] trustAllCerts = new TrustManager[] {
                            new X509TrustManager() {
                                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                                    return new java.security.cert.X509Certificate[0];
                                }
                                public void checkClientTrusted(
                                        java.security.cert.X509Certificate[] certs, String authType) {
                                }
                                public void checkServerTrusted(
                                        java.security.cert.X509Certificate[] certs, String authType) {
                                }
                            }
                    };


                    try {
                        SSLContext sc = SSLContext.getInstance("SSL");
                        sc.init(null, trustAllCerts, new java.security.SecureRandom());
                        HttpsURLConnection.setDefaultSSLSocketFactory(new MySSLSocketFactory(sc.getSocketFactory(),
                                new HandshakeCompletedListener() {
                                    @Override
                                    public void handshakeCompleted(HandshakeCompletedEvent handshakeCompletedEvent) {
                                        Connector.this.session = handshakeCompletedEvent.getSession();
                                        printCertificateChain();
                                    }
                                }, this));
                        conn = (HttpsURLConnection)url.openConnection();
                        conn.connect();
                        System.out.println("Self-Signed Certificate\n");
                    }
                    catch (Throwable t)
                    {
                        System.out.println("This is self-signed certificate connection exception");
                        t.printStackTrace();
                    }


                } catch (Throwable t) {
                    t.printStackTrace();
                }

            } catch (CertificateException e) {
                System.out.println(e.getLocalizedMessage());

            } catch (Throwable t) {
                t.printStackTrace();
            }
        }
        System.out.println(sb.toString());
    }
}




