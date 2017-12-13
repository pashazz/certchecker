package io.github.pashazz;


import java.io.IOException;



public class Main {

    public static void main(String[] args) throws IOException{
        // write your code here
        if (args.length < 1)
            System.exit(-1);
        String url_text = args[0];
        System.out.println(url_text);
        /*try {
            URL url = new URL(url_text);
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            try {
                conn.connect();
            }
            catch (SSLHandshakeException e)
            {
                ValidatorException ve = (ValidatorException) e.getCause();
                System.out.println(ve.getClass());
                Throwable c = ve.getCause().getCause();
                if (c.getClass() == CertificateExpiredException.class)
                {
                    CertificateExpiredException exc = (CertificateExpiredException)c;
                    System.out.format("Certificate expired\n");

                }
                else
                {
                    System.out.println(c.getClass());
                }

                //Certificate cert = exc.getErrorCertificate();
                //System.out.format("Invalid certificate: %s \n", cert.toString());
            }


            try{
                Certificate[] certs = conn.getServerCertificates();
                for (Certificate cert : certs)
                {
                       System.out.println("Cert Type : " + cert.getType());
                    System.out.println("Cert Hash Code : " + cert.hashCode());
                    System.out.println("Cert Public Key Algorithm : "
                                    + cert.getPublicKey().getAlgorithm());
                    System.out.println("Cert Public Key Format : "
                                    + cert.getPublicKey().getFormat());
                    System.out.println("\n");
                }
            }
            catch (SSLPeerUnverifiedException e)
            {
                System.out.println("SSL Peer Unverified");
                e.printStackTrace();
            }


        } catch (IOException e)
        {
            e.printStackTrace();
        }
*/
      Connector c = new Connector(url_text);
        try {
            c.connect();
        }
        catch (Throwable t)
        {
            t.printStackTrace();
        }



    }


}
