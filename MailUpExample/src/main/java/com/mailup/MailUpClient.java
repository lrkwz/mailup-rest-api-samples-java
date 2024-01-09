/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mailup;

import org.apache.commons.codec.binary.Base64;
import org.json.JSONObject;

import javax.net.ssl.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * @author sergeiinyushkin
 */
public class MailUpClient {

    private String accessToken;

    private String authorizationEndpoint = "https://services.mailup.com/Authorization/OAuth/Authorization";

    private String callbackUri;

    private String clientId;

    private String clientSecret;

    private String consoleEndpoint = "https://services.mailup.com/API/v1.1/Rest/ConsoleService.svc";

    private int expiresIn;

    private String logonEndpoint = "https://services.mailup.com/Authorization/OAuth/LogOn";

    private String mailstatisticsEndpoint = "https://services.mailup.com/API/v1.1/Rest/MailStatisticsService.svc";

    private String refreshToken;

    private String tokenEndpoint = "https://services.mailup.com/Authorization/OAuth/Token";

    public MailUpClient(final String clientId, final String clientSecret, final String callbackUri, final HttpServletRequest request) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.callbackUri = callbackUri;

        loadToken(request);
    }

    private void loadToken(final HttpServletRequest request) {
        final Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (int i = 0; i < cookies.length; i++) {
                final Cookie cookie = cookies[i];
                if ("access_token".equals(cookie.getName())) {
                    accessToken = cookie.getValue();
                }
                if ("refresh_token".equals(cookie.getName())) {
                    refreshToken = cookie.getValue();
                }
            }
        }
    }

    public String callMethod(final String url, final String verb, final String body, final String contentType, final HttpServletResponse response) throws MailUpException {
        return callMethod(url, verb, body, contentType, true, response);
    }

    private String callMethod(final String url, final String verb, final String body, final String contentType, final boolean refresh, final HttpServletResponse response) throws MailUpException {
        String resultStr = "";
        HttpsURLConnection con = null;
        int statusCode = 0;
        try {
            InitializeSSL();

            con = (HttpsURLConnection) new URL(url).openConnection();
            con.setRequestMethod(verb);
            con.setRequestProperty("Content-Type", contentType);
            con.setRequestProperty("Accept", contentType);
            con.setRequestProperty("Authorization", "Bearer " + accessToken);

            if (body != null && !"".equals(body)) {
                con.setDoOutput(true);
                final DataOutputStream wr = new DataOutputStream(con.getOutputStream());
                wr.writeBytes(body);
                wr.flush();
                wr.close();
            } else if ("POST".equals(verb) || "PUT".equals(verb)) {
                con.setDoOutput(true);
                final DataOutputStream wr = new DataOutputStream(con.getOutputStream());
                wr.flush();
                wr.close();
            }

            statusCode = con.getResponseCode();

            if (statusCode == 401 && refresh) {
                refreshAccessToken(response);
                return callMethod(url, verb, body, contentType, false, response);
            }

            final BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            final StringBuffer result = new StringBuffer();

            while ((inputLine = in.readLine()) != null) {
                result.append(inputLine);
            }
            in.close();

            resultStr = result.toString();
        } catch (final IOException iex) {
            try {
                statusCode = con.getResponseCode();
                if (statusCode == 401 && refresh) {
                    refreshAccessToken(response);
                    return callMethod(url, verb, body, contentType, false, response);
                } else {
                    throw new MailUpException(statusCode, iex.getMessage());
                }
            } catch (final Exception ex) {
                throw new MailUpException(statusCode, ex.getMessage());
            }
        } catch (final Exception ex) {
            throw new MailUpException(statusCode, ex.getMessage());
        }

        //TODO: updateExpiresIn();
        return resultStr;
    }

    /**
     * @return the accessToken
     */
    public String getAccessToken() {
        return accessToken;
    }

    /**
     * @param accessToken the accessToken to set
     */
    public void setAccessToken(final String accessToken) {
        this.accessToken = accessToken;
    }

    /**
     * @return the authorizationEndpoint
     */
    public String getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    /**
     * @param authorizationEndpoint the authorizationEndpoint to set
     */
    public void setAuthorizationEndpoint(final String authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
    }

    /**
     * @return the consoleEndpoint
     */
    public String getConsoleEndpoint() {
        return consoleEndpoint;
    }

    /**
     * @param consoleEndpoint the consoleEndpoint to set
     */
    public void setConsoleEndpoint(final String consoleEndpoint) {
        this.consoleEndpoint = consoleEndpoint;
    }

    /**
     * @return the expiresIn
     */
    public int getExpiresIn() {
        return expiresIn;
    }

    /**
     * @param expiresIn the expiresIn to set
     */
    public void setExpiresIn(final int expiresIn) {
        this.expiresIn = expiresIn;
    }

    /**
     * @return the mailstatisticsEndpoint
     */
    public String getMailstatisticsEndpoint() {
        return mailstatisticsEndpoint;
    }

    /**
     * @param mailstatisticsEndpoint the mailstatisticsEndpoint to set
     */
    public void setMailstatisticsEndpoint(final String mailstatisticsEndpoint) {
        this.mailstatisticsEndpoint = mailstatisticsEndpoint;
    }

    /**
     * @return the refreshToken
     */
    public String getRefreshToken() {
        return refreshToken;
    }

    /**
     * @param refreshToken the refreshToken to set
     */
    public void setRefreshToken(final String refreshToken) {
        this.refreshToken = refreshToken;
    }

    /**
     * @return the tokenEndpoint
     */
    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    /**
     * @param tokenEndpoint the tokenEndpoint to set
     */
    public void setTokenEndpoint(final String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    public void logOn(final HttpServletResponse response) throws IOException {
        final String url = getLogOnUri();
        response.sendRedirect(url);
    }

    public String getLogOnUri() {
        final String url = getLogonEndpoint() + "?client_id=" + getClientId() + "&client_secret=" + getClientSecret() + "&response_type=code&redirect_uri=" + getCallbackUri();
        return url;
    }

    /**
     * @return the logonEndpoint
     */
    public String getLogonEndpoint() {
        return logonEndpoint;
    }

    /**
     * @param logonEndpoint the logonEndpoint to set
     */
    public void setLogonEndpoint(final String logonEndpoint) {
        this.logonEndpoint = logonEndpoint;
    }

    /**
     * @return the clientId
     */
    public String getClientId() {
        return clientId;
    }

    /**
     * @param clientId the clientId to set
     */
    public void setClientId(final String clientId) {
        this.clientId = clientId;
    }

    /**
     * @return the clientSecret
     */
    public String getClientSecret() {
        return clientSecret;
    }

    /**
     * @param clientSecret the clientSecret to set
     */
    public void setClientSecret(final String clientSecret) {
        this.clientSecret = clientSecret;
    }

    /**
     * @return the callbackUri
     */
    public String getCallbackUri() {
        return callbackUri;
    }

    /**
     * @param callbackUri the callbackUri to set
     */
    public void setCallbackUri(final String callbackUri) {
        this.callbackUri = callbackUri;
    }

    public void logOnWithUsernamePassword(final String username, final String password, final HttpServletResponse response) throws MailUpException {
        final int statusCode = 0;
        try {
            this.retreiveAccessToken(username, password, response);
        } catch (final Exception ex) {
            throw new MailUpException(statusCode, ex.getMessage());
        }
    }

    public String retreiveAccessToken(final String login, final String password, final HttpServletResponse response) throws MailUpException {
        int statusCode = 0;
        try {
            InitializeSSL();

            final String body = "client_id=" + clientId
                    + "&client_secret=" + clientSecret
                    + "&grant_type=password"
                    + "&username=" + URLEncoder.encode(login, StandardCharsets.UTF_8)
                    + "&password=" + URLEncoder.encode(password, StandardCharsets.UTF_8);

            final HttpsURLConnection con = (HttpsURLConnection) new URL(tokenEndpoint).openConnection();
            con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            con.setRequestProperty("Content-Length", "" + body.length());

            final byte[] auth = String.format("%s:%s", this.clientId, this.clientSecret).getBytes();
            con.setRequestProperty("Authorization", "Basic " + Base64.encodeBase64String(auth));

            con.setDoOutput(true);
            final DataOutputStream wr = new DataOutputStream(con.getOutputStream());
            wr.writeBytes(body);
            wr.flush();
            wr.close();

            statusCode = con.getResponseCode();
            extractAndSaveTokenInfo(con, response);
        } catch (final Exception ex) {
            throw new MailUpException(statusCode, ex.getMessage());
        }
        return accessToken;
    }

    //------ JAVA 1.7.0 SSL Fix
    private void InitializeSSL() throws NoSuchAlgorithmException, KeyManagementException {
        final SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(new KeyManager[0], new TrustManager[]{new DefaultTrustManager()}, new SecureRandom());
        SSLContext.setDefault(ctx);

        HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());

        // Create all-trusting host name verifier
        final HostnameVerifier allHostsValid = new HostnameVerifier() {
            @Override
            public boolean verify(final String hostname, final SSLSession session) {
                return true;
            }
        };

        // Install the all-trusting host verifier
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
    }

    private void extractAndSaveTokenInfo(final HttpsURLConnection con, final HttpServletResponse response) throws Exception {
        final BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
        String inputLine;
        final StringBuilder result = new StringBuilder();

        while ((inputLine = in.readLine()) != null) {
            result.append(inputLine);
        }
        in.close();

        final JSONObject obj = new JSONObject(result.toString());

        accessToken = obj.getString("access_token");
        refreshToken = obj.getString("refresh_token");
        expiresIn = obj.getInt("expires_in");

        // set cookies
        final Cookie cookieAccess = new Cookie("access_token", accessToken);
        cookieAccess.setMaxAge(expiresIn);
        response.addCookie(cookieAccess);

        final Cookie cookieRefresh = new Cookie("refresh_token", refreshToken);
        cookieRefresh.setMaxAge(expiresIn);
        response.addCookie(cookieRefresh);

        final Cookie cookieAccessExpire = new Cookie("access_token_expire", String.valueOf((new Date()).getTime() + expiresIn * 1000L));
        cookieAccessExpire.setMaxAge(expiresIn);
        response.addCookie(cookieAccessExpire);
    }

    public String refreshAccessToken(final HttpServletResponse response) throws MailUpException {
        int statusCode = 0;
        try {
            InitializeSSL();

            final HttpsURLConnection con = (HttpsURLConnection) new URL(tokenEndpoint).openConnection();
            con.setRequestMethod("POST");

            final String body = "client_id=" + clientId + "&client_secret=" + clientSecret + "&refresh_token=" + refreshToken + "&grant_type=refresh_token";
            con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            con.setRequestProperty("Content-Length", "" + body.length());

            con.setDoOutput(true);
            final DataOutputStream wr = new DataOutputStream(con.getOutputStream());
            wr.writeBytes(body);
            wr.flush();
            wr.close();

            statusCode = con.getResponseCode();
            extractAndSaveTokenInfo(con, response);
        } catch (final Exception ex) {
            throw new MailUpException(statusCode, ex.getMessage());
        }
        return accessToken;
    }

    //------ JAVA 1.7.0 SSL Fix
    public String retreiveAccessToken(final String code, final HttpServletResponse response) throws MailUpException {
        int statusCode = 0;
        try {

            InitializeSSL();

            final HttpsURLConnection con = (HttpsURLConnection) new URL(tokenEndpoint + "?code=" + code + "&grant_type=authorization_code").openConnection();
            con.setRequestMethod("GET");

            statusCode = con.getResponseCode();
            extractAndSaveTokenInfo(con, response);
        } catch (final Exception ex) {
            throw new MailUpException(statusCode, ex.getMessage());
        }
        return accessToken;
    }

    private static class DefaultTrustManager implements X509TrustManager {

        @Override
        public void checkClientTrusted(final X509Certificate[] arg0, final String arg1) throws CertificateException {
        }

        @Override
        public void checkServerTrusted(final X509Certificate[] arg0, final String arg1) throws CertificateException {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }
    }
}
