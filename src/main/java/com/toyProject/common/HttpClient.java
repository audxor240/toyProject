package com.toyProject.common;

import lombok.extern.slf4j.Slf4j;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class HttpClient {
    private static final int DEFUALT_TIMEOUT = 8000;
    private static String userAgent = "";
    private static String encode = "UTF-8";

    public static HttpResult post(String url, String param) {
        return postWithHeaders(url, param, null, DEFUALT_TIMEOUT);
    }

    public static HttpResult postWithHeaders(String url, String param, Map<String, String> headers, int timeout) {

        if (headers == null) headers = new HashMap<String, String>();
        if (!headers.containsKey("User-Agent") && userAgent != null && !userAgent.isEmpty()) {
            headers.put("User-Agent", userAgent);
        }

        if (!headers.containsKey("Content-Type"))
            headers.put("Content-Type", "application/x-www-form-urlencoded");

        HttpResult result = new HttpResult();

        try {
            URL fbURL = new URL(url);
            HttpURLConnection con = (HttpURLConnection) fbURL.openConnection();
            con.setDoInput(true);

            for (String key : headers.keySet()) {
                con.setRequestProperty(key.trim(), headers.get(key));
            }

            con.setRequestMethod("POST");
            con.setDoOutput(true);
            if (timeout > 0) con.setReadTimeout(timeout);
            con.setUseCaches(false);

            OutputStream out = con.getOutputStream();
            out.write( param.getBytes(encode) );
            out.flush();
            out.close();

            result = getResult(con, (url.contains(".json") || url.contains(".ajax")));
        }
        catch(Exception ex) {
            log.error("Error occurred", ex);
            result.setSuccess(false);
        }

        return result;

    }

    private static HttpResult getResult(HttpURLConnection con, boolean perLine) throws Exception {

        HttpResult result = new HttpResult();

        boolean isText = con.getContentType() != null && (con.getContentType().contains("text/") || con.getContentType().contains("application/"));

        InputStream in;
        if (con.getResponseCode() >= 400) {
            in = con.getErrorStream();
            result.setSuccess(false);
        }
        else {
            in = con.getInputStream();
            result.setSuccess(true);
        }

        String enc = encode;
        if (con.getContentType().contains("charset")) {
            enc = con.getContentType().substring(con.getContentType().indexOf("charset=") + 8).trim();
        }

        StringBuffer buffer = new StringBuffer();
        if (perLine || isText) {
            BufferedReader br = new BufferedReader(new InputStreamReader(in, enc));

            String line = "";
            while ((line = br.readLine()) != null) buffer.append(line + "\n");

            br.close();
        }
        else {
            byte[] b = new byte[4096];
            for (int n; (n = in.read(b)) != -1;) buffer.append(new String(b, 0, n));
        }

        result.setStatus(con.getResponseCode());
        result.setData(buffer.toString());

        return result;
    }

    public static HttpResult getWithAuthorize(String url, String header) {
        return getWithAuthorize(url, header, DEFUALT_TIMEOUT);
    }

    public static HttpResult getWithAuthorize(String url, String header, int timeout) {
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", header);
        return getWithHeaders(url, headers, timeout);
    }

    public static HttpResult getWithHeaders(String url, Map<String, String> headers, int timeout) {

        if (headers == null) headers = new HashMap<String, String>();
        if (!headers.containsKey("User-Agent") && userAgent != null && !userAgent.isEmpty()) {
            headers.put("User-Agent", userAgent);
        }

        HttpResult result = new HttpResult();

        try {
            HttpURLConnection.setFollowRedirects(true);
            HttpURLConnection con = (HttpURLConnection) new URL(url).openConnection();
            con.setDoInput(true);

            for (String key : headers.keySet()) {
                con.setRequestProperty(key.trim(), headers.get(key));
            }

            con.setRequestMethod("GET");
            if (timeout > 0) con.setReadTimeout(timeout);
            con.setDoOutput(true);
            con.setUseCaches(false);

            result = getResult(con, (url.contains(".json") || url.contains(".ajax")));
            con.disconnect();
        }
        catch(Exception ex) {
            result = new HttpResult();
            result.setSuccess(false);
        }

        return result;
    }


    /*
    public static String sendPostJson(String targetUrl, HashMap<String, Object> dataMap, String accessToken)  throws  Exception{

        BufferedReader in = null;

        StringBuilder sb = new StringBuilder();
        JSONObject obj = new JSONObject(dataMap);

        String body = obj.toString();

        URL url = new URL(targetUrl); // 호출할 url

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("Authorization", accessToken);



        conn.setDoInput(true);
        conn.setDoOutput(true); //POST 데이터를 OutputStream으로 넘겨 주겠다는 설정
        conn.setUseCaches(false);
        conn.setDefaultUseCaches(false);
        conn.setConnectTimeout(3000); //연결대기시간 3초
        conn.setReadTimeout(3000);  //응답받는시간 3초.

        BufferedOutputStream wr = new BufferedOutputStream(conn.getOutputStream());
        // Request Body에 Data 셋팅.
        wr.write(body.getBytes("UTF-8"));
        // Request Body에 Data 입력.
        wr.flush();
        // OutputStream 종료.
        wr.close();
        StringBuilder str = new StringBuilder();

        if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
            in = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));


            String inputLine ="";
            while ((inputLine = in.readLine()) != null) { // response 출력
                str.append(inputLine + "\n");
                log.debug(inputLine);
            }
            in.close();

        }else {
            log.error("error sendData, {}" , conn.getResponseMessage());
            throw new Exception(conn.getResponseMessage());
        }
        return str.toString();
    }*/

    public static String get(String targetUrl,  HashMap<String, Object> dataMap, String token)  throws  Exception{

        BufferedReader in = null;

        StringBuilder sb = new StringBuilder();
        StringBuilder postData = new StringBuilder();

        URL url = new URL(targetUrl); // 호출할 url


        try{

            HttpURLConnection conn = (HttpURLConnection) url.openConnection();


            conn.setRequestMethod("GET");
            conn.setInstanceFollowRedirects(false);
            conn.setRequestProperty("Authorization", "Bearer " + token);
            conn.setUseCaches(false);
            conn.setDefaultUseCaches(false);
            conn.setConnectTimeout(3000); //연결대기시간 3초
            conn.setReadTimeout(3000);  //응답받는시간 3초.


            int responseCode = conn.getResponseCode();

            Charset charset = Charset.forName("UTF-8");

            if(responseCode != 200) {
                in = new BufferedReader(new InputStreamReader(conn.getErrorStream(),charset));
            }else {
                in = new BufferedReader(new InputStreamReader(conn.getInputStream(),charset));
            }

            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                sb.append(inputLine);
            }
            in.close();

        }catch(Exception e ) {
            log.error("[Rest] Error Push, {}",  e.getMessage());
        }
        return sb.toString();
    }

}

