package org.apache.sling.auth.oauth_client.impl;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

public class MockResponse implements HttpServletResponse {
    ArrayList<Cookie> cookies = new ArrayList();
    String sendRedirect = null;
    int error=0;
    String errorMessage = null;

    @Override
    public void addCookie(Cookie cookie) {
        cookies.add(cookie);
    }

    public List<Cookie> getCookies() {
        return cookies;
    }
    @Override
    public boolean containsHeader(String name) {
        // TODO
        return false;
    }

    @Override
    public String encodeURL(String url) {
        // TODO
        return null;
    }

    @Override
    public String encodeRedirectURL(String url) {
        // TODO
        return null;
    }

    @Override
    public String encodeUrl(String url) {
        // TODO
        return null;
    }

    @Override
    public String encodeRedirectUrl(String url) {
        // TODO
        return null;
    }

    @Override
    public void sendError(int sc, String msg) throws IOException {
        error = sc;
        errorMessage = msg;
    }

    public int getErrorCode() {
        return error;
    }

    public String getErrorMessage() {
        return errorMessage;
    }
    @Override
    public void sendError(int sc) throws IOException {
        // TODO

    }

    @Override
    public void sendRedirect(String location) throws IOException {
        sendRedirect = location;
    }

    public String getSendRedirect() {
        return sendRedirect;
    }

    @Override
    public void setDateHeader(String name, long date) {
        // TODO

    }

    @Override
    public void addDateHeader(String name, long date) {
        // TODO

    }

    @Override
    public void setHeader(String name, String value) {
        // TODO

    }

    @Override
    public void addHeader(String name, String value) {
        // TODO

    }

    @Override
    public void setIntHeader(String name, int value) {
        // TODO

    }

    @Override
    public void addIntHeader(String name, int value) {
        // TODO

    }

    @Override
    public void setStatus(int sc) {
        // TODO

    }

    @Override
    public void setStatus(int sc, String sm) {
        // TODO

    }

    @Override
    public int getStatus() {
        // TODO
        return 0;
    }

    @Override
    public String getHeader(String name) {
        // TODO
        return null;
    }

    @Override
    public Collection<String> getHeaders(String name) {
        // TODO
        return null;
    }

    @Override
    public Collection<String> getHeaderNames() {
        // TODO
        return null;
    }

    @Override
    public String getCharacterEncoding() {
        // TODO
        return null;
    }

    @Override
    public String getContentType() {
        // TODO
        return null;
    }

    @Override
    public ServletOutputStream getOutputStream() throws IOException {
        // TODO
        return null;
    }

    @Override
    public PrintWriter getWriter() throws IOException {
        // TODO
        return null;
    }

    @Override
    public void setCharacterEncoding(String charset) {
        // TODO

    }

    @Override
    public void setContentLength(int len) {
        // TODO

    }

    @Override
    public void setContentLengthLong(long len) {
        // TODO

    }

    @Override
    public void setContentType(String type) {
        // TODO

    }

    @Override
    public void setBufferSize(int size) {
        // TODO

    }

    @Override
    public int getBufferSize() {
        // TODO
        return 0;
    }

    @Override
    public void flushBuffer() throws IOException {
        // TODO

    }

    @Override
    public void resetBuffer() {
        // TODO

    }

    @Override
    public boolean isCommitted() {
        // TODO
        return false;
    }

    @Override
    public void reset() {
        // TODO

    }

    @Override
    public void setLocale(Locale loc) {
        // TODO

    }

    @Override
    public Locale getLocale() {
        // TODO
        return null;
    }
}
