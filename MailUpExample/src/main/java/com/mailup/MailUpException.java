/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mailup;

/**
 * @author sergeiinyushkin
 */
public class MailUpException extends Exception {
    private int statusCode;

    public MailUpException(final int statusCode, final String message) {
        super(message);
        setStatusCode(statusCode);
    }

    /**
     * @return the statusCode
     */
    public int getStatusCode() {
        return statusCode;
    }

    /**
     * @param statusCode the statusCode to set
     */
    public void setStatusCode(final int statusCode) {
        this.statusCode = statusCode;
    }
}
