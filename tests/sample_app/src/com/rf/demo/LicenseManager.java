package com.rf.demo;

import android.content.Context;
import android.content.SharedPreferences;

import java.security.MessageDigest;

/**
 * 目标样本里的"卡密校验"。故意写成最典型的三段式：
 *   1. 读本地卡密
 *   2. 比对 SHA-256
 *   3. 判断有效期
 * 三段全部通过才返回 true。
 *
 * 注意：这是为了实测识别与补丁而写的测试样本，不是真实产品代码。
 */
public final class LicenseManager {

    /** sha256("123456") —— 测试用卡密就是 123456 */
    private static final String KEY_HASH =
            "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92";
    private static final String PREF = "rf_demo";
    private static final String FIELD = "card_key";

    private LicenseManager() {
    }

    public static boolean verify(Context ctx) {
        String card = readCard(ctx);
        if (card == null || card.length() != 6) {
            return false;
        }
        if (!sha256(card).equals(KEY_HASH)) {
            return false;
        }
        if (isExpired(System.currentTimeMillis())) {
            return false;
        }
        return true;
    }

    static boolean isExpired(long now) {
        // 2030-01-01
        return now > 1893456000000L;
    }

    static String readCard(Context ctx) {
        SharedPreferences sp = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE);
        return sp.getString(FIELD, "");
    }

    static String sha256(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(s.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
