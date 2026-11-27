package com.rf.demo;

import android.app.Application;

/**
 * 启动入口二：Application.onCreate 比 Activity 更早。
 * 这里也做一次卡密校验，用来验证工具能否沿调用链追到"启动前"。
 */
public class App extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        if (!LicenseManager.verify(this)) {
            // 真实产品里这里可能是关闭推送/禁用核心功能
            android.util.Log.w("RF", "license invalid at application start");
        }
    }
}
